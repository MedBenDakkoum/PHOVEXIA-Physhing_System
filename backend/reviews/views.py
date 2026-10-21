"""Step 10 - human review endpoints (US31, US33-US36, US57 / BR-04, BR-05).

POST /api/scans/{uuid}/report/        owner flags a wrong verdict (IsEndUser)
GET  /api/review/queue/               analyst review queue (IsAnalyst)
GET  /api/review/{uuid}/              one case: scan + report + notes (IsAnalyst)
POST /api/review/{uuid}/decision/     confirm / false positive (IsAnalyst)
POST /api/review/{uuid}/notes/        internal note (IsAnalyst)
POST /api/review/{uuid}/rescan/       re-run as a new scan (IsAnalyst)
GET  /api/notifications/              own notifications, unread first (IsEndUser)
POST /api/notifications/{uuid}/read/  mark one as read (IsEndUser)

Isolation (ISO-6.6): the report endpoint is scoped to `owner=request.user`
(a foreign scan answers 404, never 403); every review endpoint requires the
ANALYST role (an end user gets 403, anonymous 401); notifications are scoped
to the connected user. Ids are public UUIDs only.
"""
from __future__ import annotations

from typing import ClassVar

from django.conf import settings
from django.db.models import Prefetch, Value
from django.db.models.functions import Abs, Coalesce, Least
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import generics, status
from rest_framework.filters import OrderingFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from accounts.permissions import IsAnalyst, IsEndUser
from audit.models import AuditLog  # noqa: F401 - used by the OpenAPI docstrings
from scans.models import Scan
from scans.serializers import ScanErrorSerializer
from scans.services.quota import QuotaExceeded, quota_exceeded_response
from scans.services.url_validation import InvalidURL
from scans.views import ScanPagination, _url_error  # shared helpers (Step 7/8b)

from .filters import ReviewQueueFilter
from .models import AnalystNote, Notification, Report
from .serializers import (
    DecisionSerializer,
    NoteCreateSerializer,
    NoteSerializer,
    NotificationSerializer,
    ReportCreateSerializer,
    ReportSerializer,
    RescanCreatedSerializer,
    ReviewDetailSerializer,
    ReviewQueueItemSerializer,
)
from .services import (
    AlreadyReported,
    NotDecidable,
    NotReportable,
    add_note,
    annotate_report_flags,
    report_scan,
    rescan_scan,
    submit_decision,
)

INVALID_BODY_CODE = "invalid_request"

_CONFLICT = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description=(
        "Conflit (409) : `code` = `already_reported` (BR-05), "
        "`not_reportable` (statut du scan) ou `not_decidable` (BR-04)."
    ),
)


def _conflict(code: str, detail: str) -> Response:
    return Response(
        {"code": code, "detail": detail}, status=status.HTTP_409_CONFLICT
    )


def _review_detail_queryset():
    """One scan with its report, notes and review info, without N+1."""
    return Scan.objects.select_related("owner", "reviewed_by").prefetch_related(
        Prefetch(
            "reports",
            queryset=Report.objects.select_related("reporter").order_by("-created_at"),
        ),
        Prefetch(
            "notes",
            queryset=AnalystNote.objects.select_related("author").order_by(
                "created_at", "id"
            ),
        ),
    )


class ReportCreateView(generics.GenericAPIView):
    """POST /api/scans/{uuid}/report/ - US31, BR-05."""

    serializer_class = ReportCreateSerializer
    permission_classes: ClassVar[list] = [IsEndUser]
    queryset = Scan.objects.all()

    @extend_schema(
        tags=["scans"],
        request=ReportCreateSerializer,
        responses={
            201: ReportSerializer,
            400: ScanErrorSerializer,
            404: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Scan introuvable ou non possédé par ce compte (404).",
            ),
            409: _CONFLICT,
        },
        summary="Signaler un verdict faux (US31)",
        description=(
            "Réservé au propriétaire du scan, qui doit être en `detected` ou "
            "`under_review` et sans signalement (BR-05 : un seul par scan, sinon "
            "409). Un scan `detected` passe en `under_review` via le graphe BR-04. "
            "Le commentaire et le label revendiqués sont enregistrés ; une entrée "
            "`report.created` est écrite dans le journal d'audit."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = ReportCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide : claimed_label requis "
                    "(safe ou phishing), commentaire optionnel (1000 caractères "
                    "maximum).",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan = get_object_or_404(
            Scan.objects.filter(owner=request.user), public_id=self.kwargs["public_id"]
        )
        data = input_serializer.validated_data
        try:
            report = report_scan(
                scan=scan,
                reporter=request.user,
                claimed_label=data["claimed_label"],
                comment=data.get("comment", ""),
                request=request,
            )
        except AlreadyReported:
            return _conflict(
                "already_reported",
                "Ce scan a déjà été signalé : un seul signalement par scan (BR-05).",
            )
        except NotReportable:
            return _conflict(
                "not_reportable",
                "Ce scan ne peut pas être signalé dans son état actuel "
                "(uniquement detected ou under_review).",
            )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)


class ReviewQueueView(generics.ListAPIView):
    """GET /api/review/queue/ - US33, the analyst work list."""

    serializer_class = ReviewQueueItemSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]
    pagination_class = ScanPagination
    filter_backends: ClassVar[list] = [DjangoFilterBackend, OrderingFilter]
    filterset_class = ReviewQueueFilter
    # `uncertainty` is the annotated distance to the nearest decision
    # threshold: the closer to a decision, the more urgent the case.
    ordering_fields: ClassVar[list[str]] = ["created_at", "uncertainty"]
    ordering: ClassVar[list[str]] = ["created_at"]

    def get_queryset(self):
        lower = Value(settings.DETECTION_UNCERTAIN_LOWER)
        upper = Value(settings.DETECTION_PHISHING_THRESHOLD)
        score = Coalesce("score", Value(0.5))
        return annotate_report_flags(
            Scan.objects.filter(status=Scan.Status.UNDER_REVIEW).annotate(
                uncertainty=Least(Abs(score - lower), Abs(score - upper))
            )
        ).select_related("owner")

    @extend_schema(
        tags=["review"],
        responses={200: ReviewQueueItemSerializer},
        summary="File de revue des analysts (US33)",
        description=(
            "Scans en `under_review`, du plus ancien au plus récent par défaut. "
            "Filtres : `source` (uncertain = verdict incertain, reported = "
            "signalé par un utilisateur), `verdict`, `created_after`, "
            "`created_before` (une date seule `YYYY-MM-DD` couvre le jour entier "
            "local). `ordering` : `created_at` (défaut, du plus ancien au plus "
            "récent) ou `uncertainty` (croissant = le score le plus proche d'un "
            "seuil de décision d'abord). Chaque ligne porte `reported` et "
            "`claimed_label`. Pagination identique à l'historique."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ReviewDetailView(generics.RetrieveAPIView):
    """GET /api/review/{uuid}/ - US33/US35: scan + report + notes + decision."""

    serializer_class = ReviewDetailSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]
    # Public UUID only (Step 8a); the sequential pk never appears in an URL.
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    def get_queryset(self):
        return _review_detail_queryset()

    @extend_schema(
        tags=["review"],
        responses={200: ReviewDetailSerializer},
        summary="Détail d'un cas de revue (US33)",
        description=(
            "Le scan, son signalement (label revendiqué, commentaire, statut), "
            "les notes internes des analysts et l'information de décision "
            "(analyste, date, commentaire). Visible analyste et admin uniquement."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ReviewDecisionView(generics.GenericAPIView):
    """POST /api/review/{uuid}/decision/ - US34, BR-04."""

    serializer_class = DecisionSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]

    @extend_schema(
        tags=["review"],
        request=DecisionSerializer,
        responses={
            200: ReviewDetailSerializer,
            400: ScanErrorSerializer,
            404: OpenApiResponse(
                response=OpenApiTypes.OBJECT, description="Scan introuvable (404)."
            ),
            409: _CONFLICT,
        },
        summary="Décider d'un cas (US34)",
        description=(
            "`decision` = `confirm_phishing` (→ `confirmed`) ou `false_positive` "
            "(→ `false_positive`), uniquement depuis `under_review` (BR-04, sinon "
            "409). Enregistre l'analyste, la date et le commentaire, résout le "
            "signalement et notifie son auteur (US57). Audit : `scan.decided`. "
            "`add_to_blocklist` (optionnel, uniquement avec confirm_phishing) "
            "ajoute le domaine à la blocklist dans la même transaction et fait "
            "passer le scan de `confirmed` à `blocked` (US38/US41)."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = DecisionSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide : decision requis "
                    "(confirm_phishing ou false_positive), commentaire optionnel, "
                    "add_to_blocklist optionnel (uniquement avec confirm_phishing).",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan = get_object_or_404(Scan.objects.all(), public_id=self.kwargs["public_id"])
        data = input_serializer.validated_data
        try:
            scan = submit_decision(
                scan=scan,
                analyst=request.user,
                decision=data["decision"],
                comment=data.get("comment", ""),
                add_to_blocklist=data.get("add_to_blocklist", False),
                request=request,
            )
        except NotDecidable:
            return _conflict(
                "not_decidable",
                "Une décision n'est possible qu'à partir du statut under_review "
                "(BR-04).",
            )
        serializer = ReviewDetailSerializer(_review_detail_queryset().get(pk=scan.pk))
        return Response(serializer.data, status=status.HTTP_200_OK)


class ReviewNoteView(generics.GenericAPIView):
    """POST /api/review/{uuid}/notes/ - US35."""

    serializer_class = NoteCreateSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]

    @extend_schema(
        tags=["review"],
        request=NoteCreateSerializer,
        responses={201: NoteSerializer},
        summary="Ajouter une note interne (US35)",
        description=(
            "Note visible des analysts et admins uniquement, jamais du "
            "propriétaire du scan. Audit : `note.added` (longueur seulement, "
            "jamais le texte)."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = NoteCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide : texte requis "
                    "(2000 caractères maximum).",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan = get_object_or_404(Scan.objects.all(), public_id=self.kwargs["public_id"])
        note = add_note(
            scan=scan,
            author=request.user,
            text=input_serializer.validated_data["text"],
            request=request,
        )
        return Response(NoteSerializer(note).data, status=status.HTTP_201_CREATED)


class ReviewRescanView(generics.GenericAPIView):
    """POST /api/review/{uuid}/rescan/ - US36."""

    serializer_class = RescanCreatedSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]

    @extend_schema(
        tags=["review"],
        responses={
            202: RescanCreatedSerializer,
            400: ScanErrorSerializer,
            429: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Quota quotidien de l'analyste atteint (BR-01) + Retry-After.",
            ),
        },
        summary="Relancer un scan (US36)",
        description=(
            "Crée un NOUVEAU scan (même URL, mode full, propriétaire = "
            "l'analyste, `rescan_of` = l'original), revalidé (BR-07) et compté "
            "dans le quota quotidien de l'analyste (BR-01). Audit : "
            "`scan.rescanned`."
        ),
    )
    def post(self, request, *args, **kwargs):
        scan = get_object_or_404(Scan.objects.all(), public_id=self.kwargs["public_id"])
        try:
            new_scan = rescan_scan(scan=scan, analyst=request.user, request=request)
        except InvalidURL as exc:
            return Response(_url_error(exc), status=status.HTTP_400_BAD_REQUEST)
        except QuotaExceeded as exc:
            return quota_exceeded_response(exc)
        return Response(
            RescanCreatedSerializer(
                {"id": new_scan.public_id, "status": new_scan.status}
            ).data,
            status=status.HTTP_202_ACCEPTED,
        )


class NotificationPagination(PageNumberPagination):
    """Page of notifications + the total of unread ones (US57)."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data, unread_count: int = 0):
        return Response(
            {
                "count": self.page.paginator.count,
                "unread_count": unread_count,
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "results": data,
            }
        )


class NotificationListView(generics.ListAPIView):
    """GET /api/notifications/ - US57: own notifications, unread first."""

    serializer_class = NotificationSerializer
    permission_classes: ClassVar[list] = [IsEndUser]
    pagination_class = NotificationPagination
    # Model hint for the OpenAPI generator (it reads `queryset` before ever
    # calling get_queryset(), which needs a real authenticated user).
    queryset = Notification.objects.all()

    def get_queryset(self):
        # Ordering lives in Notification.Meta (unread first, explicit
        # nulls_first: Postgres and SQLite disagree on NULL order otherwise).
        return Notification.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        unread = queryset.filter(read_at__isnull=True).count()
        return self.paginator.get_paginated_response(serializer.data, unread)

    @extend_schema(
        tags=["notifications"],
        responses={200: NotificationSerializer},
        summary="Mes notifications (US57)",
        description=(
            "Uniquement les miennes, non lues d'abord, paginées. La réponse "
            "contient aussi `unread_count`."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class NotificationReadView(generics.GenericAPIView):
    """POST /api/notifications/{uuid}/read/ - US57, own notification only."""

    serializer_class = NotificationSerializer
    permission_classes: ClassVar[list] = [IsEndUser]
    # Public UUID only (Step 8a): the sequential pk never appears in an URL.
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    @extend_schema(
        tags=["notifications"],
        responses={200: NotificationSerializer},
        summary="Marquer une notification comme lue (US57)",
        description=(
            "Positivement idempotent : déjà lue → 200 inchangé. La notification "
            "d'un autre compte (ou un UUID inconnu) répond 404, jamais 403."
        ),
    )
    def post(self, request, *args, **kwargs):
        notification = self.get_object()
        if notification.read_at is None:
            from django.utils import timezone

            notification.read_at = timezone.now()
            notification.save(update_fields=["read_at"])
        return Response(NotificationSerializer(notification).data)
