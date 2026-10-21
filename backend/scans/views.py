"""Step 7 - scan endpoints (US12, US13, US14, US15, US16 / BR-01, BR-07).

POST /api/scans/         submit a URL and run it asynchronously (202)
GET  /api/scans/         my scans, newest first, paginated, filtered (Step 8b)
GET  /api/scans/quota/   my quota for today (US14)
GET  /api/scans/{uuid}/  one scan by public UUID: owner, analyst or admin

Isolation: an end user only ever sees his own scans, and a scan id belonging
to somebody else answers 404 (never 403) so ids cannot be probed. Anonymous
requests are refused with 401 by the explicit permission class.

Step 8a (ISO-6.6): the API exposes only the public UUID (`public_id`); the
sequential integer pk never leaves the server. An unknown or malformed UUID
answers 404 (the <uuid:...> converter refuses non-UUID path segments before
any query runs, so a malformed id can never raise a 500).

Error shape: every 400 carries a machine-readable `code` (RejectionCode or
`invalid_request`) plus a human message that never leaks resolver details,
addresses or stack traces.

Step 8b (US29): the list endpoint accepts the history filters declared in
`filters.py` (q, verdict, status, created_after, created_before) plus a
whitelisted `ordering`. Filters always run on top of the owner scope, and an
invalid filter value answers 400 before any query executes.

Step 9 (US11 / BR-02): anonymous quick check, two AllowAny endpoints.
POST /api/quick-check/ runs the same BR-07 validation, creates a Scan with
owner NULL in FAST mode and limits the IP to QUICK_CHECK_HOURLY_LIMIT hits
per hour through an atomic cache counter. GET /api/quick-check/{uuid}/ shows
status, verdict, score and finished_at of an anonymous FAST scan only: any
other scan (owned, or FAST but owned) answers 404.
"""
from __future__ import annotations

from typing import ClassVar

from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    OpenApiTypes,
    extend_schema,
)
from rest_framework import generics, status
from rest_framework.filters import OrderingFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from accounts.permissions import IsEndUser
from audit.models import AuditLog
from audit.services import record

from .filters import ScanFilter
from .models import Scan
from .serializers import (
    QuickCheckCreatedSerializer,
    QuickCheckRateSerializer,
    QuickCheckResultSerializer,
    QuickCheckSerializer,
    QuotaExceededSerializer,
    QuotaSerializer,
    ScanCreatedSerializer,
    ScanCreateSerializer,
    ScanErrorSerializer,
    ScanSerializer,
)
from .services.quick_check import (
    QuickCheckRateExceeded,
    client_ip,
    hit_quick_check_limit,
    quick_check_rate_response,
)
from .services.quota import (
    QuotaExceeded,
    check_quota,
    get_quota_status,
    quota_exceeded_response,
)
from .services.url_validation import (
    DNS_TIMEOUT_SECONDS,
    InvalidURL,
    RejectionCode,
    validate_url,
)
from .tasks import enqueue_scan

User = get_user_model()

INVALID_BODY_CODE = "invalid_request"
INVALID_BODY_DETAIL = 'Corps de requête invalide : le champ "url" est requis (texte).'

# Safe, human messages for each machine-readable rejection code. Never echo
# the resolved address, the resolver error or any internal detail back.
_URL_ERROR_MESSAGES: dict[RejectionCode, str] = {
    RejectionCode.EMPTY: "URL vide : saisissez une adresse http(s) à analyser.",
    RejectionCode.TOO_LONG: "URL trop longue : 2048 caractères maximum.",
    RejectionCode.INVALID_SYNTAX: "URL mal formée : vérifiez la syntaxe de l'adresse.",
    RejectionCode.SCHEME_NOT_ALLOWED: (
        "Schéma refusé : seules les adresses http:// et https:// sont acceptées."
    ),
    RejectionCode.CREDENTIALS_NOT_ALLOWED: (
        "Identifiants refusés : l'URL ne doit pas contenir user:pass@."
    ),
    RejectionCode.EMPTY_HOST: "Domaine manquant : l'URL ne contient pas d'hôte.",
    RejectionCode.BLOCKED_HOST: (
        "Hôte local refusé : les adresses locales ne sont pas analysables."
    ),
    RejectionCode.FORBIDDEN_ADDRESS: (
        "Adresse refusée : les réseaux privés, locaux et réservés ne sont pas analysables."
    ),
    RejectionCode.DNS_FAILURE: "Domaine introuvable : la résolution DNS a échoué.",
    RejectionCode.DNS_TIMEOUT: (
        f"Délai de résolution DNS dépassé ({DNS_TIMEOUT_SECONDS:g} s) : réessayez plus tard."
    ),
}

_NOT_FOUND = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Scan introuvable ou non visible par ce compte (404 volontaire, jamais 403).",
)

# Step 8b (US29): the only accepted values of ?ordering=. A leading "-" means
# descending. Anything else is dropped by rest_framework.filters.OrderingFilter
# and the default ordering is used instead: it is never an error, and no
# client-provided field name ever reaches SQL. Single source of truth for the
# view attribute and for the OpenAPI enum below.
ORDERING_WHITELIST = [
    "created_at",
    "finished_at",
    "status",
    "verdict",
    "score",
]
ORDERING_VALUES = ORDERING_WHITELIST + [f"-{name}" for name in ORDERING_WHITELIST]


def _url_error(exc: InvalidURL) -> dict[str, str]:
    """400 body of a refused URL: machine-readable code + safe message."""
    return {
        "code": str(exc.code),
        "detail": _URL_ERROR_MESSAGES.get(exc.code, "URL refusée."),
    }


class ScanPagination(PageNumberPagination):
    """US16 / US29 history: 20 scans per page, client-tunable up to 100."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class ScanListCreateView(generics.ListCreateAPIView):
    """POST = submit a URL (US12/13/14/15); GET = my scans, filtered (US29)."""

    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    pagination_class = ScanPagination
    permission_classes: ClassVar[list] = [IsEndUser]
    # Step 8b: django-filter (q, verdict, status, created_after, created_before)
    # then the ordering whitelist. Both operate on the owner-scoped queryset.
    filter_backends: ClassVar[list] = [DjangoFilterBackend, OrderingFilter]
    filterset_class = ScanFilter
    ordering_fields: ClassVar[list[str]] = ORDERING_WHITELIST
    ordering: ClassVar[list[str]] = ["-created_at", "-id"]

    def get_queryset(self):
        # Owner scope only (US29/ISO-6.6): filtering and ordering are the job
        # of the filter backends above, so no client input can widen the query.
        # Step 10: two correlated subqueries add the review flags (no N+1).
        # Local import: reviews.views already imports this module.
        from reviews.services import annotate_report_flags

        return annotate_report_flags(self.queryset.filter(owner=self.request.user))

    @extend_schema(
        tags=["scans"],
        request=ScanCreateSerializer,
        responses={
            202: ScanCreatedSerializer,
            400: ScanErrorSerializer,
            429: QuotaExceededSerializer,
        },
        summary="Soumettre une URL (US12)",
        description=(
            "Valide l'URL (BR-07), applique le quota quotidien (BR-01), crée le scan "
            "en mode full et le file d'attente Celery (US15). Le corps ne peut contenir "
            "que `url` : mode, statut, verdict, score et propriétaire sont décidés par "
            "le serveur."
        ),
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    @extend_schema(
        tags=["scans"],
        responses={200: ScanSerializer},
        summary="Lister mes scans (US16 / US29)",
        parameters=[
            OpenApiParameter(
                name="ordering",
                type=OpenApiTypes.STR,
                required=False,
                enum=ORDERING_VALUES,
                description=(
                    "Tri de l'historique : l'un des champs autorisés (created_at, "
                    "finished_at, status, verdict, score), précédé d'un « - » pour "
                    "l'ordre décroissant. Une valeur hors liste retombe sur le tri "
                    "par défaut (-created_at, -id)."
                ),
            ),
        ],
        description=(
            "Uniquement mes scans, du plus récent au plus ancien, paginé. "
            "Filtres (US29) : `q` (sous-chaîne de l'URL ou du domaine, "
            "littérale), `verdict`, `status`, `created_after` et "
            "`created_before` (ISO 8601, bornes inclusives), combinés par ET. "
            "Une date seule `YYYY-MM-DD` couvre le jour entier dans le fuseau "
            "de `TIME_ZONE` (les deux jours bornes sont donc inclusifs). "
            "Tri : `ordering` limité à created_at, finished_at, status, "
            "verdict, score (un « - » pour le décroissant) ; toute autre "
            "valeur retombe sur le tri par défaut. "
            "Une valeur de filtre invalide renvoie 400 avant toute requête SQL."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        input_serializer = ScanCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": INVALID_BODY_DETAIL,
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        url = input_serializer.validated_data["url"]

        try:
            # ONE transaction: validate -> quota (row lock) -> blocklist (US41)
            # -> create -> audit -> enqueue (or immediate verdict). Any refusal
            # rolls the whole block back, so a refused request never creates a
            # scan and never consumes quota.
            with transaction.atomic():
                validated = validate_url(url)
                check_quota(user)
                # US41: domain or parent domain already actively blocked?
                from blocklist.services import apply_blocked_verdict, is_blocked

                blocked = is_blocked(validated.host)
                scan = Scan.objects.create(
                    owner=user,
                    url=validated.url,
                    domain=validated.host,
                    mode=Scan.Mode.FULL,
                    status=Scan.Status.SUBMITTED,
                    detection_source=(
                        Scan.DetectionSource.BLOCKLIST
                        if blocked is not None
                        else Scan.DetectionSource.MODEL
                    ),
                )
                record(
                    AuditLog.Action.SCAN_CREATED,
                    request=request,
                    target=scan,
                    metadata={"domain": scan.domain},
                )
                if blocked is not None:
                    # Immediate verdict, no Celery task (quota still counts).
                    apply_blocked_verdict(scan)
                else:
                    enqueue_scan(scan)
                quota = get_quota_status(user)
        except InvalidURL as exc:
            return Response(_url_error(exc), status=status.HTTP_400_BAD_REQUEST)
        except QuotaExceeded as exc:
            return quota_exceeded_response(exc)

        payload = {
            "id": scan.public_id,
            "url": scan.url,
            "status": scan.status,
            "detection_source": scan.detection_source,
            "created_at": scan.created_at,
            "quota": {
                "limit": quota.limit,
                "used": quota.used,
                "remaining": quota.remaining,
                "reset_at": quota.reset_at,
            },
        }
        return Response(
            ScanCreatedSerializer(payload).data,
            status=status.HTTP_202_ACCEPTED,
        )


class ScanDetailView(generics.RetrieveAPIView):
    """GET /api/scans/{uuid}/: owner, analyst or admin; 404 for anybody else.

    Step 8a: the lookup uses the public UUID. A malformed path segment never
    reaches the database: the <uuid:public_id> URL converter refuses it and
    Django answers 404 (never 500).
    """

    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes: ClassVar[list] = [IsEndUser]

    @extend_schema(
        tags=["scans"],
        responses={200: ScanSerializer, 404: _NOT_FOUND},
        summary="Détail d'un scan (US16)",
        description=(
            "Identifié par l'UUID public (`id` de la réponse), jamais par la clé "
            "entière interne."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        # Step 10: same review annotations as the list (serializer contract).
        from reviews.services import annotate_report_flags

        queryset = annotate_report_flags(self.queryset)
        if self.request.user.role == User.Role.END_USER:
            queryset = queryset.filter(owner=self.request.user)
        return get_object_or_404(queryset, public_id=self.kwargs["public_id"])


class ScanQuotaView(generics.GenericAPIView):
    """GET /api/scans/quota/: my quota for today (US14 / BR-01)."""

    serializer_class = QuotaSerializer
    permission_classes: ClassVar[list] = [IsEndUser]

    @extend_schema(
        tags=["scans"],
        responses={200: QuotaSerializer},
        summary="Mon quota de scans (US14)",
        description="Limites du jour : combien de scans restent disponibles.",
    )
    def get(self, request, *args, **kwargs):
        return Response(
            self.get_serializer(get_quota_status(request.user)).data
        )


class QuickCheckView(generics.GenericAPIView):
    """POST /api/quick-check/ - anonymous quick check (US11 / BR-02).

    AllowAny by design (the visitor has no account). The rate limit is the
    BR-02 counter of scans.services.quick_check (5/hour/IP by default), so
    `throttle_classes` is empty on purpose: exactly one limiter, one single
    429 shape. The counter is consumed BEFORE the URL validation, so a refused
    URL creates no scan but still burns one unit of the budget.
    """

    serializer_class = QuickCheckSerializer
    permission_classes: ClassVar[list] = [AllowAny]
    throttle_classes: ClassVar[list] = []

    @extend_schema(
        tags=["quick-check"],
        request=QuickCheckSerializer,
        responses={
            202: QuickCheckCreatedSerializer,
            400: ScanErrorSerializer,
            429: QuickCheckRateSerializer,
        },
        summary="Vérifier un lien sans compte (US11)",
        description=(
            "Valide l'URL (BR-07, protection SSRF), crée un scan anonyme en mode "
            "fast et le file d'attente Celery. Limite : "
            "`QUICK_CHECK_HOURLY_LIMIT` par heure et par adresse IP (BR-02), "
            "sinon 429 avec `Retry-After`. Le corps ne peut contenir que `url` : "
            "tout autre champ est ignoré. Une URL refusée ne crée aucun scan "
            "mais consomme une unité du budget horaire."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = QuickCheckSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": INVALID_BODY_DETAIL,
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Cache counter first: atomic, independent of the transaction, and
            # it protects the DNS lookup below from being hammered for free.
            hit_quick_check_limit(client_ip(request))
        except QuickCheckRateExceeded as exc:
            return quick_check_rate_response(exc)

        url = input_serializer.validated_data["url"]
        try:
            with transaction.atomic():
                validated = validate_url(url)
                # US41: an actively blocked domain gets the immediate verdict.
                from blocklist.services import apply_blocked_verdict, is_blocked

                blocked = is_blocked(validated.host)
                scan = Scan.objects.create(
                    owner=None,
                    url=validated.url,
                    domain=validated.host,
                    mode=Scan.Mode.FAST,
                    status=Scan.Status.SUBMITTED,
                    detection_source=(
                        Scan.DetectionSource.BLOCKLIST
                        if blocked is not None
                        else Scan.DetectionSource.MODEL
                    ),
                )
                # Domain + IP only: record() stores target_repr built from
                # `domain`, never the URL and its query string.
                record(
                    AuditLog.Action.QUICK_CHECK_CREATED,
                    request=request,
                    target=scan,
                    metadata={"domain": scan.domain},
                )
                if blocked is not None:
                    apply_blocked_verdict(scan)
                else:
                    enqueue_scan(scan)
        except InvalidURL as exc:
            return Response(_url_error(exc), status=status.HTTP_400_BAD_REQUEST)

        payload = {"id": scan.public_id, "status": scan.status}
        return Response(
            QuickCheckCreatedSerializer(payload).data,
            status=status.HTTP_202_ACCEPTED,
        )


class QuickCheckDetailView(generics.RetrieveAPIView):
    """GET /api/quick-check/{uuid}/ - follow an anonymous scan (US11).

    AllowAny, but the queryset is restricted to anonymous FAST scans: an
    owned scan (whatever its mode) answers 404, so the endpoint can never be
    used as an oracle on other users' scans. Throttled 60/min per IP.
    """

    queryset = Scan.objects.all()
    serializer_class = QuickCheckResultSerializer
    permission_classes: ClassVar[list] = [AllowAny]
    throttle_classes: ClassVar[list] = [ScopedRateThrottle]
    throttle_scope = "quick_check_detail"

    @extend_schema(
        tags=["quick-check"],
        responses={
            200: QuickCheckResultSerializer,
            404: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description=(
                    "Scan introuvable : UUID inconnu, ou scan possédé par un "
                    "compte (404 volontaire, jamais 403)."
                ),
            ),
        },
        summary="Suivre un quick check anonyme (US11)",
        description=(
            "Uniquement `status`, `verdict`, `score` et `finished_at`, et "
            "uniquement pour les scans anonymes en mode fast."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        return get_object_or_404(
            self.queryset.filter(owner__isnull=True, mode=Scan.Mode.FAST),
            public_id=self.kwargs["public_id"],
        )
