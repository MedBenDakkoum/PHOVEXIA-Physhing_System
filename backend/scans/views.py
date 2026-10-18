"""Step 7 - scan endpoints (US12, US13, US14, US15, US16 / BR-01, BR-07).

POST /api/scans/         submit a URL and run it asynchronously (202)
GET  /api/scans/         my scans, newest first, paginated
GET  /api/scans/quota/   my quota for today (US14)
GET  /api/scans/{id}/    one scan: owner, analyst or admin

Isolation: an end user only ever sees his own scans, and a scan id belonging
to somebody else answers 404 (never 403) so ids cannot be probed. Anonymous
requests are refused with 401 by the explicit permission class.

Error shape: every 400 carries a machine-readable `code` (RejectionCode or
`invalid_request`) plus a human message that never leaks resolver details,
addresses or stack traces.
"""
from __future__ import annotations

from typing import ClassVar

from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from accounts.permissions import IsEndUser
from audit.models import AuditLog
from audit.services import record

from .models import Scan
from .serializers import (
    QuotaExceededSerializer,
    QuotaSerializer,
    ScanCreatedSerializer,
    ScanCreateSerializer,
    ScanErrorSerializer,
    ScanSerializer,
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
    """POST = submit a URL (US12/13/14/15); GET = my scans, newest first."""

    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    pagination_class = ScanPagination
    permission_classes: ClassVar[list] = [IsEndUser]

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user).order_by(
            "-created_at", "-id"
        )

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
        summary="Lister mes scans (US16)",
        description="Uniquement mes scans, du plus récent au plus ancien, paginé.",
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
            # ONE transaction: validate -> quota (row lock) -> create -> audit
            # -> enqueue. Any refusal rolls the whole block back, so a refused
            # request never creates a scan and never consumes quota.
            with transaction.atomic():
                validated = validate_url(url)
                check_quota(user)
                scan = Scan.objects.create(
                    owner=user,
                    url=validated.url,
                    domain=validated.host,
                    mode=Scan.Mode.FULL,
                    status=Scan.Status.SUBMITTED,
                )
                record(
                    AuditLog.Action.SCAN_CREATED,
                    request=request,
                    target=scan,
                    metadata={"domain": scan.domain},
                )
                enqueue_scan(scan)
                quota = get_quota_status(user)
        except InvalidURL as exc:
            return Response(_url_error(exc), status=status.HTTP_400_BAD_REQUEST)
        except QuotaExceeded as exc:
            return quota_exceeded_response(exc)

        payload = {
            "id": scan.pk,
            "url": scan.url,
            "status": scan.status,
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
    """GET /api/scans/{id}/: owner, analyst or admin; 404 for anybody else."""

    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes: ClassVar[list] = [IsEndUser]

    @extend_schema(
        tags=["scans"],
        responses={200: ScanSerializer, 404: _NOT_FOUND},
        summary="Détail d'un scan (US16)",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        queryset = self.queryset
        if self.request.user.role == User.Role.END_USER:
            queryset = queryset.filter(owner=self.request.user)
        return get_object_or_404(queryset, pk=self.kwargs["pk"])


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
