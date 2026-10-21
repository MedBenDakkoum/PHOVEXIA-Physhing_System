"""Blocklist and protected-brands endpoints (US38-US40, US55 / BR-03, BR-12).

GET  /api/blocklist/              active entries, filtered + paginated (IsAnalyst)
POST /api/blocklist/              add a domain (IsAnalyst) -> 201 / 409 already_blocked
DELETE /api/blocklist/{uuid}/     soft delete with a REQUIRED reason (BR-12) -> 204
GET  /api/blocklist/export/       CSV stream of active entries (IsAnalyst)
GET  /api/brands/                 list (IsAdmin)
POST /api/brands/                 create (IsAdmin) -> 201
PATCH /api/brands/{uuid}/         update (IsAdmin)
DELETE /api/brands/{uuid}/        soft delete (IsAdmin)

Idi Isolation (ISO-6.6): every endpoint requires ANALYST (or ADMIN for brands);
anonymous = 401, end user = 403. Ids are public UUIDs only.
"""
from __future__ import annotations

from typing import ClassVar

from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiResponse, OpenApiTypes, extend_schema
from rest_framework import generics, status
from rest_framework.filters import OrderingFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from accounts.permissions import IsAdmin, IsAnalyst
from audit.models import AuditLog
from audit.services import record
from scans.serializers import ScanErrorSerializer

from .filters import BlocklistFilter
from .models import BlocklistEntry, ProtectedBrand
from .serializers import (
    BlocklistCreateSerializer,
    BlocklistEntrySerializer,
    BlocklistErrorSerializer,
    BlocklistRemoveSerializer,
    ProtectedBrandCreateSerializer,
    ProtectedBrandPatchSerializer,
    ProtectedBrandSerializer,
)
from .services import (
    InvalidDomain,
    add_entry,
    normalize_domain,
    remove_entry,
    write_csv,
)

INVALID_BODY_CODE = "invalid_request"

_CONFLICT = OpenApiResponse(
    response=OpenApiTypes.OBJECT,
    description="Conflit (409) : `code` = `already_blocked` (BR-03).",
)


def _error(code: str, detail: str, http_status: int) -> Response:
    return Response({"code": code, "detail": detail}, status=http_status)


class BlocklistPagination(PageNumberPagination):
    """20 entries per page, client-tunable up to 100 (same as scan history)."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


# Ordering whitelist: single source of truth for the view and the OpenAPI enum.
BLOCKLIST_ORDERING_WHITELIST = ["created_at", "domain", "reason"]
BLOCKLIST_ORDERING_VALUES = BLOCKLIST_ORDERING_WHITELIST + [
    f"-{name}" for name in BLOCKLIST_ORDERING_WHITELIST
]


class BlocklistView(generics.ListCreateAPIView):
    """GET = active entries (US38 list); POST = add a domain (US38, BR-03)."""

    queryset = BlocklistEntry.objects.all()
    serializer_class = BlocklistEntrySerializer
    pagination_class = BlocklistPagination
    permission_classes: ClassVar[list] = [IsAnalyst]
    filter_backends: ClassVar[list] = [DjangoFilterBackend, OrderingFilter]
    filterset_class = BlocklistFilter
    ordering_fields: ClassVar[list[str]] = BLOCKLIST_ORDERING_WHITELIST
    ordering: ClassVar[list[str]] = ["-created_at", "-id"]

    def get_queryset(self):
        # Active entries only (soft-deleted rows stay in the table, out of the API).
        return BlocklistEntry.objects.filter(is_active=True).select_related(
            "added_by", "source_scan"
        )

    @extend_schema(
        tags=["blocklist"],
        responses={200: BlocklistEntrySerializer},
        summary="Lister la blocklist (US38)",
        description=(
            "Uniquement les entrées actives. Filtres : `q` (sous-chaîne du "
            "domaine ou de la note), `reason`, `added_by` (email), "
            "`created_after`, `created_before` (une date seule = le jour "
            "entier local). `ordering` : created_at, domain, reason "
            "(« - » pour le décroissant)."
        ),
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=["blocklist"],
        request=BlocklistCreateSerializer,
        responses={
            201: BlocklistEntrySerializer,
            400: ScanErrorSerializer,
            409: _CONFLICT,
        },
        summary="Ajouter un domaine à la blocklist (US38)",
        description=(
            "Le domaine est normalisé (minuscules, IDNA/punycode, sans point "
            "final ; une adresse IP est refusée). BR-03 : une seule entrée "
            "active par domaine, sinon 409 `already_blocked`. Audit : "
            "`blocklist.added`."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = BlocklistCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide : domain requis, "
                    "reason requis (confirmed_phishing, campaign ou manual), "
                    "note et source_scan optionnels.",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = input_serializer.validated_data
        source_scan = None
        if data.get("source_scan") is not None:
            from scans.models import Scan

            source_scan = get_object_or_404(
                Scan.objects.all(), public_id=data["source_scan"]
            )
        try:
            result = add_entry(
                domain=data["domain"],
                reason=data["reason"],
                note=data.get("note", ""),
                added_by=request.user,
                source_scan=source_scan,
                request=request,
            )
        except InvalidDomain as exc:
            return _error(
                str(exc),
                "Domaine invalide : hostname ASCII attendu (IDNA accepté), "
                "pas d'adresse IP, pas de point final.",
                status.HTTP_400_BAD_REQUEST,
            )
        if result.entry is None:
            return _error(
                "already_blocked",
                "Ce domaine est déjà actif dans la blocklist (BR-03).",
                status.HTTP_409_CONFLICT,
            )
        return Response(
            BlocklistEntrySerializer(result.entry).data,
            status=status.HTTP_201_CREATED,
        )


class BlocklistDeleteView(generics.GenericAPIView):
    """DELETE /api/blocklist/{uuid}/ - soft delete, reason REQUIRED (BR-12)."""

    serializer_class = BlocklistRemoveSerializer
    permission_classes: ClassVar[list] = [IsAnalyst]
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    def get_queryset(self):
        return BlocklistEntry.objects.filter(is_active=True).select_related("added_by")

    @extend_schema(
        tags=["blocklist"],
        request=BlocklistRemoveSerializer,
        responses={
            204: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Entrée désactivée (soft delete) + audit blocklist.removed.",
            ),
            400: BlocklistErrorSerializer,
            404: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Entrée inconnue ou déjà retirée (404).",
            ),
        },
        summary="Retirer un domaine de la blocklist (US39)",
        description=(
            "Soft delete : la ligne est conservée (historique + audit) mais "
            "`is_active` passe à false. BR-12 : le corps `{\"reason\": ...}` "
            "est OBLIGATOIRE et non vide, sinon 400. Audit : "
            "`blocklist.removed`."
        ),
    )
    def delete(self, request, *args, **kwargs):
        entry = self.get_object()
        input_serializer = BlocklistRemoveSerializer(data=request.data)
        if not input_serializer.is_valid():
            return _error(
                INVALID_BODY_CODE,
                "Corps de requête invalide : reason est obligatoire (BR-12) "
                "et ne peut pas être vide.",
                status.HTTP_400_BAD_REQUEST,
            )
        remove_entry(
            entry=entry,
            reason=input_serializer.validated_data["reason"],
            removed_by=request.user,
            request=request,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class BlocklistExportView(generics.GenericAPIView):
    """GET /api/blocklist/export/ - CSV stream of active entries (US40)."""

    serializer_class = BlocklistEntrySerializer
    permission_classes: ClassVar[list] = [IsAnalyst]
    queryset = BlocklistEntry.objects.all()

    @extend_schema(
        tags=["blocklist"],
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.STR,
                description=(
                    "Fichier CSV (domain, reason, note, added_by, created_at) "
                    "des entrées actives. Protection anti injection CSV : une "
                    "cellule commençant par = + - @ reçoit un apostrophe en "
                    "tête. Audit : `blocklist.exported`."
                ),
            ),
        },
        summary="Exporter la blocklist en CSV (US40)",
    )
    def get(self, request, *args, **kwargs):
        entries = list(
            BlocklistEntry.objects.filter(is_active=True)
            .select_related("added_by")
            .order_by("domain")
        )
        record(
            AuditLog.Action.BLOCKLIST_EXPORTED,
            request=request,
            user=request.user,
            metadata={"count": len(entries)},
        )
        response = StreamingHttpResponse(
            _csv_stream(entries),
            content_type="text/csv; charset=utf-8",
        )
        response["Content-Disposition"] = 'attachment; filename="blocklist.csv"'
        return response


def _csv_stream(entries):
    """Yield CSV lines into a buffer the StreamingHttpResponse can consume."""

    import io

    buffer = io.StringIO()
    write_csv(buffer, entries)
    yield buffer.getvalue()


class BrandListCreateView(generics.ListCreateAPIView):
    """GET/POST /api/brands/ - protected brands, ADMIN ONLY (US55)."""

    queryset = ProtectedBrand.objects.all()
    serializer_class = ProtectedBrandSerializer
    pagination_class = BlocklistPagination
    permission_classes: ClassVar[list] = [IsAdmin]
    filter_backends: ClassVar[list] = [OrderingFilter]
    ordering_fields: ClassVar[list[str]] = ["name", "created_at"]
    ordering: ClassVar[list[str]] = ["name"]

    def get_queryset(self):
        return ProtectedBrand.objects.select_related("created_by")

    @extend_schema(
        tags=["brands"],
        responses={200: ProtectedBrandSerializer},
        summary="Lister les marques protégées (US55)",
        description="Réservé aux administrateurs.",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=["brands"],
        request=ProtectedBrandCreateSerializer,
        responses={
            201: ProtectedBrandSerializer,
            400: ScanErrorSerializer,
        },
        summary="Créer une marque protégée (US55)",
        description=(
            "Admin uniquement. Le domaine est normalisé (minuscules, "
            "IDNA/punycode) et unique. Audit : pas d'action dédiée, "
            "l'entrée est visible dans le journal via la cible."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = ProtectedBrandCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide : name et domain requis.",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = input_serializer.validated_data
        try:
            domain = normalize_domain(data["domain"])
        except InvalidDomain as exc:
            return _error(
                str(exc),
                "Domaine invalide : hostname ASCII attendu (IDNA accepté), "
                "pas d'adresse IP.",
                status.HTTP_400_BAD_REQUEST,
            )
        if ProtectedBrand.objects.filter(domain=domain).exists():
            return _error(
                "already_exists",
                "Une marque avec ce domaine existe déjà.",
                status.HTTP_409_CONFLICT,
            )
        brand = ProtectedBrand.objects.create(
            name=data["name"],
            domain=domain,
            is_active=data.get("is_active", True),
            created_by=request.user,
        )
        return Response(
            ProtectedBrandSerializer(brand).data, status=status.HTTP_201_CREATED
        )


class BrandDetailView(generics.RetrieveUpdateDestroyAPIView):
    """PATCH/DELETE /api/brands/{uuid}/ - ADMIN ONLY (US55)."""

    queryset = ProtectedBrand.objects.all()
    serializer_class = ProtectedBrandSerializer
    permission_classes: ClassVar[list] = [IsAdmin]
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    def get_queryset(self):
        return ProtectedBrand.objects.select_related("created_by")

    @extend_schema(
        tags=["brands"],
        request=ProtectedBrandPatchSerializer,
        responses={
            200: ProtectedBrandSerializer,
            400: ScanErrorSerializer,
        },
        summary="Modifier une marque protégée (US55)",
        description="Admin uniquement. Champs optionnels : name, domain, is_active.",
    )
    def patch(self, request, *args, **kwargs):
        brand = self.get_object()
        input_serializer = ProtectedBrandPatchSerializer(data=request.data)
        if not input_serializer.is_valid():
            return Response(
                {
                    "code": INVALID_BODY_CODE,
                    "detail": "Corps de requête invalide.",
                    "errors": input_serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = input_serializer.validated_data
        update_fields = []
        if "name" in data:
            brand.name = data["name"]
            update_fields.append("name")
        if "is_active" in data:
            brand.is_active = data["is_active"]
            update_fields.append("is_active")
        if "domain" in data:
            try:
                domain = normalize_domain(data["domain"])
            except InvalidDomain as exc:
                return _error(
                    str(exc),
                    "Domaine invalide : hostname ASCII attendu (IDNA accepté).",
                    status.HTTP_400_BAD_REQUEST,
                )
            clash = ProtectedBrand.objects.filter(domain=domain).exclude(pk=brand.pk)
            if clash.exists():
                return _error(
                    "already_exists",
                    "Une marque avec ce domaine existe déjà.",
                    status.HTTP_409_CONFLICT,
                )
            brand.domain = domain
            update_fields.append("domain")
        if update_fields:
            brand.save(update_fields=update_fields)
        return Response(ProtectedBrandSerializer(brand).data)

    @extend_schema(
        tags=["brands"],
        responses={
            204: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Marque désactivée (soft delete : is_active = false).",
            ),
        },
        summary="Désactiver une marque protégée (US55)",
        description=(
            "Suppression douce : la ligne est conservée mais `is_active` "
            "passe à false (elle n'est plus comparée par find_lookalike)."
        ),
    )
    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save(update_fields=["is_active"])
