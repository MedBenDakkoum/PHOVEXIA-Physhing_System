"""Admin control panel endpoints (US45, US48, US49, US52, US53, US54 / BR-11).

GET    /api/admin/settings/                 detection settings (IsAdmin)
PATCH  /api/admin/settings/                 update + audit settings.changed
GET    /api/admin/models/                   list versions (IsAdmin)
POST   /api/admin/models/                   register metadata (IsAdmin)
GET    /api/admin/models/{uuid}/            one version (IsAdmin)
POST   /api/admin/models/{uuid}/activate/   one active at a time (BR-11)
POST   /api/admin/models/rollback/          previous active version
GET    /api/admin/models/compare/?ids=a,b   side-by-side metrics + deltas
GET    /api/admin/dashboard/?period=7d|30d|90d or from/to (IsAdmin)
GET    /api/health/                         PUBLIC, minimal (AllowAny)
GET    /api/admin/health/                   detailed checks (IsAdmin)
GET    /api/admin/api-keys/                 list keys (IsAdmin)
POST   /api/admin/api-keys/                 create, secret shown ONCE (IsAdmin)
DELETE /api/admin/api-keys/{uuid}/          revoke (IsAdmin)

Every endpoint is ADMIN ONLY except /api/health/: anonymous = 401,
end user / analyst = 403. Ids are public UUIDs only.
"""
from __future__ import annotations

from typing import ClassVar
from uuid import UUID

from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.permissions import IsAdmin
from scans.models import Scan

from .models import ApiKey, DetectionSettings, ModelVersion
from .serializers import (
    AdminErrorSerializer,
    AdminHealthSerializer,
    ApiKeyCreatedSerializer,
    ApiKeyCreateSerializer,
    ApiKeySerializer,
    DashboardSerializer,
    DetectionSettingsSerializer,
    DetectionSettingsUpdateSerializer,
    ModelCompareSerializer,
    ModelVersionCreateSerializer,
    ModelVersionSerializer,
    PublicHealthSerializer,
)
from .services.api_keys import create_api_key, revoke_api_key
from .services.dashboard import DashboardPeriodError, get_dashboard
from .services.health import build_health
from .services.model_versions import (
    ModelVersionError,
    activate_model_version,
    compare_model_versions,
    register_model_version,
    rollback_model_version,
)
from .services.settings import (
    SettingsValidationError,
    get_detection_settings,
    get_settings_row,
    update_detection_settings,
)

INVALID_BODY_CODE = "invalid_request"

_ADMIN_TAG = "admin"


def _error(code: str, detail: str, http_status: int, errors=None) -> Response:
    body = {"code": code, "detail": detail}
    if errors is not None:
        body["errors"] = errors
    return Response(body, status=http_status)


class AdminPagination(PageNumberPagination):
    """20 entries per page, client-tunable up to 100 (same as the other lists)."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


def _settings_payload() -> dict:
    values = get_detection_settings()
    row = get_settings_row()
    return {
        **values.as_dict(),
        "updated_at": row.updated_at if row else None,
        "updated_by_email": (
            row.updated_by.email if row and row.updated_by else None
        ),
    }


class DetectionSettingsView(generics.GenericAPIView):
    """GET/PATCH /api/admin/settings/ - thresholds + quotas (US52)."""

    queryset = DetectionSettings.objects.all()
    serializer_class = DetectionSettingsSerializer
    permission_classes: ClassVar[list] = [IsAdmin]

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={200: DetectionSettingsSerializer},
        summary="Lire les réglages de détection (US52)",
        description=(
            "Singleton : seuils (`phishing_threshold`, `uncertain_lower`) et "
            "quotas (`daily_scan_quota`, `quick_check_hourly_limit`). Si la "
            "table est vide, les valeurs Django/env par défaut sont renvoyées. "
            "Lecture mise en cache 30 s."
        ),
    )
    def get(self, request, *args, **kwargs):
        return Response(DetectionSettingsSerializer(_settings_payload()).data)

    @extend_schema(
        tags=[_ADMIN_TAG],
        request=DetectionSettingsUpdateSerializer,
        responses={
            200: DetectionSettingsSerializer,
            400: AdminErrorSerializer,
        },
        summary="Modifier les réglages de détection (US52)",
        description=(
            "PATCH partiel : seuls les champs fournis sont modifiés, puis le "
            "ensemble est validé (`0 < uncertain_lower < phishing_threshold "
            "<= 1`, quotas entiers >= 1 et bornés). Cache invalidé "
            "immédiatement. Audit : `settings.changed` (anciennes + "
            "nouvelles valeurs)."
        ),
    )
    def patch(self, request, *args, **kwargs):
        input_serializer = DetectionSettingsUpdateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return _error(
                INVALID_BODY_CODE,
                "Corps de requête invalide (types ou bornes).",
                status.HTTP_400_BAD_REQUEST,
                errors=input_serializer.errors,
            )
        snapshot = get_detection_settings()
        merged = {**snapshot.as_dict(), **input_serializer.validated_data}
        try:
            update_detection_settings(
                values=merged, user=request.user, request=request
            )
        except SettingsValidationError as exc:
            return _error(
                "invalid_settings",
                "Réglages invalides : 0 < uncertain_lower < "
                "phishing_threshold <= 1, quotas entiers >= 1.",
                status.HTTP_400_BAD_REQUEST,
                errors=exc.errors,
            )
        return Response(DetectionSettingsSerializer(_settings_payload()).data)


class ModelListCreateView(generics.ListCreateAPIView):
    """GET = versions (US48); POST = register metadata (US48, no upload)."""

    queryset = ModelVersion.objects.all()
    serializer_class = ModelVersionSerializer
    pagination_class = AdminPagination
    permission_classes: ClassVar[list] = [IsAdmin]

    def get_queryset(self):
        return ModelVersion.objects.select_related("created_by")

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={200: ModelVersionSerializer},
        summary="Lister les versions du modèle (US48)",
        description="Réservé aux administrateurs, du plus récent au plus ancien.",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=[_ADMIN_TAG],
        request=ModelVersionCreateSerializer,
        responses={
            201: ModelVersionSerializer,
            400: AdminErrorSerializer,
            409: AdminErrorSerializer,
        },
        summary="Enregistrer une version du modèle (US48)",
        description=(
            "Métadonnées uniquement (pas d'upload). `file_path` est relatif à "
            "`MODELS_DIR` (path traversal refusé), le fichier doit exister pour "
            "un modèle ONNX, et `sha256` est calculé quand le fichier existe. "
            "(name, version) doit être unique (409 `already_exists`)."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = ModelVersionCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return _error(
                INVALID_BODY_CODE,
                "Corps de requête invalide : name, version et kind requis.",
                status.HTTP_400_BAD_REQUEST,
                errors=input_serializer.errors,
            )
        try:
            version = register_model_version(
                data=input_serializer.validated_data, created_by=request.user
            )
        except ModelVersionError as exc:
            return _error(exc.code, exc.detail, exc.http_status)
        return Response(
            ModelVersionSerializer(version).data, status=status.HTTP_201_CREATED
        )


class ModelDetailView(generics.RetrieveAPIView):
    """GET /api/admin/models/{uuid}/ - one version (US48)."""

    queryset = ModelVersion.objects.all()
    serializer_class = ModelVersionSerializer
    permission_classes: ClassVar[list] = [IsAdmin]
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    def get_queryset(self):
        return ModelVersion.objects.select_related("created_by")

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={200: ModelVersionSerializer},
        summary="Détail d'une version du modèle (US48)",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ModelActivateView(generics.GenericAPIView):
    """POST /api/admin/models/{uuid}/activate/ - ONE active (BR-11, US48)."""

    queryset = ModelVersion.objects.all()
    serializer_class = ModelVersionSerializer
    permission_classes: ClassVar[list] = [IsAdmin]
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={
            200: ModelVersionSerializer,
            400: AdminErrorSerializer,
        },
        summary="Activer une version du modèle (US48 / BR-11)",
        description=(
            "Transaction verrouillée : la version précédente est désactivée "
            "PUIS la nouvelle activée (BR-11 = une seule active). Le SHA-256 "
            "du fichier est revérifié avant l'activation. Audit : "
            "`model.activated`."
        ),
    )
    def post(self, request, *args, **kwargs):
        version = self.get_object()
        try:
            activated = activate_model_version(
                version, user=request.user, request=request
            )
        except ModelVersionError as exc:
            return _error(exc.code, exc.detail, exc.http_status)
        return Response(ModelVersionSerializer(activated).data)


class ModelRollbackView(generics.GenericAPIView):
    """POST /api/admin/models/rollback/ - previous active version (US48)."""

    queryset = ModelVersion.objects.all()
    serializer_class = ModelVersionSerializer
    permission_classes: ClassVar[list] = [IsAdmin]

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={
            200: ModelVersionSerializer,
            404: AdminErrorSerializer,
            409: AdminErrorSerializer,
        },
        summary="Réactiver la version précédente (US48)",
        description=(
            "Réactive la dernière version qui était active avant l'actuelle. "
            "409 `no_previous_version` s'il n'y en a aucune. Audit : "
            "`model.activated` (rollback: true)."
        ),
    )
    def post(self, request, *args, **kwargs):
        try:
            version = rollback_model_version(user=request.user, request=request)
        except ModelVersionError as exc:
            return _error(exc.code, exc.detail, exc.http_status)
        return Response(ModelVersionSerializer(version).data)


class ModelCompareView(generics.GenericAPIView):
    """GET /api/admin/models/compare/?ids=a,b - side by side (US49)."""

    queryset = ModelVersion.objects.all()
    serializer_class = ModelCompareSerializer
    permission_classes: ClassVar[list] = [IsAdmin]

    @extend_schema(
        tags=[_ADMIN_TAG],
        parameters=[
            OpenApiParameter(
                name="ids",
                type=OpenApiTypes.STR,
                required=True,
                description="Liste d'UUID publics séparés par des virgules (>= 2).",
            )
        ],
        responses={
            200: ModelCompareSerializer,
            400: AdminErrorSerializer,
        },
        summary="Comparer des versions du modèle (US49)",
        description=(
            "Métriques côte à côte + écart par rapport à la PREMIERE valeur "
            "de `ids`. 400 si moins de 2 identifiants ou identifiant inconnu."
        ),
    )
    def get(self, request, *args, **kwargs):
        raw = request.query_params.get("ids", "")
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        ids = []
        for part in parts:
            try:
                ids.append(UUID(part))
            except ValueError:
                return _error(
                    "invalid_id",
                    f"Identifiant invalide : {part} (UUID attendu).",
                    status.HTTP_400_BAD_REQUEST,
                )
        try:
            payload = compare_model_versions(ids)
        except ModelVersionError as exc:
            return _error(exc.code, exc.detail, exc.http_status)
        return Response(ModelCompareSerializer(payload).data)


class DashboardView(generics.GenericAPIView):
    """GET /api/admin/dashboard/ - aggregated indicators (US45)."""

    queryset = Scan.objects.all()
    serializer_class = DashboardSerializer
    permission_classes: ClassVar[list] = [IsAdmin]

    @extend_schema(
        tags=[_ADMIN_TAG],
        parameters=[
            OpenApiParameter(
                name="period",
                type=OpenApiTypes.STR,
                required=False,
                enum=["7d", "30d", "90d"],
                description="Fenêtre glissante (défaut 30d).",
            ),
            OpenApiParameter(
                name="from",
                type=OpenApiTypes.STR,
                required=False,
                description="Date de début YYYY-MM-DD (fuseau TIME_ZONE), avec `to`.",
            ),
            OpenApiParameter(
                name="to",
                type=OpenApiTypes.STR,
                required=False,
                description="Date de fin YYYY-MM-DD (incluse), avec `from`.",
            ),
        ],
        responses={200: DashboardSerializer, 400: AdminErrorSerializer},
        summary="Tableau de bord administrateur (US45)",
        description=(
            "Totaux, répartition par verdict/statut/source, taux de phishing, "
            "taux de faux positifs = FALSE_POSITIVE / (CONFIRMED + "
            "FALSE_POSITIVE), reviews en attente, médiane de durée (Python, "
            "10 000 scans finis max), scans par jour (fuseau du projet), top 10 "
            "des domaines phishing, utilisateurs par rôle et nombre de quick "
            "checks. Agrégats uniquement, cache 60 s par période."
        ),
    )
    def get(self, request, *args, **kwargs):
        try:
            payload = get_dashboard(request.query_params)
        except DashboardPeriodError as exc:
            return _error(
                "invalid_period", str(exc), status.HTTP_400_BAD_REQUEST
            )
        return Response(DashboardSerializer(payload).data)


class PublicHealthView(generics.GenericAPIView):
    """GET /api/health/ - PUBLIC, minimal, no details (US53)."""

    queryset = Scan.objects.none()
    serializer_class = PublicHealthSerializer
    permission_classes: ClassVar[list] = [AllowAny]

    @extend_schema(
        tags=["health"],
        responses={200: PublicHealthSerializer},
        summary="Santé minimale (US53)",
        description="Public : `{'status': 'ok'}` uniquement, aucun détail.",
    )
    def get(self, request, *args, **kwargs):
        return Response({"status": "ok"})


class AdminHealthView(generics.GenericAPIView):
    """GET /api/admin/health/ - detailed checks (US53), never fails."""

    queryset = Scan.objects.none()
    serializer_class = AdminHealthSerializer
    permission_classes: ClassVar[list] = [IsAdmin]

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={200: AdminHealthSerializer},
        summary="Santé détaillée du système (US53)",
        description=(
            "Base (ping), Redis (ping), workers Celery (inspect().ping(), "
            "timeout 1 s, « unreachable » au lieu d'une erreur), longueur de "
            "file Redis, scans bloqués en ANALYZING au-delà de "
            "ANALYZING_STUCK_MINUTES, dernier scan terminé, version de modèle "
            "active. Chaque contrôle renvoie ok/message : jamais d'échec de "
            "la requête, jamais de secret ni de pile d'appels."
        ),
    )
    def get(self, request, *args, **kwargs):
        return Response(AdminHealthSerializer(build_health()).data)


class ApiKeyListCreateView(generics.ListCreateAPIView):
    """GET/POST /api/admin/api-keys/ - the secret is returned ONCE (US54)."""

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    pagination_class = AdminPagination
    permission_classes: ClassVar[list] = [IsAdmin]

    def get_queryset(self):
        return ApiKey.objects.select_related("owner")

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={200: ApiKeySerializer},
        summary="Lister les clés API (US54)",
        description="Ni le secret ni son hash ne figurent jamais dans la liste.",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=[_ADMIN_TAG],
        request=ApiKeyCreateSerializer,
        responses={
            201: ApiKeyCreatedSerializer,
            400: AdminErrorSerializer,
        },
        summary="Créer une clé API (US54)",
        description=(
            "Le champ `secret` n'apparaît QUE dans cette réponse de création "
            "et n'est jamais stocké (SHA-256 seulement). Portées : "
            "`scan:create`, `scan:read`. Audit : `apikey.created` (préfixe "
            "seulement, jamais le secret)."
        ),
    )
    def post(self, request, *args, **kwargs):
        input_serializer = ApiKeyCreateSerializer(data=request.data)
        if not input_serializer.is_valid():
            return _error(
                INVALID_BODY_CODE,
                "Corps de requête invalide : name et scopes requis "
                "(scan:create, scan:read).",
                status.HTTP_400_BAD_REQUEST,
                errors=input_serializer.errors,
            )
        data = input_serializer.validated_data
        key, secret = create_api_key(
            name=data["name"],
            owner=request.user,
            scopes=sorted(data["scopes"]),
            expires_at=data.get("expires_at"),
            request=request,
        )
        return Response(
            ApiKeyCreatedSerializer(
                key, context={"request": request, "secret": secret}
            ).data,
            status=status.HTTP_201_CREATED,
        )


class ApiKeyRevokeView(generics.DestroyAPIView):
    """DELETE /api/admin/api-keys/{uuid}/ - soft revoke (US54)."""

    queryset = ApiKey.objects.all()
    serializer_class = ApiKeySerializer
    permission_classes: ClassVar[list] = [IsAdmin]
    lookup_field = "public_id"
    lookup_url_kwarg = "public_id"

    @extend_schema(
        tags=[_ADMIN_TAG],
        responses={
            204: None,
            404: AdminErrorSerializer,
        },
        summary="Révoquer une clé API (US54)",
        description=(
            "Soft revoke : `is_active = false` + `revoked_at` (la ligne est "
            "conservée). Une clé révoquée est refusée avec 401. Audit : "
            "`apikey.revoked`."
        ),
    )
    def delete(self, request, *args, **kwargs):
        key = self.get_object()
        revoke_api_key(key, user=request.user, request=request)
        return Response(status=status.HTTP_204_NO_CONTENT)
