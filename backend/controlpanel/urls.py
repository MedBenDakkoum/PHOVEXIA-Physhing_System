"""Admin control panel URLs (US45, US48, US49, US52-US54 / BR-11).

Mounted at `api/` (config/urls.py). Public UUIDs only. Route order matters:
the literal `rollback/` and `compare/` are declared BEFORE
`<uuid:public_id>/` so they can never be read as a model id.
"""
from django.urls import path

from .views import (
    AdminHealthView,
    ApiKeyListCreateView,
    ApiKeyRevokeView,
    DashboardView,
    DetectionSettingsView,
    ModelActivateView,
    ModelCompareView,
    ModelDetailView,
    ModelListCreateView,
    ModelRollbackView,
    PublicHealthView,
)

urlpatterns = [
    path(
        "admin/settings/",
        DetectionSettingsView.as_view(),
        name="admin-settings",
    ),
    path("admin/models/", ModelListCreateView.as_view(), name="admin-model-list"),
    path(
        "admin/models/rollback/",
        ModelRollbackView.as_view(),
        name="admin-model-rollback",
    ),
    path(
        "admin/models/compare/",
        ModelCompareView.as_view(),
        name="admin-model-compare",
    ),
    path(
        "admin/models/<uuid:public_id>/",
        ModelDetailView.as_view(),
        name="admin-model-detail",
    ),
    path(
        "admin/models/<uuid:public_id>/activate/",
        ModelActivateView.as_view(),
        name="admin-model-activate",
    ),
    path(
        "admin/dashboard/",
        DashboardView.as_view(),
        name="admin-dashboard",
    ),
    # Public, minimal health (US53) - the only non-admin endpoint here.
    path("health/", PublicHealthView.as_view(), name="public-health"),
    path("admin/health/", AdminHealthView.as_view(), name="admin-health"),
    path(
        "admin/api-keys/",
        ApiKeyListCreateView.as_view(),
        name="admin-apikey-list",
    ),
    path(
        "admin/api-keys/<uuid:public_id>/",
        ApiKeyRevokeView.as_view(),
        name="admin-apikey-revoke",
    ),
]
