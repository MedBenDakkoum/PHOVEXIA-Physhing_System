"""Blocklist and protected-brands URLs (US38-US40, US55).

Public UUIDs only. Route order matters: `export/` is declared BEFORE the
`<uuid:public_id>` pattern so it can never be read as an entry id (the uuid
converter would refuse "export" anyway, but the explicit order is clearer).
"""
from django.urls import path

from .views import (
    BlocklistDeleteView,
    BlocklistExportView,
    BlocklistView,
    BrandDetailView,
    BrandListCreateView,
)

urlpatterns = [
    path("blocklist/", BlocklistView.as_view(), name="blocklist"),
    path("blocklist/export/", BlocklistExportView.as_view(), name="blocklist-export"),
    path(
        "blocklist/<uuid:public_id>/",
        BlocklistDeleteView.as_view(),
        name="blocklist-delete",
    ),
    path("brands/", BrandListCreateView.as_view(), name="brand-list"),
    path(
        "brands/<uuid:public_id>/",
        BrandDetailView.as_view(),
        name="brand-detail",
    ),
]
