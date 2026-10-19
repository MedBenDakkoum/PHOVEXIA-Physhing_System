from django.urls import path

from .views import ScanDetailView, ScanListCreateView, ScanQuotaView

urlpatterns = [
    path("scans/", ScanListCreateView.as_view(), name="scan-list"),
    # Before <uuid:public_id>/ so the literal "quota" can never be read as a
    # scan UUID (the uuid converter would refuse it anyway).
    path("scans/quota/", ScanQuotaView.as_view(), name="scan-quota"),
    # Step 8a: the public UUID only; the sequential integer pk stays internal.
    path("scans/<uuid:public_id>/", ScanDetailView.as_view(), name="scan-detail"),
]
