from django.urls import path

from .views import ScanDetailView, ScanListCreateView, ScanQuotaView

urlpatterns = [
    path("scans/", ScanListCreateView.as_view(), name="scan-list"),
    # Before <int:pk>/ so the literal "quota" can never be read as a scan id.
    path("scans/quota/", ScanQuotaView.as_view(), name="scan-quota"),
    path("scans/<int:pk>/", ScanDetailView.as_view(), name="scan-detail"),
]
