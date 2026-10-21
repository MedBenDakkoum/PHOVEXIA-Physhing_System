from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    path("api/", include("scans.urls")),
    # Step 10 (US31, US33-US36, US57): human review workflow.
    path("api/", include("reviews.urls")),
    # Step 11 (US38-US41, US55): blocklist + protected brands.
    path("api/", include("blocklist.urls")),
    path('api/audit/', include("audit.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
]