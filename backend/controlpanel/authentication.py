"""US54 - `Authorization: Api-Key <secret>` authentication.

Rules (spec):
- Hash lookup (prefix-narrowed) then constant-time compare;
- the key must be active, not revoked and not expired;
- it authenticates ONLY the explicit (URL name, method) allowlist below;
  any OTHER endpoint refuses a key with 401 (never 403, never anonymous);
- each allowlisted endpoint requires ONE scope: scan:create, scan:read, or
  monitor:read (read-only health + dashboard). A scan key that lacks the
  required scan scope gets 403; a key without monitor:read is refused with
  401 on the monitoring endpoints (they are not in ITS allowlist);
- the request runs as the key's OWNER, so the owner's quota and ownership
  rules apply unchanged;
- last_used_at is stamped at most once per minute.
"""
from __future__ import annotations

from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from .models import ApiKey
from .services.api_keys import lookup_secret, touch_last_used

# (URL name, HTTP method) -> the ONE scope required on that endpoint.
# URL names come from scans/urls.py and controlpanel/urls.py.
ENDPOINT_SCOPES = {
    ("scan-list", "POST"): ApiKey.Scope.SCAN_CREATE,
    ("scan-detail", "GET"): ApiKey.Scope.SCAN_READ,
    ("admin-health", "GET"): ApiKey.Scope.MONITOR_READ,
    ("admin-dashboard", "GET"): ApiKey.Scope.MONITOR_READ,
}
ALLOWED_ENDPOINTS = frozenset(ENDPOINT_SCOPES)
# Monitoring read-only endpoints: a key that does not carry monitor:read is
# refused here with 401 (same as "not in the allowlist"), never 403.
MONITOR_ENDPOINTS = frozenset(
    {("admin-health", "GET"), ("admin-dashboard", "GET")}
)


class ApiKeyAuthentication(BaseAuthentication):
    """DRF authenticator placed in DEFAULT_AUTHENTICATION_CLASSES.

    Returns None for any other scheme (or no header) so JWT keeps working;
    raises 401 for a present-but-refused key.
    """

    keyword = b"api-key"

    def authenticate_header(self, request):
        """WWW-Authenticate scheme; without it DRF downgrades 401 -> 403."""
        auth = get_authorization_header(request).split()
        if auth and auth[0].lower() == self.keyword:
            return "Api-Key"
        # Anonymous / JWT requests keep the usual 401 + Bearer challenge.
        return "Bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth:
            return None
        if auth[0].lower() != self.keyword:
            # Bearer (JWT) or anything else: let the next authenticator decide.
            return None
        if len(auth) != 2:
            raise AuthenticationFailed(
                "En-tête Api-Key invalide (attendu : Authorization: Api-Key <secret>)."
            )
        try:
            secret = auth[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed("En-tête Api-Key invalide.") from exc

        match = getattr(request, "resolver_match", None)
        view_name = match.url_name if match else None
        endpoint = (view_name, request.method.upper())
        if endpoint not in ALLOWED_ENDPOINTS:
            raise AuthenticationFailed(
                "Clé API refusée ici : seuls POST /api/scans/, "
                "GET /api/scans/{uuid}/, GET /api/admin/health/ et "
                "GET /api/admin/dashboard/ sont acceptés."
            )

        key = lookup_secret(secret)
        if key is None:
            raise AuthenticationFailed("Clé API inconnue ou invalide.")
        if key.revoked_at is not None or not key.is_active:
            raise AuthenticationFailed("Clé API révoquée ou désactivée.")
        if key.expires_at is not None and key.expires_at <= timezone.now():
            raise AuthenticationFailed("Clé API expirée.")
        owner = key.owner
        if owner is None or not owner.is_active:
            raise AuthenticationFailed("Le propriétaire de la clé est inactif.")

        required_scope = ENDPOINT_SCOPES[endpoint]
        if required_scope not in (key.scopes or []):
            if endpoint in MONITOR_ENDPOINTS:
                raise AuthenticationFailed(
                    "Clé API refusée ici : la portée « monitor:read » est "
                    "requise pour GET /api/admin/health/ et "
                    "GET /api/admin/dashboard/."
                )
            raise PermissionDenied(
                f"Clé API sans la portée requise « {required_scope} »."
            )

        touch_last_used(key)
        return (owner, key)
