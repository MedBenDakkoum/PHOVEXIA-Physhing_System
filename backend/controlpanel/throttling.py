"""US54 - throttle scoped to the API KEY (60/min per key, not per user).

No-op for JWT and anonymous requests: get_cache_key() returns None when
`request.auth` is not an ApiKey, and DRF's SimpleRateThrottle then allows
the request without consuming any bucket.
"""
from __future__ import annotations

from rest_framework.throttling import SimpleRateThrottle

from .models import ApiKey


class ApiKeyRateThrottle(SimpleRateThrottle):
    """60/min per key (rate from REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"])."""

    scope = "api_key"

    def get_cache_key(self, request, view):
        key = getattr(request, "auth", None)
        if not isinstance(key, ApiKey):
            return None
        return self.cache_format % {"scope": self.scope, "ident": key.public_id}
