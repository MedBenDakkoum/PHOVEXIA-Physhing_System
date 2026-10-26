"""X-API-Key authentication for POST /collect, constant-time comparison."""
from __future__ import annotations

import hmac

from fastapi import Request

from .errors import ApiError


async def require_api_key(request: Request) -> None:
    """Reject the request with 401 unless X-API-Key matches the startup secret."""
    settings = request.app.state.settings
    provided = request.headers.get("X-API-Key") or ""
    if not provided or not hmac.compare_digest(provided, settings.api_key):
        raise ApiError(401, "unauthorized", "missing or invalid X-API-Key header")
