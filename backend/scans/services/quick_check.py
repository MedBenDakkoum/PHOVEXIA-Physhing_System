"""
BR-02 - anonymous quick check limit: QUICK_CHECK_HOURLY_LIMIT per IP per hour
(US11, default 5, Admin-configurable at runtime through /api/admin/settings/ -
US52 Step 12 -, with the env value as fallback).

Decisions (documented in docs/HANDOFF.md):
- The counter lives in the Django cache: Redis DB 1 in production (shared by
  every process and every worker), LocMemCache as a per-process fallback.
- Atomic pattern only: cache.add(key, 1, timeout=WINDOW) opens the window,
  cache.incr(key) consumes it. There is never a read-then-write sequence, so
  two concurrent requests can never land on the same value.
- The counter is consumed BEFORE the URL is validated: a refused URL
  (invalid syntax or SSRF) creates no scan, no audit entry and no Celery task,
  but it still consumes one unit of the budget, so nobody can hammer the DNS
  resolver for free.
- Retry-After comes from a companion key written once when the window opens
  (the cache API exposes no TTL); when that key is missing the full window is
  reported instead of an invented value.
- The identity is the DRF one (BaseThrottle.get_ident): NUM_PROXIES = 0 means
  REMOTE_ADDR only, so a client-sent X-Forwarded-For never buys a new budget.
"""
from __future__ import annotations

import time

from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle

from controlpanel.services import get_detection_settings

WINDOW_SECONDS = 3600
_KEY_PREFIX = "quick-check"

# Stateless: get_ident() only reads the request and settings.NUM_PROXIES.
_identifier = BaseThrottle()


class QuickCheckRateExceeded(Exception):
    """Raised when the IP already used its hourly quick-check budget."""

    def __init__(self, limit: int, retry_after: int):
        self.limit = limit
        self.retry_after = retry_after
        super().__init__(
            f"Quick check limit reached: {limit} per hour per IP "
            f"(retry in {retry_after}s)."
        )


def client_ip(request) -> str:
    """Client identity shared with the DRF throttles (NUM_PROXIES honoured)."""
    return _identifier.get_ident(request)


def _counter_key(ip: str) -> str:
    return f"{_KEY_PREFIX}:{ip}"


def _reset_key(ip: str) -> str:
    return f"{_KEY_PREFIX}:{ip}:reset"


def _start_reset_clock(reset_key: str) -> None:
    """Stamp the expiry epoch of the current window (written once, then read)."""
    cache.add(reset_key, int(time.time()) + WINDOW_SECONDS, timeout=WINDOW_SECONDS)


def hit_quick_check_limit(ip: str) -> int:
    """Consume one unit of the hourly budget; raise when the IP is over it.

    Returns the count for this window (useful for logs and tests).
    """
    # Step 12 (US52): admin-configurable limit (DB singleton, env fallback).
    limit = get_detection_settings().quick_check_hourly_limit
    counter_key, reset_key = _counter_key(ip), _reset_key(ip)

    if cache.add(counter_key, 1, timeout=WINDOW_SECONDS):
        count = 1
        _start_reset_clock(reset_key)
    else:
        try:
            # Atomic increment on the backend (Redis INCR keeps the TTL).
            count = cache.incr(counter_key)
        except ValueError:
            # The key expired between add() and incr(): open a new window.
            cache.add(counter_key, 1, timeout=WINDOW_SECONDS)
            _start_reset_clock(reset_key)
            count = 1

    if count > limit:
        raise QuickCheckRateExceeded(limit=limit, retry_after=_retry_after(reset_key))
    return count


def _retry_after(reset_key: str) -> int:
    reset_at = cache.get(reset_key)
    if not isinstance(reset_at, int):
        # Companion key lost (expired or evicted): report the full window
        # rather than an invented shorter delay.
        return WINDOW_SECONDS
    return max(1, reset_at - int(time.time()))


def quick_check_rate_response(exc: QuickCheckRateExceeded) -> Response:
    """HTTP 429 body + Retry-After header for BR-02."""
    response = Response(
        {
            "detail": (
                f"Limite de vérification anonyme atteinte : {exc.limit} liens "
                "par heure et par adresse IP. Réessayez plus tard."
            ),
            "limit": exc.limit,
        },
        status=status.HTTP_429_TOO_MANY_REQUESTS,
    )
    response["Retry-After"] = str(exc.retry_after)
    return response
