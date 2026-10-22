"""
BR-01 daily scan quota per user (US14).

Decisions (see docs/HANDOFF.md):
- One calendar day = the day in settings.TIME_ZONE (not UTC).
- Scans in EVERY status count, including FAILED: submitting is what
  consumes the quota.
- Same limit for every role (end_user, analyst, admin).
- Race safety: check_quota() takes a row-level lock (SELECT ... FOR UPDATE)
  on the user row inside a transaction, so two concurrent submissions for
  the same user cannot both pass the check. Callers MUST call check_quota()
  and Scan.objects.create() inside the SAME transaction.atomic() block: the
  lock is then held until that outer transaction commits. On SQLite,
  select_for_update() is a documented no-op (no row-level locking); it is
  effective on PostgreSQL. Test: test_check_quota_locks_user_row.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from controlpanel.services import get_detection_settings

from ..models import Scan

User = get_user_model()


class QuotaExceeded(Exception):
    """Raised when the user already used the daily scan quota (BR-01)."""

    def __init__(self, limit: int, used: int, reset_at: datetime):
        self.limit = limit
        self.used = used
        self.reset_at = reset_at
        super().__init__(
            f"Daily scan quota exceeded: {used}/{limit} used. "
            f"Resets at {reset_at.isoformat()}."
        )


@dataclass(frozen=True)
class QuotaStatus:
    limit: int
    used: int
    remaining: int
    reset_at: datetime


def _day_bounds(now: datetime) -> tuple[datetime, datetime]:
    """Return [start, end) of the calendar day containing `now`, in TIME_ZONE.

    Boundaries are local midnights (DST-safe: built from the local date, not
    by adding 24h to an aware datetime).
    """
    local_date = timezone.localtime(now).date()
    start = timezone.make_aware(datetime.combine(local_date, time.min))
    end = timezone.make_aware(datetime.combine(local_date + timedelta(days=1), time.min))
    return start, end


def _count_today(user: User, start: datetime, end: datetime) -> int:
    """Count the user's scans created in [start, end), all statuses."""
    return Scan.objects.filter(
        owner=user, created_at__gte=start, created_at__lt=end
    ).count()


def get_quota_status(user: User) -> QuotaStatus:
    """Read-only snapshot of the quota (US14: remaining). No lock needed."""
    # Step 12 (US52): admin-configurable limit (DB singleton, env fallback).
    limit = get_detection_settings().daily_scan_quota
    start, end = _day_bounds(timezone.now())
    used = _count_today(user, start, end)
    return QuotaStatus(
        limit=limit, used=used, remaining=max(0, limit - used), reset_at=end
    )


def check_quota(user: User) -> QuotaStatus:
    """Raise QuotaExceeded if the user reached the daily quota (BR-01).

    See module docstring for the race-safety contract: call this inside the
    same transaction.atomic() block that creates the Scan.
    """
    # Step 12 (US52): admin-configurable limit (DB singleton, env fallback).
    limit = get_detection_settings().daily_scan_quota
    start, end = _day_bounds(timezone.now())
    with transaction.atomic():
        # Row lock on the user: serialises concurrent quota checks for the
        # same user (no-op on SQLite; effective on PostgreSQL). The lock is
        # held until the CALLER's transaction commits, hence the contract.
        list(
            User.objects.select_for_update()
            .filter(pk=user.pk)
            .values_list("pk", flat=True)
        )
        used = _count_today(user, start, end)
    if used >= limit:
        raise QuotaExceeded(limit=limit, used=used, reset_at=end)
    return QuotaStatus(
        limit=limit, used=used, remaining=max(0, limit - used), reset_at=end
    )


def quota_exceeded_response(exc: QuotaExceeded) -> Response:
    """HTTP 429 body + Retry-After header for a QuotaExceeded.

    No endpoint uses it yet (scan submission endpoint comes later).
    """
    retry_after = max(1, int((exc.reset_at - timezone.now()).total_seconds()))
    response = Response(
        {
            "detail": str(exc),
            "limit": exc.limit,
            "used": exc.used,
            "reset_at": exc.reset_at.isoformat(),
        },
        status=status.HTTP_429_TOO_MANY_REQUESTS,
    )
    response["Retry-After"] = str(retry_after)
    return response
