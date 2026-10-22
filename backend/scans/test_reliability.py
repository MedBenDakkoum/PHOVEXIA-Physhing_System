"""
Reliability tests: stuck-scan reaper + retention purge (Step 15).

Covers the ISO-6.5 beat tasks (scans.reap_stuck_scans, scans.purge_expired_data),
the redelivery settings of run_scan, the CELERY_BEAT_SCHEDULE contract, the
SCAN_STUCK_MINUTES / QUICK_CHECK_RETENTION_DAYS env knobs, the BR-04
"submitted -> failed" (queue_timeout) move, the JWT OutstandingToken flush and
the ALLOW_SEED=1 gate of seed_perf_users.
Requirement tags: ISO-6.5, BR-04, US-retention.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from urllib.parse import urlparse
from uuid import uuid4

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from audit.models import AuditLog
from scans.models import Scan
from scans.tasks import purge_expired_data, reap_stuck_scans, run_scan

pytestmark = pytest.mark.django_db

STALE_DELTA = timedelta(minutes=30)  # older than the default 10 min knob


def make_scan(
    url: str = "https://example.com/login",
    *,
    owner=None,
    status=Scan.Status.ANALYZING,
    mode=Scan.Mode.FAST,
    created_at: str | None = None,
    updated_at: str | None = None,
) -> Scan:
    scan = Scan.objects.create(
        owner=owner,
        url=url,
        domain=urlparse(url).netloc,
        mode=mode,
        status=status,
    )
    updates = {}
    if created_at is not None:
        updates["created_at"] = created_at
    if updated_at is not None:
        updates["updated_at"] = updated_at
    if updates:
        Scan.objects.filter(pk=scan.pk).update(**updates)
    return Scan.objects.get(pk=scan.pk)


def audit_rows(scan):
    return list(
        AuditLog.objects.filter(
            action=AuditLog.Action.SCAN_STATUS_CHANGED,
            target_id=str(scan.public_id),
        ).order_by("created_at")
    )


# --------------------------------------------------------------------------
# reap_stuck_scans (ISO-6.5)
# --------------------------------------------------------------------------
def test_reaper_moves_a_stale_analyzing_scan_to_failed():
    scan = make_scan(status=Scan.Status.ANALYZING)
    Scan.objects.filter(pk=scan.pk).update(updated_at=timezone.now() - STALE_DELTA)

    counts = reap_stuck_scans()

    scan.refresh_from_db()
    assert counts["timeout"] == 1
    assert counts["queue_timeout"] == 0
    assert scan.status == Scan.Status.FAILED
    assert scan.error_message == "timeout"
    assert scan.finished_at is not None


def test_reaper_moves_a_stale_submitted_scan_to_failed_with_queue_timeout():
    scan = make_scan(status=Scan.Status.SUBMITTED)
    Scan.objects.filter(pk=scan.pk).update(
        created_at=timezone.now() - STALE_DELTA
    )

    counts = reap_stuck_scans()

    scan.refresh_from_db()
    assert counts["queue_timeout"] == 1
    assert scan.status == Scan.Status.FAILED
    assert scan.error_message == "queue_timeout"


def test_reaper_writes_a_system_audit_entry_and_the_queue_timeout_label():
    scan = make_scan(status=Scan.Status.SUBMITTED)
    Scan.objects.filter(pk=scan.pk).update(
        created_at=timezone.now() - STALE_DELTA
    )

    reap_stuck_scans()

    rows = audit_rows(scan)
    assert len(rows) == 1
    assert rows[0].metadata["from_status"] == Scan.Status.SUBMITTED
    assert rows[0].metadata["to_status"] == Scan.Status.FAILED
    assert rows[0].metadata["transition"] == "queue_timeout"
    assert rows[0].user is None  # SYSTEM, no human connected


def test_reaper_leaves_a_fresh_analyzing_scan_alone():
    scan = make_scan(status=Scan.Status.ANALYZING)
    Scan.objects.filter(pk=scan.pk).update(updated_at=timezone.now())

    counts = reap_stuck_scans()

    scan.refresh_from_db()
    assert counts == {"timeout": 0, "queue_timeout": 0}
    assert scan.status == Scan.Status.ANALYZING
    assert audit_rows(scan) == []


def test_reaper_never_touches_a_finished_scan():
    scan = make_scan(status=Scan.Status.DETECTED)
    Scan.objects.filter(pk=scan.pk).update(updated_at=timezone.now() - STALE_DELTA)

    reap_stuck_scans()

    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert audit_rows(scan) == []


def test_reaper_is_idempotent():
    scan = make_scan(status=Scan.Status.ANALYZING)
    Scan.objects.filter(pk=scan.pk).update(updated_at=timezone.now() - STALE_DELTA)

    first = reap_stuck_scans()
    second = reap_stuck_scans()

    scan.refresh_from_db()
    assert first == {"timeout": 1, "queue_timeout": 0}
    assert second == {"timeout": 0, "queue_timeout": 0}
    assert len(audit_rows(scan)) == 1


def test_reaper_respects_the_env_threshold(settings):
    """SCAN_STUCK_MINUTES is the single knob; a looser threshold changes nothing."""
    settings.SCAN_STUCK_MINUTES = 120
    scan = make_scan(status=Scan.Status.ANALYZING)
    Scan.objects.filter(pk=scan.pk).update(updated_at=timezone.now() - STALE_DELTA)
    assert reap_stuck_scans() == {"timeout": 0, "queue_timeout": 0}

    settings.SCAN_STUCK_MINUTES = 5
    assert reap_stuck_scans() == {"timeout": 1, "queue_timeout": 0}


def test_run_scan_is_redelivered_safely_when_a_worker_dies():
    """ISO-6.5: acks_late + reject_on_worker_lost re-queue the message; the
    SUBMITTED-only lock (test_tasks.py) makes the second run a no-op."""
    assert run_scan.acks_late is True
    assert run_scan.reject_on_worker_lost is True


def test_beat_schedules_the_reaper_and_the_daily_retention(settings):
    """The schedule lives in CODE, the thresholds in ENV (settings.py)."""
    from celery.schedules import crontab

    beat = settings.CELERY_BEAT_SCHEDULE
    assert set(beat) == {"scans-reap-stuck-scans", "scans-purge-expired-data"}
    assert beat["scans-reap-stuck-scans"]["task"] == "scans.reap_stuck_scans"
    assert beat["scans-reap-stuck-scans"]["schedule"] == crontab(minute="*/5")
    assert beat["scans-purge-expired-data"]["task"] == "scans.purge_expired_data"
    assert beat["scans-purge-expired-data"]["schedule"] == crontab(
        hour=3, minute=0
    )


# --------------------------------------------------------------------------
# purge_expired_data (retention / privacy)
# --------------------------------------------------------------------------
def test_purge_deletes_only_old_anonymous_fast_scans():
    old = timedelta(days=30)
    young = timedelta(days=1)
    anonymous = None
    owner = get_user_model().objects.create_user(email="owner@example.com")
    old_anon_fast = make_scan(
        url="https://old-anon.example/",
        owner=anonymous,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - old,
    )
    young_anon_fast = make_scan(
        url="https://young-anon.example/",
        owner=anonymous,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - young,
    )
    old_anon_full = make_scan(
        url="https://old-anon-full.example/",
        owner=anonymous,
        status=Scan.Status.DETECTED,
        mode=Scan.Mode.FULL,
        created_at=timezone.now() - old,
    )
    old_owned_fast = make_scan(
        url="https://old-owned.example/",
        owner=owner,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - old,
    )

    counts = purge_expired_data()

    assert counts["scans_deleted"] == 1
    assert not Scan.objects.filter(pk=old_anon_fast.pk).exists()
    assert Scan.objects.filter(pk=young_anon_fast.pk).exists()
    assert Scan.objects.filter(pk=old_anon_full.pk).exists()
    assert Scan.objects.filter(pk=old_owned_fast.pk).exists()


def test_purge_respects_the_retention_env_knob(settings):
    settings.QUICK_CHECK_RETENTION_DAYS = 120
    scan = make_scan(
        url="https://recent.example/",
        owner=None,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - timedelta(days=30),
    )
    assert purge_expired_data()["scans_deleted"] == 0
    assert Scan.objects.filter(pk=scan.pk).exists()

    settings.QUICK_CHECK_RETENTION_DAYS = 7
    assert purge_expired_data()["scans_deleted"] == 1


def test_purge_flushes_expired_jwt_tokens_only():
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

    now = timezone.now()
    expired = OutstandingToken.objects.create(
        user=get_user_model().objects.create_user(email="expired@example.com"),
        jti=uuid4(),
        token="expired-token",
        created_at=now - timedelta(days=30),
        expires_at=now - timedelta(days=1),
    )
    fresh = OutstandingToken.objects.create(
        user=get_user_model().objects.create_user(email="fresh@example.com"),
        jti=uuid4(),
        token="fresh-token",
        created_at=now,
        expires_at=now + timedelta(days=9),
    )

    counts = purge_expired_data()

    assert counts["tokens_flushed"] == 1
    assert not OutstandingToken.objects.filter(pk=expired.pk).exists()
    assert OutstandingToken.objects.filter(pk=fresh.pk).exists()


def test_purge_keeps_audit_entries_but_never_the_url():
    """Retention deletes the scan, never its audit trail; the domain stays,
    the URL (with its query string) never entered the audit metadata."""
    secret_url = "https://bank.example/login?token=SECRETTOKEN"
    scan = make_scan(
        url=secret_url,
        owner=None,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - timedelta(days=30),
    )
    from audit.services import record

    record(
        AuditLog.Action.QUICK_CHECK_CREATED,
        metadata={"domain": scan.domain},
        target=scan,
    )

    purge_expired_data()

    assert not Scan.objects.filter(pk=scan.pk).exists()
    rows = list(AuditLog.objects.filter(action=AuditLog.Action.QUICK_CHECK_CREATED))
    assert len(rows) == 1
    assert rows[0].metadata["domain"] == "bank.example"
    assert "SECRETTOKEN" not in str(rows[0].metadata)
    assert "SECRETTOKEN" not in rows[0].target_repr


def test_purge_logs_counts_and_never_a_url(caplog):
    caplog.set_level(logging.INFO, logger="scans.tasks")
    make_scan(
        url="https://quiet.example/path?secret=1",
        owner=None,
        status=Scan.Status.DETECTED,
        created_at=timezone.now() - timedelta(days=30),
    )

    with CaptureQueriesContext(connection) as ctx:
        counts = purge_expired_data()

    assert counts["scans_deleted"] == 1
    purge_logs = [r for r in caplog.records if "purge_expired_data" in r.message]
    assert purge_logs, "purge_expired_data must log its counts"
    message = purge_logs[0].getMessage()
    assert "scans_deleted=1" in message
    assert "https://" not in message
    assert "secret=1" not in message
    # ISO-6.5: the purge must not walk the whole table with N+1 deletes.
    assert len(ctx.captured_queries) <= 10


# --------------------------------------------------------------------------
# seed_perf_users (perf run only, ALLOW_SEED=1)
# --------------------------------------------------------------------------
def test_seed_perf_users_refuses_without_the_env_flag(monkeypatch):
    monkeypatch.delenv("ALLOW_SEED", raising=False)
    with pytest.raises(CommandError, match="ALLOW_SEED=1 is required"):
        call_command("seed_perf_users")


def test_seed_perf_users_creates_the_twenty_accounts_idempotently(monkeypatch):
    monkeypatch.setenv("ALLOW_SEED", "1")
    call_command("seed_perf_users")
    users = get_user_model().objects.filter(email__startswith="perf.user")
    assert users.count() == 20
    assert all(u.role == "end_user" for u in users)
    assert all(u.check_password("PerfUser!2026x") for u in users)

    call_command("seed_perf_users")  # second run must not duplicate
    assert users.count() == 20
