"""
BR-01 daily scan quota tests for scans/services/quota.py (US14).

timezone.now is mocked (unittest.mock) - no freezegun, no new dependency.
The same suite runs on SQLite and PostgreSQL (see HANDOFF.md for commands);
the row-lock test asserts FOR UPDATE on PostgreSQL and documents the
SQLite no-op.
"""
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from django.conf import settings
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from rest_framework import status as http_status

from config.settings import _positive_int_env
from scans.models import Scan
from scans.services.quota import (
    QuotaExceeded,
    QuotaStatus,
    check_quota,
    get_quota_status,
    quota_exceeded_response,
)

# Fixed "now": noon UTC on a Wednesday. TIME_ZONE is UTC by default.
NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)


def freeze(now=NOW):
    """Patch timezone.now as used inside the quota module."""
    return mock.patch("scans.services.quota.timezone.now", return_value=now)


def make_scan(user, created_at=NOW, status=Scan.Status.SUBMITTED):
    """Create a scan and backdate created_at (auto_now_add ignores the kwarg)."""
    scan = Scan.objects.create(
        owner=user, url="http://example.com/x", domain="example.com", status=status
    )
    Scan.objects.filter(pk=scan.pk).update(created_at=created_at)
    return scan


def make_scans(user, count, **kwargs):
    for _ in range(count):
        make_scan(user, **kwargs)


# --- check_quota: allowed / refused ----------------------------------------


@pytest.mark.django_db
def test_19_used_is_allowed(make_user):
    user = make_user()
    make_scans(user, 19)
    with freeze():
        status = check_quota(user)
    assert isinstance(status, QuotaStatus)
    assert status.limit == settings.SCAN_DAILY_QUOTA
    assert status.used == 19
    assert status.remaining == 1
    assert status.reset_at == datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC)


@pytest.mark.django_db
def test_20_used_is_refused(make_user):
    user = make_user()
    make_scans(user, 20)
    with freeze(), pytest.raises(QuotaExceeded) as excinfo:
        check_quota(user)
    exc = excinfo.value
    assert exc.limit == settings.SCAN_DAILY_QUOTA
    assert exc.used == 20
    assert exc.reset_at == datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC)
    assert "20/20" in str(exc)


@pytest.mark.django_db
def test_21st_scan_is_refused(make_user):
    user = make_user()
    make_scans(user, 21)
    with freeze(), pytest.raises(QuotaExceeded):
        check_quota(user)


# --- scoping: whose scans count, which day ---------------------------------


@pytest.mark.django_db
def test_counts_only_the_users_own_scans(make_user):
    user = make_user(email="owner@example.com")
    other = make_user(email="other@example.com")
    make_scans(user, 19)
    make_scans(other, 5)
    with freeze():
        status = check_quota(user)
    assert status.used == 19
    assert status.remaining == 1


@pytest.mark.django_db
def test_yesterdays_scans_do_not_count(make_user):
    user = make_user()
    yesterday = NOW - timedelta(days=1)
    make_scans(user, 20, created_at=yesterday)
    with freeze():
        status = check_quota(user)
    assert status.used == 0
    assert status.remaining == settings.SCAN_DAILY_QUOTA


@pytest.mark.django_db
def test_day_rollover_just_before_and_after_midnight(make_user):
    user = make_user()
    just_before = datetime(2026, 10, 14, 23, 59, 59, tzinfo=UTC)
    just_after = datetime(2026, 10, 15, 0, 0, 1, tzinfo=UTC)
    make_scan(user, created_at=just_before)
    with freeze(just_before):
        assert get_quota_status(user).used == 1
    with freeze(just_after):
        assert get_quota_status(user).used == 0


@pytest.mark.django_db
def test_failed_scans_count_toward_quota(make_user):
    user = make_user()
    make_scans(user, 20, status=Scan.Status.FAILED)
    with freeze(), pytest.raises(QuotaExceeded):
        check_quota(user)


# --- settings: limit and invalid env values --------------------------------


@pytest.mark.django_db
def test_custom_limit_via_settings(make_user, settings):
    user = make_user()
    settings.SCAN_DAILY_QUOTA = 5
    make_scans(user, 5)
    with freeze(), pytest.raises(QuotaExceeded) as excinfo:
        check_quota(user)
    assert excinfo.value.limit == 5
    assert excinfo.value.used == 5


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("20", 20),
        (" 7 ", 7),
        ("0", 20),
        ("-5", 20),
        ("abc", 20),
        ("12.5", 20),
    ],
)
def test_positive_int_env_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("SCAN_DAILY_QUOTA", raw)
    assert _positive_int_env("SCAN_DAILY_QUOTA", 20) == expected


def test_positive_int_env_unset_falls_back_silently(monkeypatch):
    monkeypatch.delenv("SCAN_DAILY_QUOTA", raising=False)
    assert _positive_int_env("SCAN_DAILY_QUOTA", 20) == 20


def test_invalid_env_logs_a_clear_warning(monkeypatch, caplog):
    import logging

    monkeypatch.setenv("SCAN_DAILY_QUOTA", "0")
    with caplog.at_level(logging.WARNING, logger="config.settings"):
        assert _positive_int_env("SCAN_DAILY_QUOTA", 20) == 20
    assert "SCAN_DAILY_QUOTA" in caplog.text
    assert "falling back to 20" in caplog.text


# --- get_quota_status ------------------------------------------------------


@pytest.mark.django_db
def test_get_quota_status_values(make_user):
    user = make_user()
    make_scans(user, 3)
    with freeze():
        status = get_quota_status(user)
    assert status.limit == settings.SCAN_DAILY_QUOTA
    assert status.used == 3
    assert status.remaining == settings.SCAN_DAILY_QUOTA - 3
    assert status.reset_at == datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC)


# --- 429 helper -------------------------------------------------------------


def test_quota_exceeded_response_is_429_with_retry_after():
    exc = QuotaExceeded(
        limit=20,
        used=20,
        reset_at=datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC),
    )
    with freeze():
        response = quota_exceeded_response(exc)
    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert response.data["detail"] == str(exc)
    assert response.data["limit"] == 20
    assert response.data["used"] == 20
    assert response.data["reset_at"] == "2026-10-15T00:00:00+00:00"
    # 12h left before midnight from the frozen NOW.
    assert response["Retry-After"] == str(12 * 3600)


# --- race safety: transaction + select_for_update --------------------------


@pytest.mark.django_db
def test_check_quota_locks_user_row(make_user):
    """FOR UPDATE must be emitted on PostgreSQL; SQLite documents the no-op."""
    user = make_user()
    with CaptureQueriesContext(connection) as ctx, freeze():
        check_quota(user)
    sql = " ".join(q["sql"] for q in ctx.captured_queries)
    if connection.features.has_select_for_update:
        assert "FOR UPDATE" in sql.upper()
    else:
        # SQLite: select_for_update() is a documented no-op, no exception.
        assert "FOR UPDATE" not in sql.upper()


@pytest.mark.django_db
def test_check_quota_runs_inside_caller_transaction(make_user, settings):
    """Documented usage pattern: check + create inside one atomic block."""
    settings.SCAN_DAILY_QUOTA = 1
    user = make_user()
    with freeze(), transaction.atomic():
        check_quota(user)
        make_scan(user)
    with freeze(), transaction.atomic(), pytest.raises(QuotaExceeded):
        check_quota(user)


# --- day boundary in the project timezone ----------------------------------


@pytest.mark.django_db
def test_day_boundary_uses_project_timezone(make_user, settings):
    """Africa/Tunis (UTC+1): same instants fall on different calendar days."""
    settings.TIME_ZONE = "Africa/Tunis"
    user = make_user()
    # 22:30 UTC = 23:30 Tunis, same local day; 23:30 UTC = 00:30 Tunis, next day.
    late_evening = datetime(2026, 10, 14, 22, 30, 0, tzinfo=UTC)
    just_after_local_midnight = datetime(2026, 10, 14, 23, 30, 0, tzinfo=UTC)
    make_scan(user, created_at=late_evening)
    with freeze(late_evening):
        assert get_quota_status(user).used == 1
    with freeze(just_after_local_midnight):
        assert get_quota_status(user).used == 0
