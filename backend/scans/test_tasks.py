"""
Celery task tests for scans/tasks.py (Step 6) - no endpoint yet.

Covers the success path for the three verdicts, the FAILED path with a
sanitized error, idempotence, unknown id, transaction.on_commit enqueueing,
audit entries per run (actor = system, user is NULL) and the SELECT ...
FOR UPDATE lock on both engines.
Requirement tags: US15, US32, US46, BR-04, ISO-6.5.
"""
from unittest import mock

import pytest
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext

from audit.models import AuditLog
from scans.models import Scan
from scans.services.inference import (
    VERDICT_LEGITIMATE,
    VERDICT_PHISHING,
    VERDICT_UNCERTAIN,
    predict,
)
from scans.tasks import enqueue_scan, run_scan


def url_for_verdict(verdict: str, attempts: int = 10_000) -> str:
    """Deterministic search: a URL whose MOCK verdict equals `verdict`."""
    for i in range(attempts):
        url = f"https://candidate{i}.example/{verdict}"
        if predict(url, Scan.Mode.FAST).verdict == verdict:
            return url
    raise AssertionError(f"no URL found for verdict {verdict}")


URL_PHISHING = url_for_verdict(VERDICT_PHISHING)
URL_LEGITIMATE = url_for_verdict(VERDICT_LEGITIMATE)
URL_UNCERTAIN = url_for_verdict(VERDICT_UNCERTAIN)


def make_scan(url, status=Scan.Status.SUBMITTED, mode=Scan.Mode.FAST):
    from urllib.parse import urlparse

    return Scan.objects.create(
        url=url, domain=urlparse(url).netloc, mode=mode, status=status
    )


def audit_rows(scan):
    return list(
        AuditLog.objects.filter(target_id=str(scan.pk)).order_by("pk")
    )


def audit_actions(scan):
    return [row.action for row in audit_rows(scan)]


# --- success paths -----------------------------------------------------------


@pytest.mark.django_db
def test_run_scan_phishing_success():
    scan = make_scan(URL_PHISHING)
    final = run_scan(scan.pk)
    scan.refresh_from_db()
    expected = predict(URL_PHISHING, Scan.Mode.FAST)

    assert final == Scan.Status.DETECTED
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == VERDICT_PHISHING
    assert scan.score == pytest.approx(expected.score)
    assert scan.finished_at is not None
    assert scan.error_message is None


@pytest.mark.django_db
def test_run_scan_legitimate_success():
    scan = make_scan(URL_LEGITIMATE)
    final = run_scan(scan.pk)
    scan.refresh_from_db()

    assert final == Scan.Status.DETECTED
    assert scan.verdict == VERDICT_LEGITIMATE
    assert scan.score == pytest.approx(predict(URL_LEGITIMATE, "fast").score)
    assert scan.finished_at is not None
    assert scan.error_message is None


@pytest.mark.django_db
def test_run_scan_uncertain_goes_under_review():
    scan = make_scan(URL_UNCERTAIN)
    final = run_scan(scan.pk)
    scan.refresh_from_db()

    assert final == Scan.Status.UNDER_REVIEW
    assert scan.status == Scan.Status.UNDER_REVIEW
    assert scan.verdict == VERDICT_UNCERTAIN
    assert scan.score == pytest.approx(predict(URL_UNCERTAIN, "fast").score)
    assert scan.finished_at is not None


# --- audit entries per run (actor = system => user is NULL) ------------------


@pytest.mark.django_db
def test_phishing_run_writes_two_audit_entries_with_system_actor():
    scan = make_scan(URL_PHISHING)
    run_scan(scan.pk)

    rows = audit_rows(scan)
    assert [row.action for row in rows] == ["scan_status_changed"] * 2
    assert [row.metadata["transition"] for row in rows] == [
        "scan_started",
        "analysis_complete",
    ]
    assert [row.user_id for row in rows] == [None, None]
    assert rows[0].metadata["to_status"] == Scan.Status.ANALYZING
    assert rows[1].metadata["to_status"] == Scan.Status.DETECTED


@pytest.mark.django_db
def test_uncertain_run_adds_under_review_audit_entry():
    scan = make_scan(URL_UNCERTAIN)
    run_scan(scan.pk)

    rows = audit_rows(scan)
    assert [row.action for row in rows] == ["scan_status_changed"] * 3
    assert [row.metadata["transition"] for row in rows] == [
        "scan_started",
        "analysis_complete",
        "detected_under_review",
    ]
    assert rows[2].metadata["from_status"] == Scan.Status.DETECTED
    assert rows[2].metadata["to_status"] == Scan.Status.UNDER_REVIEW
    assert all(row.user_id is None for row in rows)


# --- FAILED path -------------------------------------------------------------


@pytest.mark.django_db
def test_run_scan_failed_with_mocked_exception():
    scan = make_scan(URL_LEGITIMATE)
    with mock.patch(
        "scans.tasks.predict", side_effect=RuntimeError("boom")
    ):
        final = run_scan(scan.pk)
    scan.refresh_from_db()

    assert final == Scan.Status.FAILED
    assert scan.status == Scan.Status.FAILED
    assert scan.verdict is None
    assert scan.score is None
    assert scan.finished_at is not None
    assert scan.error_message == "RuntimeError: boom"
    assert "Traceback" not in scan.error_message

    rows = audit_rows(scan)
    assert [row.metadata["transition"] for row in rows] == [
        "scan_started",
        "analysis_complete",
    ]
    assert rows[1].metadata["to_status"] == Scan.Status.FAILED


@pytest.mark.django_db
def test_failed_error_message_is_sanitized_and_short():
    scan = make_scan(URL_LEGITIMATE)
    noisy = RuntimeError("line1\nline2\t" + "x" * 500)
    with mock.patch("scans.tasks.predict", side_effect=noisy):
        run_scan(scan.pk)
    scan.refresh_from_db()

    message = scan.error_message
    assert message.startswith("RuntimeError: line1 line2")
    assert "\n" not in message
    assert "\t" not in message
    assert len(message) <= 200
    assert "Traceback" not in message


# --- concurrent status change (defensive paths) ------------------------------


@pytest.mark.django_db
def test_failed_is_not_stored_if_status_changed_mid_run():
    scan = make_scan(URL_LEGITIMATE)

    def _steal_then_raise(*args, **kwargs):
        Scan.objects.filter(pk=scan.pk).update(status=Scan.Status.DETECTED)
        raise RuntimeError("boom")

    with mock.patch("scans.tasks.predict", side_effect=_steal_then_raise):
        final = run_scan(scan.pk)

    scan.refresh_from_db()
    assert final is None
    assert scan.status == Scan.Status.DETECTED
    assert scan.error_message is None
    assert [r.metadata["transition"] for r in audit_rows(scan)] == ["scan_started"]


@pytest.mark.django_db
def test_result_is_not_stored_if_status_changed_mid_run():
    scan = make_scan(URL_PHISHING)

    def _steal_then_predict(*args, **kwargs):
        Scan.objects.filter(pk=scan.pk).update(
            status=Scan.Status.UNDER_REVIEW
        )
        return predict(*args, **kwargs)

    with mock.patch("scans.tasks.predict", side_effect=_steal_then_predict):
        final = run_scan(scan.pk)

    scan.refresh_from_db()
    assert final is None
    assert scan.status == Scan.Status.UNDER_REVIEW
    assert scan.verdict is None
    assert scan.score is None
    assert [r.metadata["transition"] for r in audit_rows(scan)] == ["scan_started"]


# --- idempotence / unknown id ------------------------------------------------


@pytest.mark.django_db
def test_second_run_changes_nothing():
    scan = make_scan(URL_PHISHING)
    assert run_scan(scan.pk) == Scan.Status.DETECTED
    scan.refresh_from_db()
    first = {
        "status": scan.status,
        "verdict": scan.verdict,
        "score": scan.score,
        "error_message": scan.error_message,
        "finished_at": scan.finished_at,
        "updated_at": scan.updated_at,
    }
    audits_before = len(audit_rows(scan))

    assert run_scan(scan.pk) is None

    scan.refresh_from_db()
    second = {
        "status": scan.status,
        "verdict": scan.verdict,
        "score": scan.score,
        "error_message": scan.error_message,
        "finished_at": scan.finished_at,
        "updated_at": scan.updated_at,
    }
    assert second == first
    assert len(audit_rows(scan)) == audits_before


@pytest.mark.django_db
def test_run_scan_skips_non_submitted_scan():
    scan = make_scan(URL_PHISHING, status=Scan.Status.DETECTED)
    assert run_scan(scan.pk) is None
    assert audit_rows(scan) == []
    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict is None


@pytest.mark.django_db
def test_run_scan_unknown_id_does_not_crash():
    assert run_scan(999_999) is None
    assert AuditLog.objects.count() == 0


@pytest.mark.django_db
def test_run_scan_locks_the_scan_row():
    scan = make_scan(URL_LEGITIMATE)
    with CaptureQueriesContext(connection) as ctx:
        run_scan(scan.pk)
    sql = " ".join(q["sql"] for q in ctx.captured_queries).upper()
    if connection.features.has_select_for_update:
        assert "FOR UPDATE" in sql
    else:
        assert "FOR UPDATE" not in sql


# --- enqueue_scan / transaction.on_commit ------------------------------------


@pytest.mark.django_db
def test_enqueue_scan_is_deferred_until_commit(
    db, django_capture_on_commit_callbacks
):
    scan = make_scan(URL_PHISHING)
    with mock.patch("scans.tasks.run_scan.delay") as delay:
        with django_capture_on_commit_callbacks(execute=True):
            enqueue_scan(scan)
            delay.assert_not_called()
        delay.assert_called_once_with(scan.pk)


@pytest.mark.django_db
def test_enqueue_scan_without_commit_runs_no_task(db):
    scan = make_scan(URL_PHISHING)
    with mock.patch("scans.tasks.run_scan.delay") as delay:
        enqueue_scan(scan)
        delay.assert_not_called()


@pytest.mark.django_db
def test_enqueue_scan_runs_task_eagerly_after_commit(
    db, django_capture_on_commit_callbacks
):
    scan = make_scan(URL_PHISHING)
    with django_capture_on_commit_callbacks(execute=True):
        enqueue_scan(scan)
    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == VERDICT_PHISHING


@pytest.mark.django_db(transaction=True)
def test_enqueue_scan_waits_for_a_real_commit(db):
    scan = make_scan(URL_PHISHING)
    with mock.patch("scans.tasks.run_scan.delay") as delay:
        with transaction.atomic():
            enqueue_scan(scan)
            delay.assert_not_called()
        delay.assert_called_once_with(scan.pk)


# --- task dispatch -----------------------------------------------------------


@pytest.mark.django_db
def test_run_scan_task_is_registered_and_eager():
    assert run_scan.name == "scans.run_scan"
    scan = make_scan(URL_LEGITIMATE)
    result = run_scan.delay(scan.pk)
    assert result.get() == Scan.Status.DETECTED
    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
