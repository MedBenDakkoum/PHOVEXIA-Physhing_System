"""Celery tasks for scans (Step 6, extended Step 15). No HTTP endpoint yet.

Actor of every audit entry written here is the SYSTEM, represented by
`actor=None` (AuditLog.user is nullable by design): no human user is
connected when a worker runs a scan.

Idempotence: the scan row is locked (SELECT ... FOR UPDATE) and the task
only starts if the status is SUBMITTED, so a duplicate delivery changes
nothing. Only the scan primary key crosses the broker - never a URL or an
HTML payload.

Step 15 (ISO-6.5 reliability): run_scan uses acks_late + reject_on_worker_lost,
so a worker killed mid-analysis re-queues the message instead of losing it;
the same SUBMITTED-only lock makes that redelivery harmless. Two beat tasks
declared in config.settings.CELERY_BEAT_SCHEDULE move dead scans to FAILED
(reap_stuck_scans) and delete expired anonymous data (purge_expired_data).
"""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.core.management import call_command
from django.db import transaction
from django.utils import timezone

from .models import Scan
from .services.inference import VERDICT_UNCERTAIN, PredictionResult, predict
from .services.workflows import change_status

logger = logging.getLogger(__name__)

_ERROR_MAX_LEN = 200

# Written on the scan row when the reaper gives up on it. Never a URL.
_TIMEOUT_MESSAGE = "timeout"  # task started, worker died or analysis hung
_QUEUE_TIMEOUT_MESSAGE = "queue_timeout"  # task never started


def _sanitize_error(exc: BaseException) -> str:
    """Short, safe error message: exception class + message, no stack trace,
    no secret, no control character, truncated."""
    raw = " ".join(str(exc).split())
    raw = "".join(ch for ch in raw if ch.isprintable())
    text = f"{type(exc).__name__}: {raw}".strip()
    return text[:_ERROR_MAX_LEN]


def _lock_if_submitted(scan_id: int) -> Scan | None:
    """Lock the scan row; start the run only from SUBMITTED (BR-04)."""
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None:
            logger.warning("run_scan: scan %s does not exist; nothing to do.", scan_id)
            return None
        if scan.status != Scan.Status.SUBMITTED:
            logger.info(
                "run_scan: scan %s is %s, not submitted; idempotent skip.",
                scan_id,
                scan.status,
            )
            return None
        change_status(scan, Scan.Status.ANALYZING, actor=None)
        return scan


def _mark_failed(scan_id: int, exc: BaseException) -> bool:
    """Move ANALYZING -> FAILED and store a sanitized error message.

    Returns False (and stores nothing) if the status changed concurrently:
    the run is abandoned instead of overwriting another decision.
    """
    error = _sanitize_error(exc)
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None or scan.status != Scan.Status.ANALYZING:
            logger.info(
                "run_scan: scan %s is %s; not marking FAILED.",
                scan_id,
                getattr(scan, "status", "missing"),
            )
            return False
        scan.error_message = error
        scan.save(update_fields=["error_message"])
        change_status(scan, Scan.Status.FAILED, actor=None)
    logger.warning("run_scan: scan %s failed: %s", scan_id, error)
    return True


def _store_result(scan_id: int, result: PredictionResult) -> str | None:
    """Store verdict/score (finished_at is set by change_status), then
    DETECTED, then UNDER_REVIEW when the verdict is UNCERTAIN."""
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None or scan.status != Scan.Status.ANALYZING:
            logger.info(
                "run_scan: scan %s is %s; result not stored.",
                scan_id,
                getattr(scan, "status", "missing"),
            )
            return None
        scan.verdict = result.verdict
        scan.score = result.score
        # Step 12 (US48): stamp which ModelVersion produced this verdict
        # (the currently active one; empty if none is active).
        from controlpanel.services import get_active_model_version_label

        scan.model_version = get_active_model_version_label()
        scan.save(update_fields=["verdict", "score", "model_version", "updated_at"])
        change_status(scan, Scan.Status.DETECTED, actor=None)
        if result.verdict == VERDICT_UNCERTAIN:
            change_status(scan, Scan.Status.UNDER_REVIEW, actor=None)
        logger.info(
            "run_scan: scan %s verdict=%s score=%.6f model=%s",
            scan_id,
            result.verdict,
            result.score,
            result.model_version,
        )
        return scan.status


@shared_task(name="scans.run_scan", acks_late=True, reject_on_worker_lost=True)
def run_scan(scan_id: int) -> str | None:
    """Analyze one scan: Submitted -> Analyzing -> Detected/Under review/Failed.

    Returns the final status, or None when the task skipped the scan
    (unknown id or status no longer SUBMITTED - idempotence).
    acks_late + reject_on_worker_lost: a worker killed mid-analysis is
    re-delivered, and the SUBMITTED-only lock makes the second run a no-op
    instead of a duplicate verdict (ISO-6.5).
    """
    scan = _lock_if_submitted(scan_id)
    if scan is None:
        return None
    try:
        result = predict(scan.url, scan.mode)
    except Exception as exc:  # noqa: BLE001 - any failure must end as FAILED, never crash the worker
        return Scan.Status.FAILED if _mark_failed(scan_id, exc) else None
    return _store_result(scan_id, result)


def _reap_stale(
    status: str, *, stale_field: str, cutoff, error_message: str
) -> int:
    """Move stale `status` scans to FAILED, one row lock at a time.

    select_for_update(skip_locked=True): if another worker (or an analyst)
    already holds the row, skip it - never block, never fight over a lock.
    The status is re-checked inside the transaction: a scan that finished in
    the meantime is left alone.
    """
    candidates = list(
        Scan.objects.filter(status=status, **{f"{stale_field}__lt": cutoff})
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    reaped = 0
    for pk in candidates:
        with transaction.atomic():
            scan = (
                Scan.objects.select_for_update(skip_locked=True)
                .filter(pk=pk, status=status)
                .first()
            )
            if scan is None:
                continue
            scan.error_message = error_message
            scan.save(update_fields=["error_message"])
            change_status(scan, Scan.Status.FAILED, actor=None)
            reaped += 1
    return reaped


@shared_task(name="scans.reap_stuck_scans")
def reap_stuck_scans() -> dict[str, int]:
    """ISO-6.5: a scan stuck in ANALYZING/SUBMITTED is a dead worker.

    Runs every 5 minutes (CELERY_BEAT_SCHEDULE). ANALYZING uses updated_at
    (it moved when the task started), SUBMITTED uses created_at (it never
    moved). Both thresholds share one env knob: SCAN_STUCK_MINUTES. Every
    move goes through change_status, so the audit trail is complete.
    """
    minutes = settings.SCAN_STUCK_MINUTES
    cutoff = timezone.now() - timedelta(minutes=minutes)
    timeout = _reap_stale(
        Scan.Status.ANALYZING,
        stale_field="updated_at",
        cutoff=cutoff,
        error_message=_TIMEOUT_MESSAGE,
    )
    queue_timeout = _reap_stale(
        Scan.Status.SUBMITTED,
        stale_field="created_at",
        cutoff=cutoff,
        error_message=_QUEUE_TIMEOUT_MESSAGE,
    )
    if timeout or queue_timeout:
        logger.warning(
            "reap_stuck_scans: %d ANALYZING -> FAILED (timeout), "
            "%d SUBMITTED -> FAILED (queue_timeout), threshold=%d min",
            timeout,
            queue_timeout,
            minutes,
        )
    return {"timeout": timeout, "queue_timeout": queue_timeout}


@shared_task(name="scans.purge_expired_data")
def purge_expired_data() -> dict[str, int]:
    """ISO-6.5 privacy: delete data the retention policy has expired.

    Deletes anonymous FAST scans (quick checks, owner NULL) older than
    QUICK_CHECK_RETENTION_DAYS and calls flushexpiredtokens for expired JWT
    OutstandingTokens. Password-reset state lives only in the token blacklist
    (the reset itself is stateless), so no other table is touched. Audit
    entries keep the domain, never the URL.
    """
    days = settings.QUICK_CHECK_RETENTION_DAYS
    cutoff = timezone.now() - timedelta(days=days)
    qs = Scan.objects.filter(
        owner__isnull=True, mode=Scan.Mode.FAST, created_at__lt=cutoff
    )
    scans_deleted, _per_model = qs.delete()

    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

    expired = OutstandingToken.objects.filter(expires_at__lt=timezone.now()).count()
    call_command("flushexpiredtokens", verbosity=0)

    logger.info(
        "purge_expired_data: scans_deleted=%d tokens_flushed=%d retention_days=%d",
        scans_deleted,
        expired,
        days,
    )
    return {"scans_deleted": scans_deleted, "tokens_flushed": expired}


def enqueue_scan(scan: Scan) -> None:
    """Queue run_scan only AFTER the scan row is committed.

    transaction.on_commit: if the caller is inside an atomic block the task
    is delayed until commit, so the worker can never see a missing row.
    """
    transaction.on_commit(lambda: run_scan.delay(scan.pk))
