"""Celery tasks for scans (Step 6). No HTTP endpoint yet - Step 7 adds it.

Actor of every audit entry written here is the SYSTEM, represented by
`actor=None` (AuditLog.user is nullable by design): no human user is
connected when a worker runs a scan.

Idempotence: the scan row is locked (SELECT ... FOR UPDATE) and the task
only starts if the status is SUBMITTED, so a duplicate delivery changes
nothing. Only the scan primary key crosses the broker - never a URL or an
HTML payload.
"""
from __future__ import annotations

import logging

from celery import shared_task
from django.db import transaction

from .models import Scan
from .services.inference import VERDICT_UNCERTAIN, PredictionResult, predict
from .services.workflows import change_status

logger = logging.getLogger(__name__)

_ERROR_MAX_LEN = 200


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


@shared_task(name="scans.run_scan")
def run_scan(scan_id: int) -> str | None:
    """Analyze one scan: Submitted -> Analyzing -> Detected/Under review/Failed.

    Returns the final status, or None when the task skipped the scan
    (unknown id or status no longer SUBMITTED - idempotence).
    """
    scan = _lock_if_submitted(scan_id)
    if scan is None:
        return None
    try:
        result = predict(scan.url, scan.mode)
    except Exception as exc:  # noqa: BLE001 - any failure must end as FAILED, never crash the worker
        return Scan.Status.FAILED if _mark_failed(scan_id, exc) else None
    return _store_result(scan_id, result)


def enqueue_scan(scan: Scan) -> None:
    """Queue run_scan only AFTER the scan row is committed.

    transaction.on_commit: if the caller is inside an atomic block the task
    is delayed until commit, so the worker can never see a missing row.
    """
    transaction.on_commit(lambda: run_scan.delay(scan.pk))
