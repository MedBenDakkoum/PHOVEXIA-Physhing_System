"""Celery tasks for scans (Step 6, extended Step 15 and the resilience fix).

Actor of every audit entry written here is the SYSTEM, represented by
`actor=None` (AuditLog.user is nullable by design): no human user is
connected when a worker runs a scan.

Idempotence: the scan row is locked (SELECT ... FOR UPDATE) and the task
only starts attempt 0 from SUBMITTED, so a duplicate delivery changes
nothing. Only the scan primary key crosses the broker - never a URL or an
HTML payload.

Step 15 (ISO-6.5 reliability): run_scan uses acks_late + reject_on_worker_lost,
so a worker killed mid-analysis re-queues the message instead of losing it.
Infrastructure failures (collector/inference) are retried ACROSS tasks: the
attempt stores retry_count/reason_code, then queues the next attempt with a
Celery countdown (5, 15, 30, 60 s) - never a `time.sleep` that freezes a
worker. A scan is FAILED only once all attempts are exhausted, so a transient
blip or a busy collector cannot kill a user's scan. While waiting the scan
stays ANALYZING and carries the stable reason code; reap_stuck_scans still
catches a scan whose retries never ran.

Two beat tasks declared in config.settings.CELERY_BEAT_SCHEDULE move dead
scans to FAILED (reap_stuck_scans) and delete expired anonymous data
(purge_expired_data).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from celery import shared_task
from django.conf import settings
from django.core.management import call_command
from django.db import transaction
from django.utils import timezone

from .models import Scan
from .services.collector_client import CollectorClient, CollectorError
from .services.inference import (
    VERDICT_UNCERTAIN,
    PredictionResult,
    _thresholds,
    classify_score,
    predict,
)
from .services.inference_client import InferenceClient, InferenceError
from .services.screenshots import prepare_screenshot
from .services.workflows import change_status

logger = logging.getLogger(__name__)

_ERROR_MAX_LEN = 200

# Written on the scan row when the reaper gives up on it. Never a URL.
_TIMEOUT_MESSAGE = "timeout"  # task started, worker died or analysis hung
_QUEUE_TIMEOUT_MESSAGE = "queue_timeout"  # task never started

# ISO-6.5 / US26: up to 5 attempts, separated by 5, 15, 30 then 60 s.
# One attempt is bounded by COLLECTOR_TIMEOUT + INFERENCE_TIMEOUT (~50 s), so
# the whole retry window stays under the 10 min SCAN_STUCK_MINUTES reaper.
MAX_SCAN_ATTEMPTS = 5
RETRY_DELAYS = (5, 15, 30, 60)


@dataclass(frozen=True)
class ScanOutcome:
    """Unified result stored on the scan row by _store_result.

    Both the MOCK path and the real collector+inference path produce one.
    `escalate_to_review` drives the DETECTED -> UNDER_REVIEW move: it is true
    only for a COMPLETE uncertain verdict (fusion score inside the band);
    a PARTIAL result stays DETECTED (the user sees the reason_code instead
    of an analyst queue entry).
    """

    verdict: str
    score: float | None
    partial: bool
    reason_code: str
    final_url: str
    signals: dict[str, Any]
    probabilities: dict[str, Any]
    model_bundle_version: str
    screenshot_path: str
    escalate_to_review: bool


def _sanitize_error(exc: BaseException) -> str:
    """Short, safe error message: exception class + message, no stack trace,
    no secret, no control character, truncated."""
    raw = " ".join(str(exc).split())
    raw = "".join(ch for ch in raw if ch.isprintable())
    text = f"{type(exc).__name__}: {raw}".strip()
    return text[:_ERROR_MAX_LEN]


def _sanitize_reason(reason: str) -> str:
    """Short, safe reason string (no stack, no secret, truncated)."""
    raw = " ".join(str(reason).split())
    raw = "".join(ch for ch in raw if ch.isprintable())
    return raw[:_ERROR_MAX_LEN]


def _start_attempt(scan_id: int, attempt: int) -> Scan | None:
    """Lock the scan row and decide whether this attempt may run.

    attempt 0 starts only from SUBMITTED (BR-04). attempt N>0 starts only if
    the row is still ANALYZING with retry_count == N and a reason code left
    by the previous attempt; that reason code is then cleared, so a duplicate
    delivery of the same attempt is an idempotent no-op.
    """
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None:
            logger.warning("run_scan: scan %s does not exist; nothing to do.", scan_id)
            return None
        if attempt == 0:
            if scan.status != Scan.Status.SUBMITTED:
                logger.info(
                    "run_scan: scan %s is %s, not submitted; idempotent skip.",
                    scan_id,
                    scan.status,
                )
                return None
            change_status(scan, Scan.Status.ANALYZING, actor=None)
            scan.retry_count = 0
            scan.reason_code = ""
            scan.error_message = None
            scan.save(
                update_fields=["retry_count", "reason_code", "error_message"]
            )
            return scan
        if (
            scan.status != Scan.Status.ANALYZING
            or scan.retry_count != attempt
            or not scan.reason_code
        ):
            logger.info(
                "run_scan: scan %s attempt %d is not pending (status=%s, "
                "retry_count=%s); idempotent skip.",
                scan_id,
                attempt,
                scan.status,
                scan.retry_count,
            )
            return None
        # Consume the pending retry marker: a duplicate delivery finds it empty.
        scan.reason_code = ""
        scan.error_message = None
        scan.save(update_fields=["reason_code", "error_message", "updated_at"])
        return scan


def _schedule_retry(
    scan_id: int, next_attempt: int, delay: int, exc: BaseException
) -> bool:
    """Keep the scan ANALYZING and queue the next attempt after `delay` s."""
    reason = getattr(exc, "reason", "COLLECTOR_UNAVAILABLE")
    detail = _sanitize_error(exc)
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if (
            scan is None
            or scan.status != Scan.Status.ANALYZING
            or scan.retry_count != next_attempt - 1
        ):
            logger.info(
                "run_scan: scan %s attempt %d not scheduled (status/retry moved).",
                scan_id,
                next_attempt,
            )
            return False
        scan.retry_count = next_attempt
        scan.reason_code = reason[:64]
        scan.error_message = detail
        scan.save(
            update_fields=[
                "retry_count",
                "reason_code",
                "error_message",
                "updated_at",
            ]
        )
    logger.warning(
        "run_scan: scan %s attempt %d/%d failed (%s); retrying in %d s.",
        scan_id,
        next_attempt,
        MAX_SCAN_ATTEMPTS,
        reason,
        delay,
    )
    # Queue only once the row is committed: the worker may run immediately.
    transaction.on_commit(
        lambda: schedule_scan_attempt(scan_id, next_attempt, delay)
    )
    return True


def schedule_scan_attempt(scan_id: int, attempt: int, delay: int) -> None:
    """Broker entry point for a retried attempt (monkeypatched in tests)."""
    run_scan.apply_async(args=(scan_id, attempt), countdown=delay)


def _mark_failed(scan_id: int, reason: str, *, reason_code: str = "") -> bool:
    """Move ANALYZING -> FAILED and store a short reason (+ optional reason_code).

    Returns False (and stores nothing) if the status changed concurrently:
    the run is abandoned instead of overwriting another decision.
    """
    error = _sanitize_reason(reason)
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
        scan.reason_code = (reason_code or error)[:64]
        scan.save(update_fields=["error_message", "reason_code"])
        change_status(scan, Scan.Status.FAILED, actor=None)
    logger.warning("run_scan: scan %s failed: %s", scan_id, error)
    return True


def _mark_failed_exception(scan_id: int, exc: BaseException) -> bool:
    """Mark FAILED from an unexpected exception (sanitized)."""
    return _mark_failed(scan_id, _sanitize_error(exc))


def _store_result(scan_id: int, outcome: ScanOutcome, *, model_version_label: str) -> str | None:
    """Store the verdict + new real-pipeline fields, then DETECTED,
    then UNDER_REVIEW when `escalate_to_review` is true.

    `model_version_label` is stamped from the active ModelVersion (empty when
    none is active); `model_bundle_version` comes from the inference /health
    bundle id (MOCK path leaves it empty).
    """
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None or scan.status != Scan.Status.ANALYZING:
            logger.info(
                "run_scan: scan %s is %s; result not stored.",
                scan_id,
                getattr(scan, "status", "missing"),
            )
            return None
        scan.verdict = outcome.verdict
        scan.score = outcome.score
        scan.model_version = model_version_label
        scan.partial = outcome.partial
        scan.reason_code = outcome.reason_code
        scan.final_url = outcome.final_url
        scan.signals = outcome.signals
        scan.probabilities = outcome.probabilities
        scan.model_bundle_version = outcome.model_bundle_version
        scan.screenshot_path = outcome.screenshot_path
        scan.error_message = None
        scan.save(
            update_fields=[
                "verdict",
                "score",
                "model_version",
                "partial",
                "reason_code",
                "final_url",
                "signals",
                "probabilities",
                "model_bundle_version",
                "screenshot_path",
                "error_message",
                "updated_at",
            ]
        )
        change_status(scan, Scan.Status.DETECTED, actor=None)
        if outcome.escalate_to_review:
            change_status(scan, Scan.Status.UNDER_REVIEW, actor=None)
        logger.info(
            "run_scan: scan %s verdict=%s score=%s partial=%s bundle=%s",
            scan_id,
            outcome.verdict,
            outcome.score,
            outcome.partial,
            outcome.model_bundle_version,
        )
        return scan.status


def _signals_from_capture(capture) -> dict[str, Any]:
    """Captured signals stored on the scan (the metadata MLP inputs)."""
    return {
        "ssl": capture.ssl,
        "tld": capture.tld,
        "domain": capture.domain,
        "fld": capture.fld,
        "subdomain": capture.subdomain,
    }


def _run_mock_path(scan_id: int, url: str, mode: str) -> str | None:
    """Active version is absent or MOCK/ONNX: keep the existing MOCK flow."""
    result: PredictionResult = predict(url, mode)
    outcome = ScanOutcome(
        verdict=result.verdict,
        score=result.score,
        partial=False,
        reason_code="",
        final_url="",
        signals={},
        probabilities={},
        model_bundle_version="",
        screenshot_path="",
        escalate_to_review=(result.verdict == VERDICT_UNCERTAIN),
    )
    from controlpanel.services import get_active_model_version_label

    return _store_result(
        scan_id, outcome, model_version_label=get_active_model_version_label()
    )


def _run_real_pipeline(scan_id: int, active, scan: Scan) -> str | None:
    """Collector -> (screenshot) -> inference for an active TORCH_BUNDLE."""
    url = scan.url
    collector = CollectorClient()
    capture = collector.collect(url)

    if capture.status != "complete":
        # Site-level partial: verdict UNCERTAIN, DETECTED (not UNDER_REVIEW),
        # reason_code carries the collector's reason. No inference call.
        outcome = ScanOutcome(
            verdict=VERDICT_UNCERTAIN,
            score=None,
            partial=True,
            reason_code=capture.reason_code or "COLLECTOR_PARTIAL",
            final_url=capture.final_url or url,
            signals=_signals_from_capture(capture),
            probabilities={},
            model_bundle_version="",
            screenshot_path="",
            escalate_to_review=False,
        )
        return _store_result(scan_id, outcome, model_version_label=active.version)

    screenshot_path, screenshot_png = prepare_screenshot(
        scan.public_id, capture.screenshot_png_base64
    )

    inference = InferenceClient()
    inf = inference.predict(
        url=capture.final_url or url,
        text=capture.text or "",
        screenshot_png=screenshot_png,
        ssl=capture.ssl,
        tld=capture.tld,
        subdomain=capture.subdomain,
    )

    if inf.model_bundle_version and inf.model_bundle_version != active.version:
        message = (
            f"model_mismatch: bundle {inf.model_bundle_version} != "
            f"active {active.version}"
        )
        ok = _mark_failed(scan_id, message, reason_code="MODEL_MISMATCH")
        return Scan.Status.FAILED if ok else None

    signals = _signals_from_capture(capture)
    final_url = capture.final_url or url

    if inf.status == "uncertain" or inf.partial:
        outcome = ScanOutcome(
            verdict=VERDICT_UNCERTAIN,
            score=None,
            partial=True,
            reason_code=inf.reason_code or "MODEL_UNCERTAIN",
            final_url=final_url,
            signals=signals,
            probabilities={**inf.base_probabilities, "fusion": None},
            model_bundle_version=inf.model_bundle_version,
            screenshot_path=screenshot_path,
            escalate_to_review=False,
        )
        return _store_result(scan_id, outcome, model_version_label=active.version)

    score = inf.phishing_probability
    lower, upper = _thresholds()
    verdict = classify_score(score, lower, upper)
    outcome = ScanOutcome(
        verdict=verdict,
        score=score,
        partial=False,
        reason_code="",
        final_url=final_url,
        signals=signals,
        probabilities={**inf.base_probabilities, "fusion": score},
        model_bundle_version=inf.model_bundle_version,
        screenshot_path=screenshot_path,
        escalate_to_review=(verdict == VERDICT_UNCERTAIN),
    )
    return _store_result(scan_id, outcome, model_version_label=active.version)


@shared_task(name="scans.run_scan", acks_late=True, reject_on_worker_lost=True)
def run_scan(scan_id: int, attempt: int = 0) -> str | None:
    """Analyze one scan: Submitted -> Analyzing -> Detected/Under review/Failed.

    Picks the active ModelVersion (BR-11): MOCK/none -> the existing MOCK
    path; TORCH_BUNDLE -> collector + inference. Returns the final status, or
    None when the scan is left ANALYZING for a retry / skipped (unknown id,
    wrong status or already-consumed attempt - idempotence).
    acks_late + reject_on_worker_lost: a worker killed mid-analysis is
    re-delivered, and the attempt marker makes the second run a no-op instead
    of a duplicate verdict (ISO-6.5).
    """
    scan = _start_attempt(scan_id, attempt)
    if scan is None:
        return None
    try:
        from controlpanel.models import ModelVersion

        active = ModelVersion.objects.filter(is_active=True).first()
        if active is None or active.kind != ModelVersion.Kind.TORCH_BUNDLE:
            # Guard against silent MOCK runs (E2E honesty): the verdict is a
            # deterministic hash, NOT the torch bundle. Never log the URL.
            logger.warning(
                "run_scan: scan %s uses the MOCK path (active model: %s) - "
                "NOT the real collector+inference pipeline",
                scan_id,
                f"{active.kind} {active.version}" if active else "none",
            )
            return _run_mock_path(scan_id, scan.url, scan.mode)
        return _run_real_pipeline(scan_id, active, scan)
    except (CollectorError, InferenceError) as exc:
        reason = getattr(exc, "reason", "COLLECTOR_UNAVAILABLE")
        if exc.retryable and attempt + 1 < MAX_SCAN_ATTEMPTS:
            _schedule_retry(
                scan_id,
                next_attempt=attempt + 1,
                delay=RETRY_DELAYS[attempt],
                exc=exc,
            )
            return None
        logger.error(
            "run_scan: scan %s attempt %d/%d exhausted (%s: %s)",
            scan_id,
            attempt + 1,
            MAX_SCAN_ATTEMPTS,
            type(exc).__name__,
            reason,
        )
        ok = _mark_failed(scan_id, _sanitize_error(exc), reason_code=reason)
        return Scan.Status.FAILED if ok else None
    except Exception as exc:  # noqa: BLE001 - any failure must end as FAILED, never crash the worker
        logger.error(
            "run_scan: scan %s unexpected %s", scan_id, type(exc).__name__
        )
        return Scan.Status.FAILED if _mark_failed_exception(scan_id, exc) else None


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
