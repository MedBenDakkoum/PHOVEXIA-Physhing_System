"""Outbound integration events (n8n), disabled by default.

``N8N_WEBHOOK_BASE_URL`` empty = the whole feature is a no-op: no event id is
built, no Celery task is queued. When it is set, ``N8N_WEBHOOK_SECRET`` is
required at startup (config/settings.py) and every event is signed.

The payload is deliberately minimal and privacy-safe: no full URL, no email,
no user name. Only the scan domain, verdicts, risk index, detection source,
the event time and a review link built from FRONTEND_URL.
"""
from __future__ import annotations

import logging
import uuid
from functools import partial
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .events import (
    EVENT_PATHS,
    SCAN_CONFIRMED,
    SCAN_NEEDS_REVIEW,
)
from .tasks import deliver_event

logger = logging.getLogger(__name__)


def is_enabled() -> bool:
    """True only when a base URL is configured (empty = feature disabled)."""
    return bool((settings.N8N_WEBHOOK_BASE_URL or "").strip())


def emit_event(event_type: str, payload: dict[str, Any] | None = None) -> str | None:
    """Build one event and enqueue its delivery AFTER the current commit.

    Returns the event id, or None when the feature is disabled or the event
    type is unknown. Never takes a destination: the host is fixed by settings.
    """
    if not is_enabled():
        return None
    if event_type not in EVENT_PATHS:
        logger.warning("integration.unknown_event event_type=%s", event_type)
        return None

    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "occurred_at": timezone.now().isoformat(),
        "data": payload or {},
    }
    transaction.on_commit(partial(deliver_event.delay, event))
    return event["id"]


def _scan_payload(scan, *, review_reason: str | None = None) -> dict[str, Any]:
    """Minimal, privacy-safe scan payload (never the URL or a user identity)."""
    payload: dict[str, Any] = {
        "scan_id": str(scan.public_id),
        "domain": scan.domain,
        "verdict": scan.verdict,
        "model_verdict": scan.model_verdict,
        "risk_index": scan.score,
        "source": scan.detection_source,
        "review_url": f"{settings.FRONTEND_URL}/review/{scan.public_id}",
    }
    if review_reason is not None:
        payload["review_reason"] = review_reason
    return payload


def emit_scan_confirmed(scan) -> str | None:
    """scan.confirmed: an analyst saved a CONFIRM_PHISHING decision."""
    return emit_event(SCAN_CONFIRMED, _scan_payload(scan))


def emit_scan_needs_review(scan, *, reason: str) -> str | None:
    """scan.needs_review: uncertain verdict or owner report (never partial)."""
    if scan.partial:
        return None
    return emit_event(
        SCAN_NEEDS_REVIEW, _scan_payload(scan, review_reason=reason)
    )
