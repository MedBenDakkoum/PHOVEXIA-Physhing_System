"""Celery task delivering one integration event to the configured n8n webhook.

Rules:
- destination = ``{N8N_WEBHOOK_BASE_URL}/webhook/<fixed event path>`` (the
  host NEVER comes from the event payload or from user input);
- the JSON body is signed with HMAC-SHA256 using ``N8N_WEBHOOK_SECRET``;
- 5 s HTTP timeout, 3 retries with growing delays (5 s, 15 s, 45 s);
- after the last retry the failure is written as an immutable audit entry
  (event type and id only) and the task returns: it NEVER raises into the
  caller (business code or the originating HTTP request).
- logs carry the event type and the HTTP status only: never the body, the
  payload or the secret.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

import requests
from celery import shared_task
from django.conf import settings

from audit.models import AuditLog
from audit.services import record

from .events import EVENT_PATHS

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = (5, 15, 45)
HTTP_TIMEOUT_SECONDS = 5


@shared_task(bind=True, max_retries=MAX_RETRIES)
def deliver_event(self, event: dict) -> None:
    event_type = str(event.get("type", ""))
    event_id = str(event.get("id", ""))
    path = EVENT_PATHS.get(event_type)
    base = (settings.N8N_WEBHOOK_BASE_URL or "").rstrip("/")
    secret = settings.N8N_WEBHOOK_SECRET or ""

    if not base or not secret or path is None:
        logger.info("integration.delivery_skipped event_type=%s", event_type)
        return

    body = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Secret": secret,
        "X-Event-Id": event_id,
        "X-Signature": signature,
    }
    url = f"{base}/webhook/{path}"

    try:
        response = requests.post(
            url, data=body, headers=headers, timeout=HTTP_TIMEOUT_SECONDS
        )
        response.raise_for_status()
    except Exception as exc:  # every failure is retried, then audited
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if self.request.retries < self.max_retries:
            delay = RETRY_DELAYS[
                min(self.request.retries, len(RETRY_DELAYS) - 1)
            ]
            raise self.retry(exc=exc, countdown=delay) from exc
        logger.warning(
            "integration.delivery_failed event_type=%s status=%s",
            event_type,
            status if status is not None else "none",
        )
        record(
            AuditLog.Action.INTEGRATION_DELIVERY_FAILED,
            metadata={"event_type": event_type, "event_id": event_id},
        )
        return

    logger.info(
        "integration.delivered event_type=%s status=%s",
        event_type,
        response.status_code,
    )
