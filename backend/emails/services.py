"""Step 13 - templated email delivery (US5, US56, US57).

Contract:
- send_templated_email(to, template_name, context) renders the French
  plain-text AND HTML templates (emails/templates/emails/<name>.txt|.html,
  Django autoescape ON for the HTML part) and queues send_email_task with
  transaction.on_commit, so the HTTP request NEVER waits for SMTP.
- The Celery task autoretries 3 times with exponential backoff; a final
  failure is contained in the worker (the queueing side swallows an eager
  failure too), so a broken SMTP can never break a user action.
- Logging rule: only the event kind and the user id are ever logged -
  never the recipient, the message body, the token or the link.
"""
from __future__ import annotations

import logging
from typing import Any

from django.db import transaction

from .tasks import send_email_task

logger = logging.getLogger(__name__)

# template_name -> French subject (single source of truth for subjects).
SUBJECTS: dict[str, str] = {
    "welcome": "Bienvenue sur la plateforme de détection de phishing",
    "password_reset": "Réinitialisation de votre mot de passe",
    "password_changed": "Votre mot de passe a été modifié",
    "account_suspended": "Suspension de votre compte",
    "account_reactivated": "Réactivation de votre compte",
    "report_decision": "Décision sur votre signalement",
}


def send_templated_email(
    to: str,
    template_name: str,
    context: dict[str, Any],
    *,
    user_id: int | None = None,
) -> None:
    """Queue the email AFTER the current transaction commits (never inline).

    `context` must be JSON-serializable (it crosses the Celery broker).
    `user_id` is only used for the log line (never the recipient address).
    """
    try:
        subject = SUBJECTS[template_name]
    except KeyError as exc:
        raise ValueError(f"Unknown email template: {template_name!r}") from exc

    def _queue() -> None:
        try:
            send_email_task.delay(to, subject, template_name, context)
        except Exception:  # noqa: BLE001 - a queue failure must never break the user action
            logger.warning(
                "email_queue_failed kind=%s user_id=%s", template_name, user_id
            )

    transaction.on_commit(_queue)
    logger.info("email_queued kind=%s user_id=%s", template_name, user_id)
