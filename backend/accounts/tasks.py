"""Step 13 - Celery task for the password-reset email (US5).

Thin wrapper: the business logic lives in accounts.services so the view
never does the user lookup (no enumeration through the response time).
"""
from __future__ import annotations

from celery import shared_task


@shared_task(name="accounts.send_password_reset_email")
def send_password_reset_email(email: str) -> None:
    from .services import request_password_reset

    request_password_reset(email)
