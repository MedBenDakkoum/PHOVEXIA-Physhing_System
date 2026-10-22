"""Step 13 - the Celery task that actually sends one email.

Rendering + sending live here so the HTTP request never touches SMTP.
autoretry: 3 retries, exponential backoff between attempts.
The queueing side (emails.services) catches an eager-mode failure, so a
broken SMTP can never propagate into a user action.
"""
from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)


@shared_task(
    name="emails.send_email_task",
    autoretry_for=(Exception,),
    retry_backoff=True,  # exponential countdown between retries
    retry_kwargs={"max_retries": 3},
)
def send_email_task(
    to: str, subject: str, template_name: str, context: dict
) -> bool:
    """Render <template_name>.txt + .html (French, autoescape ON) and send."""
    text_body = render_to_string(f"emails/{template_name}.txt", context)
    html_body = render_to_string(f"emails/{template_name}.html", context)
    message = EmailMultiAlternatives(
        subject, text_body, settings.DEFAULT_FROM_EMAIL, [to]
    )
    message.attach_alternative(html_body, "text/html")
    message.send()
    logger.info("email_sent kind=%s", template_name)
    return True
