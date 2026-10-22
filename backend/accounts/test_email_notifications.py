"""
Step 13 tests - notification emails (US56, US57) + email_notifications (US6).

Contract verified here:
- Welcome email after registration, queued AFTER the commit (on_commit).
- "Password changed" security email after the change-password endpoint.
- Suspension / reactivation security emails ALWAYS sent, even when the
  user opted out of email_notifications.
- Report-decision email (US57) respects email_notifications; the in-app
  Notification is always created either way.
- PATCH /api/auth/me/ can toggle email_notifications.
"""
import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from rest_framework import status as http_status

from reviews.models import Notification, Report
from scans.models import Scan

User = get_user_model()
pytestmark = pytest.mark.django_db

PASSWORD = "StrongPass!234"
NEW_PASSWORD = "AnotherStrong!567"


def test_registration_sends_the_welcome_email_only_after_commit(
    api_client, django_capture_on_commit_callbacks
):
    with django_capture_on_commit_callbacks(execute=False):
        response = api_client.post(
            reverse("register"),
            {"email": "new@example.com", "password": PASSWORD},
            format="json",
        )
    assert response.status_code == http_status.HTTP_201_CREATED
    # The task is still queued behind on_commit: nothing sent yet.
    assert mail.outbox == []

    with django_capture_on_commit_callbacks(execute=True):
        api_client.post(
            reverse("register"),
            {"email": "second@example.com", "password": PASSWORD},
            format="json",
        )
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["second@example.com"]
    assert "Bienvenue" in mail.outbox[0].subject


def test_change_password_sends_the_security_email(
    auth_client, viewer, django_capture_on_commit_callbacks
):
    with django_capture_on_commit_callbacks(execute=True):
        response = auth_client.post(
            reverse("change_password"),
            {"old_password": PASSWORD, "new_password": NEW_PASSWORD},
            format="json",
        )
    assert response.status_code == http_status.HTTP_204_NO_CONTENT
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == [viewer.email]
    assert "modifié" in mail.outbox[0].subject


def test_suspension_and_reactivation_emails_ignore_email_notifications(
    admin_client, make_user, django_capture_on_commit_callbacks
):
    """Security emails are ALWAYS sent (flag False on purpose)."""
    user = make_user(email="victim@example.com", email_notifications=False)
    url = reverse("user-detail", args=[user.pk])

    with django_capture_on_commit_callbacks(execute=True):
        deleted = admin_client.delete(url)
    assert deleted.status_code == http_status.HTTP_204_NO_CONTENT
    assert len(mail.outbox) == 1
    assert "Suspension" in mail.outbox[0].subject

    with django_capture_on_commit_callbacks(execute=True):
        restored = admin_client.patch(url, {"is_active": True}, format="json")
    assert restored.status_code == http_status.HTTP_200_OK
    assert len(mail.outbox) == 2
    assert "Réactivation" in mail.outbox[1].subject


def _make_reported_scan(owner):
    """A UNDER_REVIEW scan with one open report (ready for a decision)."""
    scan = Scan.objects.create(
        owner=owner,
        url="https://phish.example.com/login",
        domain="phish.example.com",
        mode="fast",
        status=Scan.Status.UNDER_REVIEW,
    )
    Report.objects.create(scan=scan, reporter=owner, claimed_label="safe")
    return scan


def test_decision_email_respects_email_notifications(
    api_client, make_user, analyst, django_capture_on_commit_callbacks
):
    reporter_on = make_user(email="on@example.com")
    reporter_off = make_user(email="off@example.com", email_notifications=False)
    scan_on = _make_reported_scan(reporter_on)
    scan_off = _make_reported_scan(reporter_off)

    api_client.force_authenticate(analyst)
    with django_capture_on_commit_callbacks(execute=True):
        first = api_client.post(
            reverse("review-decision", args=[scan_on.public_id]),
            {"decision": "confirm_phishing"},
            format="json",
        )
        second = api_client.post(
            reverse("review-decision", args=[scan_off.public_id]),
            {"decision": "confirm_phishing"},
            format="json",
        )
    assert first.status_code == second.status_code == http_status.HTTP_200_OK

    # Only the reporter who did NOT opt out received the email.
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["on@example.com"]
    assert "signalement" in mail.outbox[0].subject.lower()

    # The in-app Notification exists for BOTH reporters.
    assert Notification.objects.filter(user=reporter_on).count() == 1
    assert Notification.objects.filter(user=reporter_off).count() == 1


def test_me_patch_can_toggle_email_notifications(auth_client, viewer):
    assert viewer.email_notifications is True

    response = auth_client.patch(
        reverse("me"), {"email_notifications": False}, format="json"
    )

    assert response.status_code == http_status.HTTP_200_OK
    assert response.json()["email_notifications"] is False
    viewer.refresh_from_db()
    assert viewer.email_notifications is False


def test_a_failed_send_never_breaks_the_user_action(
    auth_client, viewer, settings, django_capture_on_commit_callbacks
):
    """A broken SMTP (here: an unknown backend) must not fail the request."""
    from django.core.mail.backends.base import BaseEmailBackend

    class BrokenBackend(BaseEmailBackend):
        def send_messages(self, email_messages):
            raise OSError("connection refused")

    settings.MAILERS = {
        "default": {"BACKEND": "accounts.test_email_notifications.BrokenBackend"}
    }
    with django_capture_on_commit_callbacks(execute=True):
        response = auth_client.post(
            reverse("change_password"),
            {"old_password": PASSWORD, "new_password": NEW_PASSWORD},
            format="json",
        )

    assert response.status_code == http_status.HTTP_204_NO_CONTENT
    viewer.refresh_from_db()
    assert viewer.check_password(NEW_PASSWORD)
