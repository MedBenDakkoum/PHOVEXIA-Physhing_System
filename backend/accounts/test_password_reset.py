"""
Step 13 tests - password reset (US5 / ISO-6.6 anti-enumeration).

Contract verified here:
- POST /api/auth/password-reset/ always answers the same 202 (existing,
  unknown or suspended email); the email is sent only to an ACTIVE account.
- The emailed link works end to end; the token is single-use; an expired
  token, a bad uid and an already-used token all give the SAME 400 with
  code invalid_or_expired_token.
- After confirm: all outstanding refresh tokens are blacklisted and login
  works with the new password.
- Throttles: 5/hour/IP, 3/hour per HASHED email, confirm 10/hour/IP.
- No token, link or email body in the logs or in the audit entries.

Celery is eager (conftest) and emails use the locmem backend (outbox).
"""
import logging
import re
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.urls import reverse
from rest_framework import status as http_status

from accounts.services import _email_key, encode_uid
from audit.models import AuditLog

User = get_user_model()
pytestmark = pytest.mark.django_db

PASSWORD = "StrongPass!234"
NEW_PASSWORD = "BrandNew!Pass789"
RESET_URL = "password_reset"
CONFIRM_URL = "password_reset_confirm"
INVALID_CODE = "invalid_or_expired_token"

LINK_RE = re.compile(r"(http://localhost:5173/reset-password\?uid=[^\s&]+&token=[^\s]+)")


def _request_reset(client, email, **extra):
    return client.post(
        reverse(RESET_URL), {"email": email}, format="json", **extra
    )


def _extract_link(body: str) -> tuple[str, str]:
    match = LINK_RE.search(body)
    assert match, f"no reset link in the email body: {body!r}"
    query = match.group(1).split("?", 1)[1]
    uid = query.split("uid=", 1)[1].split("&", 1)[0]
    token = query.split("token=", 1)[1].split()[0]
    return uid, token


def test_reset_request_returns_the_same_202_for_existing_unknown_and_suspended(
    api_client, make_user, django_capture_on_commit_callbacks
):
    """US5 / no enumeration: identical status AND body, email only if active."""
    make_user(email="active@example.com")
    make_user(email="off@example.com", is_active=False)

    responses = []
    for email in ["active@example.com", "ghost@example.com", "off@example.com"]:
        with django_capture_on_commit_callbacks(execute=True):
            responses.append(_request_reset(api_client, email))

    assert [r.status_code for r in responses] == [
        http_status.HTTP_202_ACCEPTED,
        http_status.HTTP_202_ACCEPTED,
        http_status.HTTP_202_ACCEPTED,
    ]
    bodies = [r.json() for r in responses]
    assert bodies[0] == bodies[1] == bodies[2]

    # Exactly one email, to the active account only.
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == ["active@example.com"]

    # Audit: only the existing ACTIVE user is recorded, never the typed
    # email of an unknown address.
    entries = AuditLog.objects.filter(action="password.reset_requested")
    assert entries.count() == 1
    assert entries.get().user == User.objects.get(email="active@example.com")
    assert not AuditLog.objects.filter(user_email="ghost@example.com").exists()


def test_reset_link_works_end_to_end_and_login_uses_the_new_password(
    api_client, make_user, django_capture_on_commit_callbacks
):
    user = make_user(email="alice@example.com")
    with django_capture_on_commit_callbacks(execute=True):
        assert _request_reset(api_client, user.email).status_code == 202

    uid, token = _extract_link(mail.outbox[0].body)
    with django_capture_on_commit_callbacks(execute=True):
        response = api_client.post(
            reverse(CONFIRM_URL),
            {"uid": uid, "token": token, "new_password": NEW_PASSWORD},
            format="json",
        )
    assert response.status_code == http_status.HTTP_200_OK

    login = api_client.post(
        reverse("login"),
        {"email": user.email, "password": NEW_PASSWORD},
        format="json",
    )
    assert login.status_code == http_status.HTTP_200_OK
    assert "access" in login.json()


def test_a_reset_token_works_only_once(
    api_client, make_user, django_capture_on_commit_callbacks
):
    user = make_user(email="once@example.com")
    with django_capture_on_commit_callbacks(execute=True):
        _request_reset(api_client, user.email)
    uid, token = _extract_link(mail.outbox[0].body)
    payload = {"uid": uid, "token": token, "new_password": NEW_PASSWORD}

    with django_capture_on_commit_callbacks(execute=True):
        first = api_client.post(reverse(CONFIRM_URL), payload, format="json")
    second = api_client.post(reverse(CONFIRM_URL), payload, format="json")

    assert first.status_code == http_status.HTTP_200_OK
    assert second.status_code == http_status.HTTP_400_BAD_REQUEST
    assert second.json()["code"] == INVALID_CODE


def test_an_expired_token_gives_the_same_400(api_client, make_user):
    user = make_user(email="late@example.com")
    uid = encode_uid(user)
    token = default_token_generator.make_token(user)
    # PasswordResetTokenGenerator._now() is naive datetime.now(): the mock
    # must stay naive or the subtraction raises TypeError.
    future = datetime.now() + timedelta(seconds=3600 + 60)  # noqa: DTZ005 - must match Django's naive _now()

    with patch.object(type(default_token_generator), "_now", return_value=future):
        response = api_client.post(
            reverse(CONFIRM_URL),
            {"uid": uid, "token": token, "new_password": NEW_PASSWORD},
            format="json",
        )

    assert response.status_code == http_status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == INVALID_CODE


def test_a_weak_password_on_confirm_is_400(
    api_client, make_user, django_capture_on_commit_callbacks
):
    user = make_user(email="weak@example.com")
    with django_capture_on_commit_callbacks(execute=True):
        _request_reset(api_client, user.email)
    uid, token = _extract_link(mail.outbox[0].body)

    response = api_client.post(
        reverse(CONFIRM_URL),
        {"uid": uid, "token": token, "new_password": "123"},
        format="json",
    )

    assert response.status_code == http_status.HTTP_400_BAD_REQUEST
    assert "new_password" in response.json()
    user.refresh_from_db()
    assert user.check_password(PASSWORD)  # unchanged


def test_a_malformed_uid_gives_the_same_400_code(api_client, make_user):
    for uid in ["not-a-uid", "zzzz", "12345"]:
        response = api_client.post(
            reverse(CONFIRM_URL),
            {"uid": uid, "token": "whatever", "new_password": NEW_PASSWORD},
            format="json",
        )
        assert response.status_code == http_status.HTTP_400_BAD_REQUEST
        assert response.json()["code"] == INVALID_CODE


def test_confirm_blacklists_the_outstanding_refresh_tokens(
    api_client, make_user, django_capture_on_commit_callbacks
):
    user = make_user(email="tokens@example.com")
    login = api_client.post(
        reverse("login"),
        {"email": user.email, "password": PASSWORD},
        format="json",
    )
    refresh = login.json()["refresh"]

    with django_capture_on_commit_callbacks(execute=True):
        _request_reset(api_client, user.email)
    uid, token = _extract_link(mail.outbox[0].body)
    with django_capture_on_commit_callbacks(execute=True):
        confirm = api_client.post(
            reverse(CONFIRM_URL),
            {"uid": uid, "token": token, "new_password": NEW_PASSWORD},
            format="json",
        )
    assert confirm.status_code == http_status.HTTP_200_OK

    reused = api_client.post(
        reverse("token_refresh"), {"refresh": refresh}, format="json"
    )
    assert reused.status_code == http_status.HTTP_401_UNAUTHORIZED

    # The security email was also sent (password changed).
    subjects = [m.subject for m in mail.outbox]
    assert any("modifié" in s for s in subjects)


def test_reset_request_is_throttled_per_ip(api_client, make_user):
    for i in range(5):
        response = _request_reset(api_client, f"user{i}@example.com")
        assert response.status_code == http_status.HTTP_202_ACCEPTED

    blocked = _request_reset(api_client, "user5@example.com")
    other_ip = _request_reset(
        api_client, "user5@example.com", REMOTE_ADDR="203.0.113.9"
    )

    assert blocked.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert blocked.has_header("Retry-After")
    assert other_ip.status_code == http_status.HTTP_202_ACCEPTED


def test_reset_request_is_throttled_per_hashed_email(api_client):
    for _ in range(3):
        response = _request_reset(api_client, "same@example.com")
        assert response.status_code == http_status.HTTP_202_ACCEPTED

    blocked = _request_reset(api_client, "same@example.com")
    other_email = _request_reset(api_client, "other@example.com")

    assert blocked.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert blocked.json()["limit"] == 3
    assert other_email.status_code == http_status.HTTP_202_ACCEPTED
    # The cache key is a SHA-256 digest: the raw address is never stored.
    key = _email_key("same@example.com")
    assert "same@example.com" not in key
    assert key.startswith("password-reset:")
    assert len(key) == len("password-reset:") + 64


def test_reset_confirm_is_throttled_per_ip(api_client):
    payload = {"uid": "bogus", "token": "bogus", "new_password": NEW_PASSWORD}
    for _ in range(10):
        response = api_client.post(reverse(CONFIRM_URL), payload, format="json")
        assert response.status_code != http_status.HTTP_429_TOO_MANY_REQUESTS

    blocked = api_client.post(reverse(CONFIRM_URL), payload, format="json")
    assert blocked.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS


def test_no_token_link_or_email_body_in_the_logs_or_audit(
    api_client, make_user, caplog, django_capture_on_commit_callbacks
):
    user = make_user(email="quiet@example.com")
    with (
        caplog.at_level(logging.DEBUG),
        django_capture_on_commit_callbacks(execute=True),
    ):
        _request_reset(api_client, user.email)

    log_text = " ".join(record.getMessage() for record in caplog.records)
    assert "token=" not in log_text
    assert "reset-password" not in log_text
    assert user.email not in log_text

    entry = AuditLog.objects.get(action="password.reset_requested")
    assert entry.user == user
    assert entry.metadata == {}
    assert "token" not in entry.target_repr
    # The completed entry (from a later confirm) must not carry a token either.
    uid, token = _extract_link(mail.outbox[0].body)
    with django_capture_on_commit_callbacks(execute=True):
        api_client.post(
            reverse(CONFIRM_URL),
            {"uid": uid, "token": token, "new_password": NEW_PASSWORD},
            format="json",
        )
    completed = AuditLog.objects.get(action="password.reset_completed")
    assert completed.user == user
    assert completed.metadata == {}
    all_meta = " ".join(str(e.metadata) for e in AuditLog.objects.all())
    assert token not in all_meta
