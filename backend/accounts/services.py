"""Step 13 - password reset business logic (US5) + per-email throttle.

Rules enforced here (the views stay thin):
- request_password_reset(email): the lookup, the token and the email happen
  INSIDE the Celery task, so the HTTP response time can never reveal
  whether the account exists (no enumeration).
- confirm_password_reset(uid, token, new_password): the token is checked
  under a row lock; it works only ONCE (Django's PasswordResetTokenGenerator
  folds the password hash into the token, so changing the password
  invalidates it); every outstanding refresh token is blacklisted.
- An invalid, expired, already-used token OR a suspended account all raise
  the SAME InvalidResetToken -> the endpoint answers the same 400 (never
  says which).
- hit_email_throttle(email): 3 requests/hour per HASHED email address
  (cache counter, atomic add/incr pattern like BR-02); the identity is the
  typed address hashed with SHA-256, so the cache never stores a raw email.
"""
from __future__ import annotations

import hashlib
import logging
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.db import transaction
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)

from audit.models import AuditLog
from audit.services import record
from emails.services import send_templated_email

logger = logging.getLogger(__name__)
User = get_user_model()

PASSWORD_RESET_EMAIL_LIMIT = 3
PASSWORD_RESET_EMAIL_WINDOW = 3600  # seconds


class InvalidResetToken(Exception):
    """Invalid, expired, already-used token, or suspended account."""


class EmailThrottleExceeded(Exception):
    """The typed address already used its hourly reset-request budget."""

    def __init__(self, limit: int, retry_after: int):
        self.limit = limit
        self.retry_after = retry_after
        super().__init__(
            f"Password reset limit reached: {limit} per hour per address "
            f"(retry in {retry_after}s)."
        )


def encode_uid(user) -> str:
    return urlsafe_base64_encode(force_bytes(user.pk))


def build_reset_link(user) -> str:
    """FRONTEND_URL/reset-password?uid=...&token=... (one-shot token)."""
    uid = encode_uid(user)
    token = default_token_generator.make_token(user)
    return f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"


def _email_key(email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    return f"password-reset:{digest}"


def _retry_after(reset_key: str) -> int:
    reset_at = cache.get(reset_key)
    if not isinstance(reset_at, int):
        return PASSWORD_RESET_EMAIL_WINDOW
    return max(1, reset_at - int(time.time()))


def hit_email_throttle(email: str) -> int:
    """Consume one unit of the per-address budget; raise when it is used up.

    Returns the count for this window. Atomic pattern only (cache.add then
    cache.incr), identical to the BR-02 quick-check counter.
    """
    counter_key = _email_key(email)
    reset_key = f"{counter_key}:reset"
    if cache.add(counter_key, 1, timeout=PASSWORD_RESET_EMAIL_WINDOW):
        count = 1
        cache.add(
            reset_key,
            int(time.time()) + PASSWORD_RESET_EMAIL_WINDOW,
            timeout=PASSWORD_RESET_EMAIL_WINDOW,
        )
    else:
        try:
            count = cache.incr(counter_key)
        except ValueError:
            cache.add(counter_key, 1, timeout=PASSWORD_RESET_EMAIL_WINDOW)
            count = 1
    if count > PASSWORD_RESET_EMAIL_LIMIT:
        raise EmailThrottleExceeded(
            limit=PASSWORD_RESET_EMAIL_LIMIT, retry_after=_retry_after(reset_key)
        )
    return count


def email_throttle_response(exc: EmailThrottleExceeded) -> Response:
    """HTTP 429 body + Retry-After for the per-address limit."""
    response = Response(
        {
            "detail": (
                f"Trop de demandes de réinitialisation pour cette adresse : "
                f"{exc.limit} par heure. Réessayez plus tard."
            ),
            "limit": exc.limit,
        },
        status=status.HTTP_429_TOO_MANY_REQUESTS,
    )
    response["Retry-After"] = str(exc.retry_after)
    return response


def request_password_reset(email: str) -> None:
    """Run INSIDE the Celery task: lookup + token + audit + email.

    Email is sent only to an existing ACTIVE account; an unknown or
    suspended address does nothing and logs nothing about the address
    (the audit entry carries the user id only when the user exists).
    """
    user = User.objects.filter(email__iexact=email, is_active=True).first()
    if user is None:
        logger.info("password_reset_skipped kind=password_reset")
        return
    record(
        AuditLog.Action.PASSWORD_RESET_REQUESTED,
        user=user,
        target=user,
    )
    send_templated_email(
        user.email,
        "password_reset",
        {
            "link": build_reset_link(user),
            "first_name": user.first_name or user.email,
            "valid_hours": max(1, settings.PASSWORD_RESET_TIMEOUT // 3600),
        },
        user_id=user.pk,
    )


def _user_from_uid(uid: str) -> User:
    try:
        pk = urlsafe_base64_decode(uid).decode()
        return User.objects.get(pk=pk)
    except (ValueError, TypeError, UnicodeDecodeError, User.DoesNotExist) as exc:
        raise InvalidResetToken from exc


def _blacklist_refresh_tokens(user) -> int:
    """Blacklist every outstanding refresh token of the user (US5)."""
    tokens = list(OutstandingToken.objects.filter(user=user))
    for token in tokens:
        BlacklistedToken.objects.get_or_create(token=token)
    return len(tokens)


def confirm_password_reset(
    *, uid: str, token: str, new_password: str, request=None
) -> User:
    """Set the new password once the token is validated under a row lock.

    Raises InvalidResetToken for anything wrong (same 400 either way).
    On success: password set, ALL outstanding refresh tokens blacklisted,
    audit password.reset_completed, "password changed" security email
    (always sent, never gated by email_notifications).
    """
    user = _user_from_uid(uid)
    if not user.is_active:
        raise InvalidResetToken
    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user.pk)
        # check_token under the lock: two concurrent confirms cannot both
        # pass (the loser sees the changed password hash -> InvalidResetToken).
        if not default_token_generator.check_token(locked, token):
            raise InvalidResetToken
        locked.set_password(new_password)
        locked.save(update_fields=["password"])
        _blacklist_refresh_tokens(locked)
        record(
            AuditLog.Action.PASSWORD_RESET_COMPLETED,
            request=request,
            user=locked,
            target=locked,
        )
    send_templated_email(
        locked.email,
        "password_changed",
        {"first_name": locked.first_name or locked.email},
        user_id=locked.pk,
    )
    return locked
