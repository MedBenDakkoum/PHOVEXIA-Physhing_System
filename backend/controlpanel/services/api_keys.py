"""US54 - API key service: generation, hashing, revoke.

The secret (secrets.token_urlsafe(32)) exists ONLY in the creation response:
we store its SHA-256 hash plus the first 8 characters (prefix) used to
narrow the lookup before a constant-time compare. The audit metadata keeps
the prefix and the scopes, NEVER the secret.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import record

from ..models import ApiKey

PREFIX_LEN = 8
SECRET_BYTES = 32
LAST_USED_GRACE_SECONDS = 60


def generate_secret() -> str:
    return secrets.token_urlsafe(SECRET_BYTES)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def create_api_key(
    *, name: str, owner, scopes: list[str], expires_at=None, request=None
) -> tuple[ApiKey, str]:
    """Create a key and return (row, plaintext secret) - shown once (US54)."""
    secret = generate_secret()
    with transaction.atomic():
        key = ApiKey.objects.create(
            name=name,
            owner=owner,
            key_prefix=secret[:PREFIX_LEN],
            key_hash=hash_secret(secret),
            scopes=scopes,
            expires_at=expires_at,
        )
        record(
            AuditLog.Action.APIKEY_CREATED,
            request=request,
            user=owner,
            target=key,
            metadata={"name": name, "prefix": key.key_prefix, "scopes": scopes},
        )
    return key, secret


def revoke_api_key(key: ApiKey, *, user, request=None) -> ApiKey:
    """Soft revoke: is_active=False + revoked_at stamped (the row stays)."""
    if key.revoked_at is None:
        with transaction.atomic():
            key.is_active = False
            key.revoked_at = timezone.now()
            key.save(update_fields=["is_active", "revoked_at"])
            record(
                AuditLog.Action.APIKEY_REVOKED,
                request=request,
                user=user,
                target=key,
                metadata={"name": key.name, "prefix": key.key_prefix},
            )
    return key


def lookup_secret(secret: str) -> ApiKey | None:
    """Prefix-narrowed lookup + constant-time hash compare (timing safety)."""
    digest = hash_secret(secret)
    candidates = ApiKey.objects.select_related("owner").filter(
        key_prefix=secret[:PREFIX_LEN]
    )
    found = None
    # Scan every candidate of this prefix and compare in constant time, so
    # the number of rows never short-circuits the comparison.
    for candidate in candidates:
        if hmac.compare_digest(candidate.key_hash, digest):
            found = candidate
    return found


def touch_last_used(key: ApiKey) -> None:
    """Stamp last_used_at at most once per minute (no write on every call)."""
    now = timezone.now()
    if key.last_used_at is None or (
        now - key.last_used_at
    ).total_seconds() >= LAST_USED_GRACE_SECONDS:
        ApiKey.objects.filter(pk=key.pk).update(last_used_at=now)
        key.last_used_at = now
