"""Constant-time API-key comparison."""

from __future__ import annotations

import hmac


def is_valid_api_key(candidate: str, expected: str) -> bool:
    """Compare in constant time; never short-circuits on length alone."""
    if not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))
