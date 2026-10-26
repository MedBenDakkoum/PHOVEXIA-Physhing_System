"""Errors that cross the HTTP boundary: stable machine code + generic detail."""
from __future__ import annotations


class ApiError(Exception):
    """Raised by endpoints to produce a {"code", "detail"} JSON body."""

    def __init__(self, status_code: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail
