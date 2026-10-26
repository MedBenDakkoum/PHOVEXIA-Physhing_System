"""Request/response models of the collector HTTP contract (spec v1 section 5)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CollectRequest(BaseModel):
    url: str


class TlsInfo(BaseModel):
    ok: bool
    error: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    self_signed: bool | None = None


class TimingsInfo(BaseModel):
    total: int
    navigation: int | None = None
    screenshot: int | None = None
    text_extraction: int | None = None
    tls_probe: int | None = None


class CollectResponse(BaseModel):
    status: Literal["complete", "partial"]
    reason_code: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    http_status: int | None = None
    text: str | None = None
    ssl: int | None = None
    tld: str | None = None
    domain: str | None = None
    fld: str | None = None
    subdomain: str | None = None
    screenshot_png_base64: str | None = None
    tls: TlsInfo
    timings_ms: TimingsInfo
