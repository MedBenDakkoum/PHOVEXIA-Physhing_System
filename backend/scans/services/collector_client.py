"""Internal client to the isolated Playwright collector (US17 / US26).

The Celery worker calls POST /collect on the collector container (reachable on
collect_net only; no published port). Every failure here is an infrastructure
failure: the Celery task retries twice with backoff and then ends the scan as
FAILED with a short reason.

Site-level partial results are NOT errors: the collector answers 200 with
`status=partial` + a stable reason_code (SITE_UNREACHABLE, TIMEOUT, ...), and
the task decides the verdict from it.

Never log request bodies or the shared API key.
"""
from __future__ import annotations

import json
from typing import Any

import requests
from django.conf import settings

MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # the collector payload is small JSON


class CollectorError(Exception):
    """Infrastructure or protocol failure talking to the collector.

    `reason` is a short, safe code (no stack trace, no secret) stored on the
    scan as error_message / reason_code.
    """

    def __init__(self, reason: str, status_code: int | None = None):
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


class CollectorResponse:
    """Validated shape of the collector /collect JSON (spec v1 section 5.3)."""

    def __init__(self, data: dict[str, Any]):
        if data.get("status") not in ("complete", "partial"):
            raise CollectorError("COLLECTOR_BAD_SHAPE")
        self.status: str = data["status"]
        self.reason_code: str | None = data.get("reason_code")
        self.final_url: str = data.get("final_url") or ""
        self.redirect_chain: list[str] = data.get("redirect_chain") or []
        self.http_status: int | None = data.get("http_status")
        self.text: str | None = data.get("text")
        self.ssl: int | None = data.get("ssl")
        self.tld: str | None = data.get("tld")
        self.domain: str | None = data.get("domain")
        self.fld: str | None = data.get("fld")
        self.subdomain: str | None = data.get("subdomain")
        self.screenshot_png_base64: str | None = data.get("screenshot_png_base64")
        self.tls: dict[str, Any] = data.get("tls") or {}
        self.timings_ms: dict[str, Any] = data.get("timings_ms") or {}


class CollectorClient:
    def __init__(self) -> None:
        self.base_url = settings.COLLECTOR_URL.rstrip("/")
        self.api_key = settings.COLLECTOR_API_KEY
        self.timeout = float(settings.COLLECTOR_TIMEOUT or 20.0)
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({"X-API-Key": self.api_key})

    def collect(self, url: str) -> CollectorResponse:
        if not self.base_url:
            raise CollectorError("COLLECTOR_NOT_CONFIGURED")
        try:
            resp = self._session.post(
                f"{self.base_url}/collect",
                json={"url": url},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise CollectorError("COLLECTOR_UNREACHABLE") from exc
        if resp.status_code != 200:
            raise CollectorError(
                f"COLLECTOR_HTTP_{resp.status_code}",
                status_code=resp.status_code,
            )
        try:
            data = self._bounded_json(resp)
        except (ValueError, KeyError, TypeError) as exc:
            raise CollectorError("COLLECTOR_BAD_SHAPE") from exc
        return CollectorResponse(data)

    def _bounded_json(self, resp: requests.Response) -> dict[str, Any]:
        total = 0
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise CollectorError("COLLECTOR_RESPONSE_TOO_LARGE")
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
