"""Internal client to the CPU inference service (US20 / US26 / contract §3).

POST /predict multipart: url, text, ssl, tld, subdomain + screenshot file.
Returns a validated shape: the 4 base probabilities + the fusion probability.
Any failure is an infrastructure failure retried by the Celery task.

Never log request bodies or the shared API key.
"""
from __future__ import annotations

import json
from typing import Any

import requests
from django.conf import settings

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = 6 * 1024 * 1024  # the collector already caps screenshots at 5 MB

# Inference contract §2.E input order, exposed to the API under friendly names.
_BASE_KEYS = (
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
)

_FRIENDLY_KEYS = ("url", "page_text", "screenshot", "metadata")


class InferenceError(Exception):
    """Infrastructure or protocol failure talking to the inference service.

    `reason` is a short, safe code (no stack trace, no secret) stored on the
    scan as error_message / reason_code.
    """

    def __init__(self, reason: str, status_code: int | None = None):
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


class InferenceResponse:
    """Validated shape of the inference /predict JSON (contract section 3)."""

    def __init__(self, data: dict[str, Any]):
        if data.get("status") not in ("complete", "uncertain"):
            raise InferenceError("INFERENCE_BAD_SHAPE")
        base = data.get("base_probabilities") or {}
        if not isinstance(base, dict):
            raise InferenceError("INFERENCE_BAD_SHAPE")
        self.status: str = data["status"]
        self.partial: bool = bool(data.get("partial", False))
        self.prediction: str | None = data.get("prediction")
        self.phishing_probability: float | None = data.get("phishing_probability")
        self.base_probabilities: dict[str, float | None] = {
            friendly: base.get(key) for friendly, key in zip(_FRIENDLY_KEYS, _BASE_KEYS)
        }
        self.model_bundle_version: str = data.get("model_bundle_version") or ""
        self.reason_code: str | None = data.get("reason_code")
        self.available_signals: list[str] = data.get("available_signals") or []
        self.unavailable_signals: list[str] = data.get("unavailable_signals") or []


class InferenceClient:
    def __init__(self) -> None:
        self.base_url = settings.INFERENCE_URL.rstrip("/")
        self.api_key = settings.INFERENCE_API_KEY
        self.timeout = float(settings.INFERENCE_TIMEOUT or 30.0)
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({"X-API-Key": self.api_key})

    def predict(
        self,
        url: str,
        text: str,
        screenshot_png: bytes | None,
        ssl: int | None,
        tld: str | None,
        subdomain: str | None,
    ) -> InferenceResponse:
        if not self.base_url:
            raise InferenceError("INFERENCE_NOT_CONFIGURED")
        fields: dict[str, Any] = {
            "url": (None, url),
            "text": (None, text or ""),
            "ssl": (None, "" if ssl is None else str(int(ssl))),
            "tld": (None, tld or ""),
            "subdomain": (None, subdomain or ""),
        }
        files: dict[str, Any] | None = None
        if screenshot_png is not None:
            if len(screenshot_png) > MAX_UPLOAD_BYTES:
                raise InferenceError("INFERENCE_SCREENSHOT_TOO_LARGE")
            files = {
                "screenshot": ("screenshot.png", screenshot_png, "image/png")
            }
        try:
            resp = self._session.post(
                f"{self.base_url}/predict",
                data=fields,
                files=files,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise InferenceError("INFERENCE_UNREACHABLE") from exc
        if resp.status_code != 200:
            raise InferenceError(
                f"INFERENCE_HTTP_{resp.status_code}",
                status_code=resp.status_code,
            )
        try:
            data = self._bounded_json(resp)
        except (ValueError, KeyError, TypeError) as exc:
            raise InferenceError("INFERENCE_BAD_SHAPE") from exc
        return InferenceResponse(data)

    def _bounded_json(self, resp: requests.Response) -> dict[str, Any]:
        total = 0
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise InferenceError("INFERENCE_RESPONSE_TOO_LARGE")
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
