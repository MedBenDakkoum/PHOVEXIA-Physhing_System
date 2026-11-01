"""Internal client to the CPU inference service (US20 / US26 / contract §3).

POST /predict multipart: url, text, ssl, tld, subdomain + screenshot file.
Returns a validated shape: the 4 base probabilities + the fusion probability.
Every infrastructure/protocol failure is mapped to ONE stable code,
INFERENCE_UNAVAILABLE, with a technical `detail` for error_message; the Celery
task retries with a countdown (never a sleep inside the worker) and only ends
the scan FAILED once its attempts are exhausted.

Never log request bodies or the shared API key.
"""
from __future__ import annotations

import json
from typing import Any

import requests
from django.conf import settings

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = 6 * 1024 * 1024  # the collector already caps screenshots at 5 MB

# Inference contract §2.E raw model keys -> API-friendly modality names.
# The mapping is BY NAME (never by position): the inference service returns the
# fusion order mobilenet, distilbert, url_cnn, metadata, while the API exposes
# screenshot, page_text, url, metadata.
_BASE_KEY_TO_FRIENDLY = {
    "mobilenet_phishing_probability": "screenshot",
    "distilbert_phishing_probability": "page_text",
    "url_cnn_phishing_probability": "url",
    "metadata_phishing_probability": "metadata",
}


class InferenceError(Exception):
    """Infrastructure or protocol failure talking to the inference service.

    `reason` is the stable INFERENCE_UNAVAILABLE code (or
    INFERENCE_NOT_CONFIGURED). `detail` keeps the technical context for
    error_message (never a URL, a body or a secret).
    """

    def __init__(
        self,
        reason: str,
        status_code: int | None = None,
        *,
        retryable: bool = False,
        detail: str = "",
    ):
        self.reason = reason
        self.status_code = status_code
        self.retryable = retryable
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class InferenceResponse:
    """Validated shape of the inference /predict JSON (contract section 3)."""

    def __init__(self, data: dict[str, Any]):
        if data.get("status") not in ("complete", "uncertain"):
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                retryable=True,
                detail="invalid predict payload (status)",
            )
        base = data.get("base_probabilities") or {}
        if not isinstance(base, dict):
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                retryable=True,
                detail="invalid predict payload (base_probabilities)",
            )
        self.status: str = data["status"]
        self.partial: bool = bool(data.get("partial", False))
        self.prediction: str | None = data.get("prediction")
        self.phishing_probability: float | None = data.get("phishing_probability")
        self.base_probabilities: dict[str, float | None] = {
            friendly: base.get(raw_key)
            for raw_key, friendly in _BASE_KEY_TO_FRIENDLY.items()
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
            raise InferenceError(
                "INFERENCE_NOT_CONFIGURED",
                detail="INFERENCE_URL is empty",
            )
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
                raise InferenceError(
                    "INFERENCE_UNAVAILABLE",
                    retryable=True,
                    detail="screenshot too large",
                )
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
        except requests.exceptions.Timeout as exc:
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                retryable=True,
                detail=f"timeout after {self.timeout:g}s",
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                retryable=True,
                detail=type(exc).__name__,
            ) from exc
        if resp.status_code != 200:
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                status_code=resp.status_code,
                retryable=resp.status_code >= 500 or resp.status_code == 429,
                detail=f"HTTP {resp.status_code}",
            )
        try:
            data = self._bounded_json(resp)
        except (ValueError, KeyError, TypeError) as exc:
            raise InferenceError(
                "INFERENCE_UNAVAILABLE",
                retryable=True,
                detail="invalid JSON",
            ) from exc
        return InferenceResponse(data)

    def _bounded_json(self, resp: requests.Response) -> dict[str, Any]:
        total = 0
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise InferenceError(
                    "INFERENCE_UNAVAILABLE",
                    retryable=True,
                    detail="response too large",
                )
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
