"""API-key enforcement and constant-time comparison (US26 auth, ISO 6.8)."""

from __future__ import annotations

import httpx
from app.security import is_valid_api_key

from tests.conftest import INFERENCE_URL, post_predict


def test_constant_time_compare_accepts_exact_key():
    assert is_valid_api_key("secret", "secret")


def test_constant_time_compare_rejects_wrong_key():
    assert not is_valid_api_key("wrong", "secret")


def test_predict_without_key_is_401():
    client = httpx.Client(base_url=INFERENCE_URL.rstrip("/"), timeout=30.0)
    response = client.post("/predict", data={"url": "https://example.com"})
    assert response.status_code == 401
    assert response.json()["detail"] == "unauthorized"


def test_predict_with_wrong_key_is_401(service):
    response = service.post(
        "/predict",
        data={"url": "https://example.com"},
        headers={"X-API-Key": "not-the-key"},
    )
    assert response.status_code == 401


def test_predict_with_key_reaches_business_layer(service, golden_png_bytes):
    png = next(iter(golden_png_bytes.values()))
    response = post_predict(
        service,
        url="https://example.com",
        text="login page",
        ssl="true",
        tld="com",
        subdomain="www",
        png_bytes=png,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"complete", "uncertain"}
