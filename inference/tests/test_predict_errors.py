"""POST /predict business rules for missing/invalid inputs (contract section 3)."""

from __future__ import annotations

from tests.conftest import post_predict


def _valid_fields(png_bytes):
    return {
        "url": "https://legit.example.com/login",
        "text": "Please sign in to your account dashboard",
        "ssl": "true",
        "tld": "com",
        "subdomain": "legit",
        "png_bytes": png_bytes,
    }


def test_missing_screenshot_returns_uncertain(service, golden_png_bytes):
    response = post_predict(
        service,
        url="https://example.com",
        text="hello",
        ssl="true",
        tld="com",
        subdomain="www",
        png_bytes=None,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "uncertain"
    assert body["partial"] is True
    assert body["prediction"] == "uncertain"
    assert body["reason_code"] == "MISSING_SCREENSHOT"
    assert body["phishing_probability"] is None
    assert "screenshot" in body["unavailable_signals"]
    assert "url" in body["available_signals"]


def test_empty_url_returns_uncertain(service, golden_png_bytes):
    png = next(iter(golden_png_bytes.values()))
    fields = _valid_fields(png)
    fields["url"] = "   "
    response = post_predict(service, **fields)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "uncertain"
    assert body["reason_code"] == "EMPTY_URL"
    assert body["phishing_probability"] is None


def test_corrupted_image_returns_invalid_screenshot(service, golden_png_bytes):
    fields = _valid_fields(next(iter(golden_png_bytes.values())))
    fields["png_bytes"] = b"\x89PNG\r\n\x1a\nGARBAGE-NOT-A-PNG"
    response = post_predict(service, **fields)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "uncertain"
    assert body["reason_code"] == "INVALID_SCREENSHOT"


def test_oversized_image_rejected_before_decode(service, golden_png_bytes):
    fields = _valid_fields(next(iter(golden_png_bytes.values())))
    fields["png_bytes"] = b"\x00" * (5 * 1024 * 1024 + 1)
    response = post_predict(service, **fields)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "uncertain"
    assert body["reason_code"] == "IMAGE_TOO_LARGE"


def test_unknown_tld_and_subdomain_still_complete(service, golden_png_bytes):
    """OneHotEncoder(handle_unknown='ignore'): unknown categories must not fail."""
    png = next(iter(golden_png_bytes.values()))
    fields = _valid_fields(png)
    fields["tld"] = "zz-not-a-real-tld"
    fields["subdomain"] = "totally-unknown-subdomain-xyz"
    response = post_predict(service, **fields)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete", body
    assert body["partial"] is False
    assert body["prediction"] in {"phishing", "legitimate"}
    base = body["base_probabilities"]
    for key in (
        "mobilenet_phishing_probability",
        "distilbert_phishing_probability",
        "url_cnn_phishing_probability",
        "metadata_phishing_probability",
    ):
        value = base[key]
        assert value is not None and 0.0 <= value <= 1.0
    assert body["model_bundle_version"]
