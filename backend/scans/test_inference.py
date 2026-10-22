"""
MOCK inference tests for scans/services/inference.py (Step 6).

Covers: determinism of the SHA-256 mock score, verdict thresholds
(DETECTION_PHISHING_THRESHOLD=0.70 / DETECTION_UNCERTAIN_LOWER=0.40,
boundary values included) and threshold validation (ImproperlyConfigured).
Requirement tags: US15, US27, US32, ISO-6.1.
"""
import logging

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings import _float_env
from scans.services.inference import (
    VERDICT_LEGITIMATE,
    VERDICT_PHISHING,
    VERDICT_UNCERTAIN,
    _score_from_url,
    classify_score,
    predict,
)

URL = "https://example.com/login?ref=1"

# Step 12 (US52): predict() reads the DetectionSettings singleton, so every
# test of this module needs DB access (the table stays empty: env fallback).
pytestmark = pytest.mark.django_db


# --- determinism -------------------------------------------------------------


def test_same_url_gives_same_result():
    assert predict(URL, "fast") == predict(URL, "fast")


def test_result_is_case_insensitive_on_url():
    assert predict("HTTPS://Example.COM/Login?Ref=1", "full") == predict(
        "https://example.com/login?ref=1", "fast"
    )


def test_score_is_in_unit_interval_for_many_urls():
    for i in range(50):
        result = predict(f"https://site{i}.example/path#{i}", "fast")
        assert 0.0 <= result.score <= 1.0
        assert result.verdict in (
            VERDICT_PHISHING,
            VERDICT_LEGITIMATE,
            VERDICT_UNCERTAIN,
        )


def test_model_version_is_the_mock_one():
    assert predict(URL, "fast").model_version == "mock-0"


def test_score_is_reproducible_across_calls():
    scores = {predict(URL, "fast").score for _ in range(5)}
    assert scores == {_score_from_url(URL)}


# --- threshold boundaries (lower = 0.40, upper = 0.70) -----------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, VERDICT_LEGITIMATE),
        (0.40, VERDICT_LEGITIMATE),
        (0.4000001, VERDICT_UNCERTAIN),
        (0.5, VERDICT_UNCERTAIN),
        (0.6999999, VERDICT_UNCERTAIN),
        (0.70, VERDICT_PHISHING),
        (1.0, VERDICT_PHISHING),
    ],
)
def test_classify_score_boundaries(score, expected):
    assert classify_score(score, 0.40, 0.70) == expected


def test_classify_score_uses_custom_thresholds():
    assert classify_score(0.30, 0.20, 0.30) == VERDICT_PHISHING
    assert classify_score(0.25, 0.20, 0.30) == VERDICT_UNCERTAIN
    assert classify_score(0.20, 0.20, 0.30) == VERDICT_LEGITIMATE


# --- thresholds read from settings ------------------------------------------


def test_predict_honours_overridden_thresholds(settings):
    base = predict(URL, "fast")
    assert 0.0 < base.score < 1.0

    settings.DETECTION_UNCERTAIN_LOWER = base.score
    settings.DETECTION_PHISHING_THRESHOLD = 1.0
    assert predict(URL, "fast").verdict == VERDICT_LEGITIMATE

    settings.DETECTION_UNCERTAIN_LOWER = 0.0
    settings.DETECTION_PHISHING_THRESHOLD = base.score
    assert predict(URL, "fast").verdict == VERDICT_PHISHING


@pytest.mark.parametrize(
    ("lower", "upper"),
    [
        (0.70, 0.40),
        (0.50, 0.50),
        (1.5, 0.90),
        (-0.2, 0.90),
        (0.10, 1.2),
        ("abc", 0.90),
        (0.10, None),
    ],
)
def test_invalid_threshold_settings_raise(settings, lower, upper):
    settings.DETECTION_UNCERTAIN_LOWER = lower
    settings.DETECTION_PHISHING_THRESHOLD = upper
    with pytest.raises(ImproperlyConfigured):
        predict(URL, "fast")


# --- env parsing (_float_env) ------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0.55", 0.55),
        ("0", 0.0),
        ("-1", -1.0),
        (" 0.42 ", 0.42),
    ],
)
def test_float_env_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("DETECTION_PHISHING_THRESHOLD", raw)
    assert _float_env("DETECTION_PHISHING_THRESHOLD", 0.70) == expected


def test_float_env_unset_falls_back_silently(monkeypatch):
    monkeypatch.delenv("DETECTION_PHISHING_THRESHOLD", raising=False)
    assert _float_env("DETECTION_PHISHING_THRESHOLD", 0.70) == 0.70


def test_float_env_invalid_logs_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("DETECTION_PHISHING_THRESHOLD", "high")
    with caplog.at_level(logging.WARNING, logger="config.settings"):
        assert _float_env("DETECTION_PHISHING_THRESHOLD", 0.70) == 0.70
    assert "DETECTION_PHISHING_THRESHOLD" in caplog.text
    assert "falling back to 0.7" in caplog.text
