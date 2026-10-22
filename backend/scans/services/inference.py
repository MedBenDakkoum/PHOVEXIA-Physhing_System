"""MOCK inference service - placeholder until the real ONNX multimodal model.

CLEARLY A MOCK: no model is loaded, nothing is downloaded, no ONNX Runtime
call happens. The score is a deterministic function of the URL alone
(SHA-256 of the lowercased URL mapped to [0, 1]), so the same URL always
gives the same verdict and every test is reproducible.

Verdict rule (config/settings.py):
    score >= DETECTION_PHISHING_THRESHOLD (0.70) -> phishing
    score <= DETECTION_UNCERTAIN_LOWER (0.40)    -> legitimate
    otherwise                                    -> uncertain (analyst queue)

Real signature in Sprint 5 (US20/US25/US26, see docs/HANDOFF.md):
    predict(url, html, screenshot, signals) -> PredictionResult
This mock keeps the same return type so the Celery task and the future
endpoint do not change.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from django.core.exceptions import ImproperlyConfigured

from controlpanel.services import get_detection_settings

VERDICT_PHISHING = "phishing"
VERDICT_LEGITIMATE = "legitimate"
VERDICT_UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class PredictionResult:
    """Verdict + confidence score + model version (stored on the scan)."""

    verdict: str
    score: float
    model_version: str = "mock-0"


def _thresholds() -> tuple[float, float]:
    """Return (lower, upper) thresholds, validated.

    Step 12 (US52): the values come from the DetectionSettings singleton
    (30 s cache) and fall back to settings/env while the table is empty.

    Raises ImproperlyConfigured if a threshold is not a float in [0, 1]
    or if lower >= upper (an empty/invalid uncertain band would make the
    verdict ambiguous).
    """
    snapshot = get_detection_settings()
    try:
        lower = float(snapshot.uncertain_lower)
        upper = float(snapshot.phishing_threshold)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(
            f"Detection thresholds must be numbers: {exc}"
        ) from exc
    if not (0.0 <= lower <= 1.0) or not (0.0 <= upper <= 1.0):
        raise ImproperlyConfigured(
            "Detection thresholds must be in [0, 1]: "
            f"DETECTION_UNCERTAIN_LOWER={lower!r}, "
            f"DETECTION_PHISHING_THRESHOLD={upper!r}."
        )
    if lower >= upper:
        raise ImproperlyConfigured(
            "DETECTION_UNCERTAIN_LOWER must be < DETECTION_PHISHING_THRESHOLD: "
            f"{lower!r} >= {upper!r}."
        )
    return lower, upper


def _score_from_url(url: str) -> float:
    """Deterministic MOCK score in [0, 1] from the SHA-256 of the URL."""
    digest = hashlib.sha256(url.lower().encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], "big")
    return value / float(2**64 - 1)


def classify_score(score: float, lower: float, upper: float) -> str:
    """Map a score to a verdict using the validated thresholds."""
    if score >= upper:
        return VERDICT_PHISHING
    if score <= lower:
        return VERDICT_LEGITIMATE
    return VERDICT_UNCERTAIN


def predict(url: str, mode: str) -> PredictionResult:
    """MOCK prediction: verdict + score derived from the URL only.

    `mode` (fast/full) is accepted for signature compatibility with the
    real model but unused by the mock.
    """
    lower, upper = _thresholds()
    score = _score_from_url(url)
    verdict = classify_score(score, lower, upper)
    return PredictionResult(verdict=verdict, score=score)
