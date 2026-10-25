"""Response schemas for the inference API (contract section 3)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class BaseProbabilities(BaseModel):
    mobilenet_phishing_probability: float | None = None
    distilbert_phishing_probability: float | None = None
    url_cnn_phishing_probability: float | None = None
    metadata_phishing_probability: float | None = None


class PredictResponse(BaseModel):
    status: Literal["complete", "uncertain"]
    partial: bool
    prediction: Literal["phishing", "legitimate", "uncertain"]
    model_bundle_version: str
    phishing_probability: float | None = None
    base_probabilities: BaseProbabilities | None = None
    reason_code: str | None = None
    available_signals: list[str] = []
    unavailable_signals: list[str] = []


class HealthResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    model_bundle_version: str | None = None
    checks: dict | None = None
