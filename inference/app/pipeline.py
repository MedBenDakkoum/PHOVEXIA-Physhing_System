"""Synchronous inference pipeline (runs in a worker thread).

Every preprocessing step mirrors the Kaggle notebook (sections 50/54) and
docs/data_contract.md section 2. Fusion is called ONLY with four finite
values in [0, 1], in the exact manifest feature order.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import torch
from PIL import Image

from app.errors import FusionInputError
from app.loader import IMAGE_TRANSFORM, Bundle

logger = logging.getLogger(__name__)

FUSION_FEATURE_ORDER = [
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
]


@dataclass
class PipelineResult:
    base_probabilities: dict = field(default_factory=dict)
    fusion_probability: float | None = None
    prediction: str | None = None
    failed_signal: str | None = None
    error: str | None = None


def encode_url(url: str, vocab: dict, max_len: int) -> list[int]:
    """Exact Char-CNN encoding from notebook section 50."""
    url = str(url).strip().lower()
    if len(url) > max_len:
        url = url[: max_len - 64] + url[-64:]
    ids = [vocab.get(ch, vocab["<UNK>"]) for ch in url][:max_len]
    return ids + [vocab["<PAD>"]] * (max_len - len(ids))


def validate_fusion_input(probabilities: list[float]) -> None:
    """Fusion contract: exactly 4 finite values in [0, 1] (section 2E)."""
    if len(probabilities) != 4:
        raise FusionInputError(
            f"fusion expects 4 probabilities, got {len(probabilities)}"
        )
    for name, value in zip(FUSION_FEATURE_ORDER, probabilities, strict=True):
        if value is None or not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise FusionInputError(f"invalid fusion input {name}={value!r}")


def _image_probability(bundle: Bundle, image: Image.Image) -> float:
    tensor = IMAGE_TRANSFORM(image).unsqueeze(0)
    with torch.no_grad():
        logits = bundle.image_model(tensor)
    return float(torch.softmax(logits, dim=1)[0, 1].item())


def _html_probability(bundle: Bundle, text: str) -> float:
    encoded = bundle.tokenizer(
        text,
        max_length=256,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    )
    with torch.no_grad():
        logits = bundle.html_model(**encoded).logits
    return float(torch.softmax(logits, dim=1)[0, 1].item())


def _url_probability(bundle: Bundle, url: str) -> float:
    ids = encode_url(url, bundle.vocab, bundle.max_len)
    tensor = torch.tensor(np.array([ids]), dtype=torch.long)
    with torch.no_grad():
        logits = bundle.url_model(tensor)
    return float(torch.softmax(logits, dim=1)[0, 1].item())


def _metadata_probability(
    bundle: Bundle, ssl: int, tld: str, subdomain: str
) -> float:
    frame = pd.DataFrame(
        [
            {
                "TLD": tld if tld else "UNKNOWN",
                "Subdomain": subdomain if subdomain else "UNKNOWN",
                "SSL": int(ssl),
            }
        ]
    )
    encoded = bundle.preprocessor.transform(frame)
    if hasattr(encoded, "toarray"):
        encoded = encoded.toarray()
    tensor = torch.tensor(np.asarray(encoded), dtype=torch.float32)
    with torch.no_grad():
        logits = bundle.meta_model(tensor)
    return float(torch.softmax(logits, dim=1)[0, 1].item())


def _fusion_probability(bundle: Bundle, base: dict) -> float:
    vector = [float(base[name]) for name in FUSION_FEATURE_ORDER]
    validate_fusion_input(vector)
    tensor = torch.tensor([vector], dtype=torch.float32)
    with torch.no_grad():
        probs = torch.softmax(bundle.fusion_model(tensor), dim=1)
    value = float(probs[0, 1].item())
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise FusionInputError(f"fusion output out of range: {value!r}")
    return value


def run_pipeline(
    bundle: Bundle,
    *,
    url: str,
    text: str,
    ssl: int,
    tld: str,
    subdomain: str,
    image: Image.Image,
) -> PipelineResult:
    """Run the four base models then fusion; never raises on model errors."""
    result = PipelineResult()
    steps = (
        ("screenshot", lambda: _image_probability(bundle, image)),
        ("html_text", lambda: _html_probability(bundle, text.strip())),
        ("url", lambda: _url_probability(bundle, url)),
        (
            "metadata",
            lambda: _metadata_probability(bundle, ssl, tld, subdomain),
        ),
    )
    key_by_signal = {
        "screenshot": "mobilenet_phishing_probability",
        "html_text": "distilbert_phishing_probability",
        "url": "url_cnn_phishing_probability",
        "metadata": "metadata_phishing_probability",
    }
    for signal, step in steps:
        try:
            result.base_probabilities[key_by_signal[signal]] = step()
        except Exception as exc:
            logger.exception("model failed on signal %s", signal)
            result.failed_signal = signal
            result.error = str(type(exc).__name__)
            return result

    try:
        result.fusion_probability = _fusion_probability(
            bundle, result.base_probabilities
        )
    except Exception as exc:
        logger.exception("fusion failed")
        result.failed_signal = "fusion"
        result.error = str(type(exc).__name__)
        return result

    result.prediction = (
        "phishing" if result.fusion_probability >= 0.5 else "legitimate"
    )
    return result
