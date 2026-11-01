"""Regression tests for the modality label mapping (US27 / ISO-6.1).

The inference service returns the fusion order (mobilenet, distilbert,
url_cnn, metadata). The API exposes screenshot, page_text, url, metadata.
Any positional zip silently swaps url and screenshot; these tests use four
distinct values so a swap can never pass.
"""
import pytest

from scans.services.inference_client import InferenceResponse


def payload(**overrides):
    base = {
        "status": "complete",
        "partial": False,
        "prediction": "phishing",
        "phishing_probability": 0.5,
        "model_bundle_version": "bundle-1",
        "base_probabilities": {
            "mobilenet_phishing_probability": 0.11,
            "distilbert_phishing_probability": 0.22,
            "url_cnn_phishing_probability": 0.33,
            "metadata_phishing_probability": 0.44,
        },
    }
    base.update(overrides)
    return base


def test_base_probabilities_are_mapped_by_name_not_by_position():
    response = InferenceResponse(payload())

    assert response.base_probabilities == {
        "screenshot": pytest.approx(0.11),
        "page_text": pytest.approx(0.22),
        "url": pytest.approx(0.33),
        "metadata": pytest.approx(0.44),
    }


def test_missing_raw_branch_yields_none_for_its_friendly_key():
    body = payload()
    body["base_probabilities"] = {
        "mobilenet_phishing_probability": 0.11,
        "distilbert_phishing_probability": None,
        "metadata_phishing_probability": 0.44,
    }

    response = InferenceResponse(body)

    assert response.base_probabilities["screenshot"] == pytest.approx(0.11)
    assert response.base_probabilities["page_text"] is None
    assert response.base_probabilities["url"] is None
    assert response.base_probabilities["metadata"] == pytest.approx(0.44)
