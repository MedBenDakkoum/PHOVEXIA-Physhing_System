"""Golden-sample acceptance test (contract section 5, decision D8).

Compares the live service against golden_samples.csv produced by the Kaggle
export cell, absolute tolerance 1e-4. The tolerance is NOT loosened here.
On mismatch the failure message names the sample and the delta.
"""

from __future__ import annotations

import math

import pytest

from tests.conftest import GOLDEN_DIR, post_predict

TOLERANCE = 1e-4

BASE_FIELDS = [
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
    "fusion_mlp_phishing_probability",
]


def test_golden_fixtures_are_exactly_20(golden_rows):
    assert len(golden_rows) == 20
    labels = [row["label"] for row in golden_rows]
    assert labels.count("0") == 10
    assert labels.count("1") == 10


@pytest.mark.parametrize("row_index", range(20))
def test_golden_sample_matches_service(service, golden_rows, golden_png_bytes, row_index):
    row = golden_rows[row_index]
    sample_id = row["sample_index"]
    png_path = GOLDEN_DIR / f"{sample_id}.png"
    if not png_path.is_file():
        pytest.skip(f"golden screenshot absent: {png_path}")
    png_bytes = png_path.read_bytes()

    response = post_predict(
        service,
        url=row["URL"],
        text=row["html_text"],
        ssl=row["SSL"],
        tld=row["TLD"],
        subdomain=row["Subdomain"],
        png_bytes=png_bytes,
    )
    assert response.status_code == 200, f"sample {sample_id}: HTTP {response.status_code}"
    body = response.json()
    assert body["status"] == "complete", (
        f"sample {sample_id}: expected complete, got {body['status']} "
        f"reason={body.get('reason_code')}"
    )

    base = body["base_probabilities"]
    got = {
        "mobilenet_phishing_probability": base["mobilenet_phishing_probability"],
        "distilbert_phishing_probability": base["distilbert_phishing_probability"],
        "url_cnn_phishing_probability": base["url_cnn_phishing_probability"],
        "metadata_phishing_probability": base["metadata_phishing_probability"],
        "fusion_mlp_phishing_probability": body["phishing_probability"],
    }
    deltas = {}
    for field_name in BASE_FIELDS:
        expected = float(row[field_name])
        actual = got[field_name]
        assert actual is not None, f"sample {sample_id}: {field_name} is null"
        if not math.isclose(actual, expected, rel_tol=0.0, abs_tol=TOLERANCE):
            deltas[field_name] = (expected, actual, abs(actual - expected))
    if deltas:
        detail = "; ".join(
            f"{name}: expected {e:.8f} got {a:.8f} (delta {d:.2e})"
            for name, (e, a, d) in deltas.items()
        )
        pytest.fail(f"sample {sample_id} outside atol {TOLERANCE}: {detail}")

    expected_decision = int(row["fusion_decision_05"])
    expected_prediction = "phishing" if expected_decision == 1 else "legitimate"
    assert body["prediction"] == expected_prediction, (
        f"sample {sample_id}: decision mismatch"
    )
    assert body["model_bundle_version"] == row.get(
        "model_bundle_version", body["model_bundle_version"]
    )
