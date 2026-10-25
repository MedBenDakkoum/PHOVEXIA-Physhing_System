"""Shared fixtures for the inference service test suite.

Service tests talk to a RUNNING service (INFERENCE_URL) with the shared
secret INFERENCE_API_KEY. Unit tests (security, images, loader integrity,
fusion validation) import the app package directly and need no server.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

INFERENCE_URL = os.environ.get("INFERENCE_URL", "http://localhost:8000")
INFERENCE_API_KEY = os.environ.get("INFERENCE_API_KEY", "test-key")
ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
GOLDEN_DIR = ARTIFACTS_DIR / "golden"


@pytest.fixture(scope="session")
def api_key() -> str:
    return INFERENCE_API_KEY


@pytest.fixture(scope="session")
def service() -> object:
    import httpx

    client = httpx.Client(
        base_url=INFERENCE_URL.rstrip("/"),
        headers={"X-API-Key": INFERENCE_API_KEY},
        timeout=120.0,
    )
    response = client.get("/health")
    if response.status_code != 200:
        pytest.fail(
            f"inference service not ready at {INFERENCE_URL} "
            f"(/health -> {response.status_code})"
        )
    return client


@pytest.fixture(scope="session")
def golden_rows() -> list[dict]:
    csv_path = GOLDEN_DIR / "golden_samples.csv"
    if not csv_path.is_file():
        pytest.skip(
            f"golden fixtures absent: {csv_path}. Run the Kaggle export cell "
            "and place the bundle in ARTIFACTS_DIR to enable the golden test."
        )
    with open(csv_path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 20:
        pytest.fail(f"golden_samples.csv must contain 20 rows, got {len(rows)}")
    return rows


@pytest.fixture(scope="session")
def golden_png_bytes() -> dict[str, bytes]:
    if not GOLDEN_DIR.is_dir():
        pytest.skip(f"golden fixtures absent: {GOLDEN_DIR}")
    return {
        path.stem: path.read_bytes()
        for path in sorted(GOLDEN_DIR.glob("*.png"))
    }


def post_predict(client, *, url=None, text=None, ssl=None, tld="", subdomain="",
                 png_bytes=None):
    data = {}
    if url is not None:
        data["url"] = url
    if text is not None:
        data["text"] = text
    if ssl is not None:
        data["ssl"] = ssl
    data["tld"] = tld
    data["subdomain"] = subdomain
    files = None
    if png_bytes is not None:
        files = {"screenshot": ("shot.png", png_bytes, "image/png")}
    return client.post("/predict", data=data, files=files)
