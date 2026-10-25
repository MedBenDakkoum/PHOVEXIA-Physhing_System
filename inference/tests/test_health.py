"""GET /health readiness contract (contract section 3)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import ARTIFACTS_DIR


def test_health_reports_ready_and_bundle_version(service):
    response = service.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["bundle_files_sha256"] is True
    assert body["checks"]["metadata_dim"] == 1272

    manifest_path = ARTIFACTS_DIR / "manifest.json"
    if Path(manifest_path).is_file():
        with open(manifest_path, encoding="utf-8") as handle:
            expected = json.load(handle)["bundle_version"]
        assert body["model_bundle_version"] == expected
