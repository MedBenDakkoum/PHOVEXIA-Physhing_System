"""Bundle integrity and fusion-input validation (contract sections 4 and 2E)."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest
from app.errors import BundleIntegrityError, FusionInputError
from app.loader import REQUIRED_FILES, verify_bundle
from app.pipeline import validate_fusion_input


def _write_fake_bundle(tmp_path: Path, *, tamper: str | None = None) -> Path:
    files = {}
    for name in REQUIRED_FILES:
        content = f"content-of-{name}".encode()
        (tmp_path / name).write_bytes(content)
        files[name] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    if tamper:
        (tmp_path / tamper).write_bytes(b"tampered-bytes")
    manifest = {"bundle_version": "test", "files": files}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_verify_bundle_accepts_untampered_bundle(tmp_path):
    bundle_dir = _write_fake_bundle(tmp_path)
    manifest = verify_bundle(bundle_dir)
    assert manifest["bundle_version"] == "test"


def test_verify_bundle_refuses_wrong_hash(tmp_path):
    bundle_dir = _write_fake_bundle(tmp_path, tamper="phish360_fusion_mlp.pth")
    with pytest.raises(BundleIntegrityError) as excinfo:
        verify_bundle(bundle_dir)
    assert "sha256 mismatch" in str(excinfo.value)
    assert "phish360_fusion_mlp.pth" in str(excinfo.value)


def test_verify_bundle_refuses_missing_file(tmp_path):
    bundle_dir = _write_fake_bundle(tmp_path)
    (bundle_dir / "best_distilbert_html.pth").unlink()
    with pytest.raises(BundleIntegrityError) as excinfo:
        verify_bundle(bundle_dir)
    assert "missing file" in str(excinfo.value)


def test_fusion_input_rejects_out_of_range():
    with pytest.raises(FusionInputError):
        validate_fusion_input([1.2, 0.5, 0.5, 0.5])


def test_fusion_input_rejects_nan():
    with pytest.raises(FusionInputError):
        validate_fusion_input([math.nan, 0.5, 0.5, 0.5])


def test_fusion_input_rejects_wrong_length():
    with pytest.raises(FusionInputError):
        validate_fusion_input([0.5, 0.5])


def test_fusion_input_accepts_valid_vector():
    validate_fusion_input([0.0, 0.25, 0.75, 1.0])
