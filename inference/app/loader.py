"""Bundle verification and safe model loading (startup only).

Order is mandatory:
  1. SHA-256 of every file the service loads, against the trusted manifest;
  2. scikit-learn version against the manifest;
  3. joblib load of the preprocessor, dimension check (1272);
  4. torch.load(weights_only=True, map_location="cpu") for every checkpoint,
     load_state_dict(strict=True) — never weights_only=False;
  5. shape checks + one fusion smoke forward pass.
Any failure raises; the process must stop. There is no fallback path.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
import sklearn
import torch
from sklearn.compose import ColumnTransformer
from torchvision import models as tv_models
from torchvision import transforms as tv_transforms
from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

from app.arch import FusionMLP, MetadataMLP, URLCharCNN
from app.errors import BundleIntegrityError, BundleLoadError
from app.hashing import sha256_file

logger = logging.getLogger(__name__)

REQUIRED_FILES = (
    "best_mobilenetv2_phish360.pth",
    "best_distilbert_html.pth",
    "phish360_url_charcnn.pth",
    "phish360_url_charcnn_vocab.json",
    "phish360_metadata_mlp.pth",
    "metadata_preprocessor.joblib",
    "phish360_fusion_mlp.pth",
)

EXPECTED_METADATA_DIM = 1272
FUSION_INPUT_DIM = 4
# Same revision the Dockerfile downloads at build time (hf-fetch stage).
HF_DISTILBERT_REVISION = "12040accade4e8a0f71eabdb258fecc2e7e948be"

IMAGE_TRANSFORM = tv_transforms.Compose(
    [
        tv_transforms.Resize((224, 224)),
        tv_transforms.ToTensor(),
        tv_transforms.Normalize(
            mean=[0.485, 0.456, 0.406],
            std=[0.229, 0.224, 0.225],
        ),
    ]
)


@dataclass
class Bundle:
    image_model: torch.nn.Module
    html_model: torch.nn.Module
    tokenizer: object
    url_model: torch.nn.Module
    meta_model: torch.nn.Module
    fusion_model: torch.nn.Module
    preprocessor: ColumnTransformer
    vocab: dict
    max_len: int
    version: str
    checks: dict


def verify_bundle(artifacts_dir: Path) -> dict:
    """Refuse to continue unless every loaded file matches the manifest."""
    manifest_path = artifacts_dir / "manifest.json"
    if not manifest_path.is_file():
        raise BundleIntegrityError(f"manifest.json not found in {artifacts_dir}")
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)

    listed = manifest.get("files", {})
    problems: list[str] = []
    for name in REQUIRED_FILES:
        path = artifacts_dir / name
        if not path.is_file():
            problems.append(f"missing file: {name}")
            continue
        entry = listed.get(name)
        if entry is None:
            problems.append(f"not listed in manifest: {name}")
            continue
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            problems.append(
                f"sha256 mismatch: {name} expected {entry['sha256']} got {actual}"
            )
        elif path.stat().st_size != entry["size_bytes"]:
            problems.append(f"size mismatch: {name}")
    if problems:
        raise BundleIntegrityError("; ".join(problems))
    logger.info("bundle verified: %d files match manifest", len(REQUIRED_FILES))
    return manifest


def _safe_torch_load(path: Path) -> object:
    try:
        return torch.load(path, map_location="cpu", weights_only=True)
    except Exception as exc:
        raise BundleLoadError(
            f"unsafe or unreadable checkpoint {path.name}: {exc}. "
            "Refusing to fall back to weights_only=False."
        ) from exc


def load_bundle(artifacts_dir: Path, hf_local_dir: Path) -> Bundle:
    manifest = verify_bundle(artifacts_dir)

    expected_sklearn = manifest.get("versions", {}).get("scikit_learn")
    if sklearn.__version__ != expected_sklearn:
        raise BundleLoadError(
            f"scikit-learn version mismatch: running {sklearn.__version__}, "
            f"manifest expects {expected_sklearn}"
        )

    preprocessor = joblib.load(artifacts_dir / "metadata_preprocessor.joblib")
    probe = pd.DataFrame([{"TLD": "com", "Subdomain": "www", "SSL": 1}])
    dim = preprocessor.transform(probe).shape[1]
    if dim != EXPECTED_METADATA_DIM:
        raise BundleLoadError(
            f"metadata preprocessor output dim {dim} != {EXPECTED_METADATA_DIM}"
        )

    url_checkpoint = _safe_torch_load(artifacts_dir / "phish360_url_charcnn.pth")
    with open(artifacts_dir / "phish360_url_charcnn_vocab.json", encoding="utf-8") as fh:
        vocab = json.load(fh)
    if len(vocab) != url_checkpoint["vocab_size"]:
        raise BundleLoadError(
            f"vocab size {len(vocab)} != checkpoint vocab_size "
            f"{url_checkpoint['vocab_size']}"
        )
    if "<PAD>" not in vocab or "<UNK>" not in vocab:
        raise BundleLoadError("URL vocabulary is missing <PAD>/<UNK>")
    url_model = URLCharCNN(url_checkpoint["vocab_size"])
    url_model.load_state_dict(url_checkpoint["model_state_dict"], strict=True)
    url_model.eval()
    if url_model.embedding.num_embeddings != len(vocab):
        raise BundleLoadError("URL embedding size does not match vocabulary")

    meta_checkpoint = _safe_torch_load(artifacts_dir / "phish360_metadata_mlp.pth")
    if meta_checkpoint["input_dim"] != EXPECTED_METADATA_DIM:
        raise BundleLoadError(
            f"metadata checkpoint input_dim {meta_checkpoint['input_dim']} "
            f"!= {EXPECTED_METADATA_DIM}"
        )
    meta_model = MetadataMLP(meta_checkpoint["input_dim"])
    meta_model.load_state_dict(meta_checkpoint["model_state_dict"], strict=True)
    meta_model.eval()
    first_linear = meta_model.network[0]
    if first_linear.in_features != EXPECTED_METADATA_DIM:
        raise BundleLoadError("MetadataMLP first layer does not expect 1272 features")

    fusion_state = _safe_torch_load(artifacts_dir / "phish360_fusion_mlp.pth")
    fusion_model = FusionMLP()
    fusion_model.load_state_dict(fusion_state, strict=True)
    fusion_model.eval()
    fusion_first = fusion_model.network[0]
    if fusion_first.in_features != FUSION_INPUT_DIM:
        raise BundleLoadError("FusionMLP first layer does not expect 4 features")
    with torch.no_grad():
        smoke = torch.softmax(fusion_model(torch.zeros(1, FUSION_INPUT_DIM)), dim=1)
    if smoke.shape != (1, 2):
        raise BundleLoadError(f"fusion smoke forward returned {tuple(smoke.shape)}")

    image_model = tv_models.mobilenet_v2(weights=None)
    image_model.classifier[1] = torch.nn.Linear(
        image_model.classifier[1].in_features, 2
    )
    image_model.load_state_dict(
        _safe_torch_load(artifacts_dir / "best_mobilenetv2_phish360.pth"), strict=True
    )
    image_model.eval()
    if image_model.classifier[1].out_features != 2:
        raise BundleLoadError("MobileNetV2 classifier does not output 2 classes")

    tokenizer = AutoTokenizer.from_pretrained(
        str(hf_local_dir),
        local_files_only=True,
        revision=HF_DISTILBERT_REVISION,
    )
    config = AutoConfig.from_pretrained(
        str(hf_local_dir),
        local_files_only=True,
        revision=HF_DISTILBERT_REVISION,
    )
    html_model = AutoModelForSequenceClassification.from_config(config)
    html_model.load_state_dict(
        _safe_torch_load(artifacts_dir / "best_distilbert_html.pth"), strict=True
    )
    html_model.eval()
    if html_model.config.num_labels != 2:
        raise BundleLoadError("DistilBERT config does not declare 2 labels")

    version = manifest.get("bundle_version", "unknown")
    checks = {
        "bundle_files_sha256": True,
        "sklearn_version": sklearn.__version__,
        "metadata_dim": EXPECTED_METADATA_DIM,
        "models": [
            "mobilenet_v2",
            "distilbert_html",
            "url_charcnn",
            "metadata_mlp",
            "fusion_mlp",
        ],
    }
    logger.info("bundle %s loaded: all shape checks passed", version)
    return Bundle(
        image_model=image_model,
        html_model=html_model,
        tokenizer=tokenizer,
        url_model=url_model,
        meta_model=meta_model,
        fusion_model=fusion_model,
        preprocessor=preprocessor,
        vocab=vocab,
        max_len=url_checkpoint.get("max_len", 256),
        version=version,
        checks=checks,
    )
