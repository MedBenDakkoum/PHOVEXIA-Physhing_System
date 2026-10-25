# =============================================================================
# EXPORT INTEGRATION BUNDLE  (append this as the LAST cell of the Kaggle
# notebook docs/phish360-deeplearning-training.ipynb, then Run All below it)
#
# Purpose: build /kaggle/working/bundle/ = contract section 4 + fitted encoder
#          + manifest.json + 20 golden samples + rules sample + audits + zip.
#
# Requires (already defined by the notebook, asserted below):
#   df, device, checkpoint_dir, image_transform, preprocessor, tokenizer,
#   encode_url, URLCharCNN, MetadataMLP, FusionMLP, features, fusion_test
# =============================================================================

import hashlib
import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import torch
import torchvision
import transformers
from IPython.display import display
from PIL import Image
from sklearn.compose import ColumnTransformer
from sklearn.metrics import confusion_matrix
from torch import nn
from torchvision import models
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# -----------------------------------------------------------------------------
# 0. Guard the notebook state, then bind every required global
# -----------------------------------------------------------------------------
_REQUIRED = [
    "df", "device", "checkpoint_dir", "image_transform",
    "preprocessor", "tokenizer", "encode_url",
    "URLCharCNN", "MetadataMLP", "FusionMLP",
    "features", "fusion_test",
]
_ns = globals()
missing = [name for name in _REQUIRED if name not in _ns]
assert not missing, (
    "Run every training/inference section first; missing globals: "
    + ", ".join(missing)
)

df = _ns["df"]
device = _ns["device"]
checkpoint_dir = _ns["checkpoint_dir"]
image_transform = _ns["image_transform"]
preprocessor = _ns["preprocessor"]
tokenizer = _ns["tokenizer"]
encode_url = _ns["encode_url"]
URLCharCNN = _ns["URLCharCNN"]
MetadataMLP = _ns["MetadataMLP"]
FusionMLP = _ns["FusionMLP"]
features = _ns["features"]
fusion_test = _ns["fusion_test"]

BUNDLE_VERSION = datetime.now(timezone.utc).strftime("%Y-%m-%d")
bundle_dir = Path("/kaggle/working/bundle")
golden_dir = bundle_dir / "golden"

if bundle_dir.exists():
    shutil.rmtree(bundle_dir)
bundle_dir.mkdir(parents=True)
golden_dir.mkdir()

FUSION_FEATURES = [
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
]
assert list(features) == FUSION_FEATURES, (
    f"Fusion feature order changed: {list(features)}"
)

CATEGORICAL_COLS = ["TLD", "Subdomain"]
NUMERIC_COLS = ["SSL"]
EXPECTED_METADATA_DIM = 1272

print("Bundle directory:", bundle_dir)

# -----------------------------------------------------------------------------
# 1. Export the fitted metadata encoder
# -----------------------------------------------------------------------------
assert isinstance(preprocessor, ColumnTransformer), "preprocessor unexpected."
preprocessor_file = bundle_dir / "metadata_preprocessor.joblib"
joblib.dump(preprocessor, preprocessor_file)

_probe = df.loc[df["model_split"] == "test", CATEGORICAL_COLS + NUMERIC_COLS]
_probe = _probe.copy()
for col in CATEGORICAL_COLS:
    _probe[col] = _probe[col].fillna("UNKNOWN").astype(str)
_probe["SSL"] = (
    pd.to_numeric(_probe["SSL"], errors="coerce").fillna(0).astype(int)
)
_encoded_dim = preprocessor.transform(_probe).shape[1]

meta_ckpt_probe = torch.load(
    checkpoint_dir / "phish360_metadata_mlp.pth",
    map_location=device,
    weights_only=False,
)
assert _encoded_dim == meta_ckpt_probe["input_dim"] == EXPECTED_METADATA_DIM, (
    f"Encoded dim = {_encoded_dim}, checkpoint = "
    f"{meta_ckpt_probe['input_dim']}, contract = {EXPECTED_METADATA_DIM}"
)
print(f"Preprocessor exported: {preprocessor_file.name} "
      f"(dim {_encoded_dim} == {EXPECTED_METADATA_DIM} OK)")

# -----------------------------------------------------------------------------
# 2. Copy the five checkpoints + URL vocabulary into the bundle
# -----------------------------------------------------------------------------
CHECKPOINT_FILES = [
    checkpoint_dir / "best_mobilenetv2_phish360.pth",
    checkpoint_dir / "best_distilbert_html.pth",
    checkpoint_dir / "phish360_url_charcnn.pth",
    checkpoint_dir / "phish360_url_charcnn_vocab.json",
    checkpoint_dir / "phish360_metadata_mlp.pth",
    Path("/kaggle/working/phish360_fusion_mlp.pth"),
]
for src in CHECKPOINT_FILES:
    assert src.is_file(), (
        f"Missing {src}. Expected the four base checkpoints + vocab in "
        f"'{checkpoint_dir}' and the fusion checkpoint in /kaggle/working "
        "(notebook sections 50 and 54 must have run)."
    )
    shutil.copy2(src, bundle_dir / src.name)

# Re-derive URL encoding state from the exported artifacts (same files the
# notebook uses in section 50, so encode_url stays identical).
url_checkpoint = torch.load(
    bundle_dir / "phish360_url_charcnn.pth",
    map_location=device,
    weights_only=False,
)
with open(bundle_dir / "phish360_url_charcnn_vocab.json") as f:
    vocab = json.load(f)
MAX_LEN = url_checkpoint.get("max_len", 256)
PAD, UNK = "<PAD>", "<UNK>"
assert PAD in vocab and UNK in vocab, "URL vocabulary is missing PAD/UNK."

# -----------------------------------------------------------------------------
# 3. Load every model from the BUNDLE (proves the files load standalone)
# -----------------------------------------------------------------------------
image_model = models.mobilenet_v2(weights=None)
image_model.classifier[1] = nn.Linear(
    image_model.classifier[1].in_features, 2
)
image_model.load_state_dict(torch.load(
    bundle_dir / "best_mobilenetv2_phish360.pth",
    map_location=device,
    weights_only=True,
))
image_model.to(device).eval()

tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
html_model = AutoModelForSequenceClassification.from_pretrained(
    "distilbert-base-uncased", num_labels=2
)
html_model.load_state_dict(torch.load(
    bundle_dir / "best_distilbert_html.pth",
    map_location=device,
    weights_only=True,
))
html_model.to(device).eval()

url_model = URLCharCNN(url_checkpoint["vocab_size"]).to(device)
url_model.load_state_dict(url_checkpoint["model_state_dict"])
url_model.eval()

meta_checkpoint = torch.load(
    bundle_dir / "phish360_metadata_mlp.pth",
    map_location=device,
    weights_only=False,
)
meta_model = MetadataMLP(meta_checkpoint["input_dim"]).to(device)
meta_model.load_state_dict(meta_checkpoint["model_state_dict"])
meta_model.eval()

fusion_model = FusionMLP().to(device)
fusion_model.load_state_dict(torch.load(
    bundle_dir / "phish360_fusion_mlp.pth",
    map_location=device,
    weights_only=True,
))
fusion_model.eval()
print("All five models loaded from the bundle.")

# -----------------------------------------------------------------------------
# 4. Golden samples — 20 rows from the test split, 10 per class, fixed seed
# -----------------------------------------------------------------------------
test = df[df["model_split"] == "test"].copy()
test["sample_index"] = test.index
test["html_text"] = (
    test["BeautifulSoup_text"].fillna("").astype(str).str.strip()
)
for col in CATEGORICAL_COLS:
    test[col] = test[col].fillna("UNKNOWN").astype(str)
test["SSL"] = (
    pd.to_numeric(test["SSL"], errors="coerce").fillna(0).astype(int)
)

golden = pd.concat([
    test[test["label"] == 0].sample(n=10, random_state=42),
    test[test["label"] == 1].sample(n=10, random_state=42),
]).sort_values("sample_index")
assert len(golden) == 20, f"Expected 20 golden rows, got {len(golden)}"
assert (golden["label"].value_counts() == 10).all(), "10 per class required."

# 4a. Screenshots (original files, untouched)
golden_images = []
for row in golden.itertuples():
    src = Path(row.screenshot_path)
    assert src.is_file(), f"Screenshot missing: {src}"
    suffix = src.suffix or ".png"
    shutil.copy2(src, golden_dir / f"{row.sample_index}{suffix}")
    with Image.open(src) as img:
        golden_images.append(img.convert("RGB").copy())
golden_images = torch.stack([
    image_transform(img) for img in golden_images
]).to(device)

# 4b. HTML text (exact cleaning from section 50)
html_encoded = tokenizer(
    golden["html_text"].tolist(),
    max_length=256,
    padding="max_length",
    truncation=True,
    return_tensors="pt",
)
html_encoded = {k: v.to(device) for k, v in html_encoded.items()}

# 4c. URLs (encode_url from section 50)
x_url = torch.tensor(
    np.array([encode_url(u) for u in golden["URL"].tolist()]),
    dtype=torch.long,
    device=device,
)

# 4d. Metadata (preprocessor fitted on the train split, section 50)
x_meta = preprocessor.transform(
    golden[CATEGORICAL_COLS + NUMERIC_COLS]
)
if hasattr(x_meta, "toarray"):
    x_meta = x_meta.toarray()
x_meta = torch.tensor(
    np.asarray(x_meta), dtype=torch.float32, device=device
)
assert x_meta.shape[1] == EXPECTED_METADATA_DIM

# 4e. Four base probabilities + fusion probability
with torch.no_grad():
    p_image = torch.softmax(
        image_model(golden_images), dim=1
    )[:, 1].cpu().numpy()
    p_html = torch.softmax(
        html_model(**html_encoded).logits, dim=1
    )[:, 1].cpu().numpy()
    p_url = torch.softmax(url_model(x_url), dim=1)[:, 1].cpu().numpy()
    p_meta = torch.softmax(meta_model(x_meta), dim=1)[:, 1].cpu().numpy()

golden = golden.assign(
    mobilenet_phishing_probability=p_image,
    distilbert_phishing_probability=p_html,
    url_cnn_phishing_probability=p_url,
    metadata_phishing_probability=p_meta,
)
x_fusion = torch.tensor(
    golden[FUSION_FEATURES].values, dtype=torch.float32, device=device
)
with torch.no_grad():
    p_fusion = torch.softmax(
        fusion_model(x_fusion), dim=1
    )[:, 1].cpu().numpy()

# Decision rule used in the notebook evaluation cells (section 54):
#   predictions = (probabilities >= 0.5).astype(int)
golden = golden.assign(
    fusion_mlp_phishing_probability=p_fusion,
    fusion_decision_05=(p_fusion >= 0.5).astype(int),
)

# 4f. Store inputs + expected values
GOLDEN_COLUMNS = [
    "sample_index", "URL", "html_text", "SSL", "TLD", "Subdomain",
    "label",
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
    "fusion_mlp_phishing_probability",
    "fusion_decision_05",
]
golden_csv = golden_dir / "golden_samples.csv"
golden[GOLDEN_COLUMNS].to_csv(golden_csv, index=False)

for row in golden.itertuples():
    (golden_dir / f"{row.sample_index}.txt").write_text(
        row.html_text, encoding="utf-8"
    )

print(f"\nGolden samples: {len(golden)} rows "
      f"({golden['label'].value_counts().to_dict()})")
print(f"  -> {golden_csv}")
display(golden[
    ["sample_index", "label", "fusion_mlp_phishing_probability",
     "fusion_decision_05"]
])

# -----------------------------------------------------------------------------
# 5. Rules sample — 600 rows, fixed seed
# -----------------------------------------------------------------------------
RULES_COLUMNS = [
    "URL", "TLD", "Domain", "FLD", "Subdomain", "SSL",
    "BeautifulSoup_text", "full_html", "label", "model_split",
]
rules_sample = df[RULES_COLUMNS].sample(
    n=min(600, len(df)), random_state=42
)
rules_parquet = bundle_dir / "phish360_rules_sample.parquet"
rules_sample.to_parquet(rules_parquet, index=False)
rules_bytes = rules_parquet.stat().st_size
rules_mb = rules_bytes / (1024 * 1024)
print(f"\nRules sample: {len(rules_sample)} rows -> {rules_parquet.name} "
      f"({rules_mb:.1f} MB)")
if rules_bytes > 15 * 1024 * 1024:
    print("  NOTE: larger than 15 MB — keep it out of git.")

# -----------------------------------------------------------------------------
# 6. Domain leakage audit: FLD/Domain present in both train and test
# -----------------------------------------------------------------------------
def _clean(values):
    cleaned = values.fillna("").astype(str).str.strip()
    return cleaned[cleaned != ""]


train_split = df[df["model_split"] == "train"]
test_split = df[df["model_split"] == "test"]
print("\n=== DOMAIN OVERLAP AUDIT (train vs test) ===")
overlap_report = {}
for col in ["Domain", "FLD"]:
    train_set = set(_clean(train_split[col]))
    test_values = _clean(test_split[col])
    shared = test_values.isin(train_set)
    overlap_report[col] = {
        "train_unique": len(train_set),
        "test_unique": int(test_values.nunique()),
        "shared_unique": len(set(test_values) & train_set),
        "test_rows_in_train_share": round(float(shared.mean()), 4),
    }
    print(f"  {col}: train_unique={overlap_report[col]['train_unique']} "
          f"test_unique={overlap_report[col]['test_unique']} "
          f"shared_unique={overlap_report[col]['shared_unique']} "
          f"test_rows_seen_in_train="
          f"{overlap_report[col]['test_rows_in_train_share']:.2%}")

# -----------------------------------------------------------------------------
# 7. Threshold audit on the TEST split (fusion probabilities recomputed from
#    the exported fusion checkpoint)
# -----------------------------------------------------------------------------
audit = fusion_test.copy()
x_audit = torch.tensor(
    audit[FUSION_FEATURES].values, dtype=torch.float32, device=device
)
with torch.no_grad():
    audit_p = torch.softmax(fusion_model(x_audit), dim=1)[:, 1].cpu().numpy()
y_true = audit["label"].astype(int).to_numpy()

pred_05 = (audit_p >= 0.5).astype(int)
tn, fp, fn, tp = confusion_matrix(y_true, pred_05, labels=[0, 1]).ravel()

in_band = (audit_p >= 0.40) & (audit_p <= 0.70)
error_05 = pred_05 != y_true

print("\n=== THRESHOLD AUDIT — TEST SPLIT ===")
print(f"  Rows: {len(audit)}  label_counts="
      f"{pd.Series(y_true).value_counts().sort_index().to_dict()}")
print(f"  Rule 0.50 (notebook evaluation): TN={tn} FP={fp} FN={fn} TP={tp}")
print(f"  Share with fusion prob in [0.40, 0.70]: {in_band.mean():.2%}")
print(f"  Error rate INSIDE  [0.40, 0.70]: "
      f"{error_05[in_band].mean() if in_band.any() else float('nan'):.2%}")
print(f"  Error rate OUTSIDE [0.40, 0.70]: "
      f"{error_05[~in_band].mean() if (~in_band).any() else float('nan'):.2%}")

for cutoff in (0.70, 0.40):
    if cutoff == 0.70:
        decided = audit_p >= 0.70
        decided_pred = 1
        label_txt = "phishing if p >= 0.70"
    else:
        decided = audit_p < 0.40
        decided_pred = 0
        label_txt = "legitimate if p < 0.40"
    covered = decided.mean()
    if decided.any():
        err = float((y_true[decided] != decided_pred).mean())
    else:
        err = float("nan")
    print(f"  Cutoff {label_txt}: coverage={covered:.2%} "
          f"error_among_decided={err:.2%}")

# -----------------------------------------------------------------------------
# 8. manifest.json — hash every bundle file
# -----------------------------------------------------------------------------
def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


files_manifest = {}
for path in sorted(bundle_dir.rglob("*")):
    if path.is_file() and path.name != "manifest.json":
        files_manifest[str(path.relative_to(bundle_dir))] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }

manifest = {
    "bundle_version": BUNDLE_VERSION,
    "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "source_notebook": "phish360-deeplearning-training.ipynb (export cell)",
    "class_mapping": {"0": "legitimate", "1": "phishing"},
    "fusion_feature_order": FUSION_FEATURES,
    "decision_rule": {
        "model": "fusion_mlp",
        "field": "fusion_mlp_phishing_probability",
        "threshold": 0.5,
        "meaning": "phishing if probability >= 0.5, else legitimate",
        "source": "notebook fusion evaluation cells "
                  "(predictions = (probabilities >= 0.5).astype(int))",
        "note": "production API adds its own uncertainty bands on top",
    },
    "preprocessing": {
        "encoder_file": "metadata_preprocessor.joblib",
        "categorical_columns": CATEGORICAL_COLS,
        "numeric_columns": NUMERIC_COLS,
        "fitted_on": "train split",
        "encoded_dim": int(_encoded_dim),
        "encoded_dim_expected": EXPECTED_METADATA_DIM,
        "preprocessing_version_sha256": files_manifest[
            "metadata_preprocessor.joblib"
        ]["sha256"],
    },
    "versions": {
        "python": platform.python_version(),
        "torch": torch.__version__,
        "torchvision": torchvision.__version__,
        "transformers": transformers.__version__,
        "scikit_learn": sklearn.__version__,
        "joblib": joblib.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
    },
    "test_split_reference": {
        "rows": len(audit),
        "label_counts": {
            str(k): int(v)
            for k, v in pd.Series(y_true).value_counts().sort_index().items()
        },
        "fusion_confusion_matrix_05": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
        "share_in_band_040_070": round(float(in_band.mean()), 4),
    },
    "domain_overlap": overlap_report,
    "files": files_manifest,
}

manifest_file = bundle_dir / "manifest.json"
with open(manifest_file, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, ensure_ascii=False)
print(f"\nManifest written: {manifest_file} "
      f"({len(files_manifest)} files hashed)")

# -----------------------------------------------------------------------------
# 9. Final summary + zip
# -----------------------------------------------------------------------------
print("\n" + "=" * 60)
print("BUNDLE SUMMARY")
print("=" * 60)
print(f"  bundle_version      : {BUNDLE_VERSION}")
print(f"  bundle directory    : {bundle_dir}")
for rel, info in files_manifest.items():
    print(f"    {rel:<48} {info['size_bytes']:>12,} bytes")
print(f"  golden samples      : {len(golden)} (10 legit / 10 phishing)")
print(f"  rules sample        : {len(rules_sample)} rows "
      f"({rules_parquet.name}, {rules_mb:.1f} MB)")
print(f"  metadata dim        : {_encoded_dim}")
print("  fusion rule         : p >= 0.5 => phishing")
print(f"  domain overlap      : "
      f"FLD {overlap_report['FLD']['test_rows_in_train_share']:.2%} of test "
      f"rows seen in train")

zip_base = f"/kaggle/working/phish360_export_bundle_{BUNDLE_VERSION}"
zip_path = Path(
    shutil.make_archive(zip_base, "zip", root_dir=bundle_dir)
)
zip_mb = zip_path.stat().st_size / (1024 * 1024)
print(f"\n  zip                  : {zip_path} ({zip_mb:.1f} MB)")
print("Done. Download the zip (or the bundle folder) from Output.")
