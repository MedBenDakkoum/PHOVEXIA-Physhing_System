# Phish360 inference service image (CPU only).
#
# Python version rationale: manifest.json pins torch 2.11.0+cpu /
# torchvision 0.26.0+cpu. Checked on 2026-10-25 that
# https://download.pytorch.org/whl/cpu/ publishes
#   torch-2.11.0+cpu-cp313-cp313-manylinux_2_28_x86_64.whl
#   torchvision-0.26.0+cpu-cp313-cp313-manylinux_2_28_x86_64.whl
# and python:3.13-slim-bookworm ships glibc 2.36 (>= 2.28). No cp314 wheels
# were needed; contract section 3 forbids Python 3.14 unless explicitly tested.
#
# Stages:
#   hf-fetch  -> downloads distilbert-base-uncased tokenizer+config at BUILD
#                time, pinned to an exact revision; no download at runtime.
#   test      -> same deps + pytest; used by compose service inference-tests.
#   runtime   -> production image, non-root, healthcheck, single uvicorn worker.
#
# Build (from repo root):
#   docker build -t phish360-inference:local inference/

ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS hf-fetch
ARG HF_REVISION=12040accade4e8a0f71eabdb258fecc2e7e948be
RUN pip install --no-cache-dir transformers==5.16.1
RUN python - <<'PY'
import os
from transformers import AutoConfig, AutoTokenizer

revision = os.environ["HF_REVISION"]
name = "distilbert-base-uncased"
# Tokenizer + architecture config only. Model WEIGHTS are intentionally NOT
# baked: best_distilbert_html.pth (bundle, SHA-256 verified at startup)
# provides them, so the image carries the checkpoint once, not twice.
tokenizer = AutoTokenizer.from_pretrained(name, revision=revision)
config = AutoConfig.from_pretrained(name, revision=revision)
tokenizer.save_pretrained("/models_html")
config.save_pretrained("/models_html")
print("saved distilbert-base-uncased@", revision, "to /models_html")
PY

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS test
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY app ./app
COPY tests ./tests
COPY --from=hf-fetch /models_html /models_html
CMD ["pytest", "-q"]

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ARTIFACTS_DIR=/artifacts HF_LOCAL_DIR=/models_html PORT=8000

RUN groupadd --system app && useradd --system --gid app --home /srv app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=hf-fetch /models_html /models_html
RUN chown -R app:app /srv /models_html

USER app
EXPOSE 8000

# /health answers 200 only after SHA-256 verification, safe loads, shape
# checks and the dimension==1272 check all passed (lifespan startup).
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=5 \
    CMD python -c "import sys, urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# One worker on purpose: models are loaded once in process memory.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
