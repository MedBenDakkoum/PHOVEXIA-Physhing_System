"""FastAPI entry point for the Phish360 CPU inference service."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from app.config import Settings, load_settings
from app.errors import (
    BundleIntegrityError,
    BundleLoadError,
    ImageValidationError,
)
from app.images import decode_screenshot
from app.loader import Bundle, load_bundle
from app.pipeline import PipelineResult, run_pipeline
from app.schemas import BaseProbabilities, HealthResponse, PredictResponse
from app.security import is_valid_api_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s")
logger = logging.getLogger(__name__)

ALL_SIGNALS = ["url", "html_text", "metadata", "screenshot"]


async def _read_bounded(file: UploadFile, limit: int) -> bytes | None:
    """Read at most limit+1 bytes; None means the upload exceeds the limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(bundle: Bundle | None = None, settings: Settings | None = None) -> FastAPI:
    state: dict = {"ready": False, "bundle": bundle}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if state["bundle"] is None:
            cfg = load_settings()
            state["settings"] = cfg
            try:
                state["bundle"] = load_bundle(cfg.artifacts_dir, cfg.hf_local_dir)
            except (BundleIntegrityError, BundleLoadError):
                logger.critical("bundle verification/loading failed", exc_info=True)
                raise
            state["settings"] = cfg
        else:
            state["settings"] = settings or load_settings()
        state["ready"] = True
        logger.info(
            "inference service ready, bundle=%s",
            state["bundle"].version,
        )
        yield
        state["ready"] = False

    app = FastAPI(title="Phish360 inference service", lifespan=lifespan)

    def require_api_key(x_api_key: str = Header(default="")) -> None:
        expected = state["settings"].api_key
        if not is_valid_api_key(x_api_key, expected):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse | JSONResponse:
        if not state["ready"]:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "model_bundle_version": None},
            )
        bundle: Bundle = state["bundle"]
        return HealthResponse(
            status="ready",
            model_bundle_version=bundle.version,
            checks=bundle.checks,
        )

    @app.post("/predict", response_model=PredictResponse, status_code=200)
    async def predict(
        url: str | None = Form(default=None),
        text: str | None = Form(default=None),
        ssl: str | None = Form(default=None),
        tld: str | None = Form(default=""),
        subdomain: str | None = Form(default=""),
        screenshot: UploadFile | None = File(default=None),  # noqa: B008
        _: None = Depends(require_api_key),
    ) -> PredictResponse:
        cfg: Settings = state["settings"]
        bundle: Bundle = state["bundle"]

        failures: list[tuple[str, str]] = []
        available: list[str] = []
        unavailable: list[str] = []

        clean_url = (url or "").strip()
        if url is None:
            failures.append(("url", "MISSING_URL"))
        elif not clean_url:
            failures.append(("url", "EMPTY_URL"))
        elif len(clean_url) > cfg.max_url_length:
            failures.append(("url", "URL_TOO_LONG"))
        else:
            available.append("url")

        clean_text = (text or "").strip()
        if text is None:
            failures.append(("html_text", "MISSING_TEXT"))
        elif len(text.encode("utf-8")) > cfg.max_text_bytes:
            failures.append(("html_text", "TEXT_TOO_LARGE"))
        elif not clean_text:
            failures.append(("html_text", "EMPTY_TEXT"))
        else:
            available.append("html_text")

        ssl_value: int | None = None
        if ssl is None or ssl.strip() == "":
            failures.append(("metadata", "MISSING_SSL"))
        else:
            token = ssl.strip().lower()
            if token in {"1", "true", "yes"}:
                ssl_value = 1
            elif token in {"0", "false", "no"}:
                ssl_value = 0
            else:
                failures.append(("metadata", "INVALID_SSL"))
        if ssl_value is not None:
            available.append("metadata")

        image = None
        if screenshot is None:
            failures.append(("screenshot", "MISSING_SCREENSHOT"))
        else:
            raw_bytes = await _read_bounded(screenshot, cfg.max_image_bytes)
            if raw_bytes is None:
                failures.append(("screenshot", "IMAGE_TOO_LARGE"))
            elif not raw_bytes:
                failures.append(("screenshot", "MISSING_SCREENSHOT"))
            else:
                try:
                    image = decode_screenshot(raw_bytes, cfg.max_image_pixels)
                    available.append("screenshot")
                except ImageValidationError as exc:
                    failures.append(("screenshot", exc.reason_code))

        if failures:
            reason = failures[0][1]
            failed_signals = {signal for signal, _ in failures}
            for signal in ALL_SIGNALS:
                if signal in failed_signals and signal not in unavailable:
                    unavailable.append(signal)
            available = [s for s in ALL_SIGNALS if s in available]
            return _uncertain(
                bundle.version,
                reason_code=reason,
                available=available,
                unavailable=unavailable,
            )

        try:
            result: PipelineResult = await asyncio.wait_for(
                run_in_threadpool(
                    run_pipeline,
                    bundle,
                    url=clean_url,
                    text=clean_text,
                    ssl=ssl_value,
                    tld=(tld or "").strip(),
                    subdomain=(subdomain or "").strip(),
                    image=image,
                ),
                timeout=cfg.predict_timeout_seconds,
            )
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("predict timed out after %ss", cfg.predict_timeout_seconds)
            return _uncertain(
                bundle.version,
                reason_code="TIMEOUT",
                available=ALL_SIGNALS,
                unavailable=[],
            )
        except Exception:
            logger.exception("unexpected pipeline failure")
            return _uncertain(
                bundle.version,
                reason_code="INTERNAL_ERROR",
                available=ALL_SIGNALS,
                unavailable=[],
            )

        if result.error is not None:
            failed_signal = result.failed_signal
            if failed_signal == "fusion":
                computed_signals = list(ALL_SIGNALS)
                remaining: list[str] = []
            else:
                cut = ALL_SIGNALS.index(failed_signal)
                computed_signals = ALL_SIGNALS[:cut]
                remaining = ALL_SIGNALS[cut:]
            return _uncertain(
                bundle.version,
                reason_code="MODEL_ERROR",
                available=computed_signals,
                unavailable=remaining,
                base=result.base_probabilities,
            )

        return PredictResponse(
            status="complete",
            partial=False,
            prediction=result.prediction,
            model_bundle_version=bundle.version,
            phishing_probability=result.fusion_probability,
            base_probabilities=BaseProbabilities(**result.base_probabilities),
            reason_code=None,
            available_signals=ALL_SIGNALS,
            unavailable_signals=[],
        )

    return app


def _uncertain(
    version: str,
    *,
    reason_code: str,
    available: list[str],
    unavailable: list[str],
    base: dict | None = None,
) -> PredictResponse:
    base_field = None
    if base:
        base_field = BaseProbabilities(
            mobilenet_phishing_probability=base.get("mobilenet_phishing_probability"),
            distilbert_phishing_probability=base.get("distilbert_phishing_probability"),
            url_cnn_phishing_probability=base.get("url_cnn_phishing_probability"),
            metadata_phishing_probability=base.get("metadata_phishing_probability"),
        )
    return PredictResponse(
        status="uncertain",
        partial=True,
        prediction="uncertain",
        model_bundle_version=version,
        phishing_probability=None,
        base_probabilities=base_field,
        reason_code=reason_code,
        available_signals=available,
        unavailable_signals=unavailable,
    )


app = create_app()
