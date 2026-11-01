"""FastAPI entry point: GET /health, POST /collect (spec v1 section 5)."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import extract, tlsprobe, urlrules
from .collector import PageCollector
from .config import Settings
from .errors import ApiError
from .proxy import ForwardProxy
from .schemas import CollectRequest, CollectResponse
from .security import require_api_key

logger = logging.getLogger("collector.api")


def _timeout_payload(url: str, settings: Settings) -> dict[str, Any]:
    """Partial payload for a request that burned the whole deadline (spec 5.5)."""
    features = extract.url_features(url)
    return {
        "status": "partial",
        "reason_code": "TIMEOUT",
        "final_url": url,
        "redirect_chain": [],
        "http_status": None,
        "text": None,
        "ssl": features.ssl,
        "tld": features.tld,
        "domain": features.domain,
        "fld": features.fld,
        "subdomain": features.subdomain,
        "screenshot_png_base64": None,
        "load_complete": False,
        "tls": tlsprobe.empty_info("not_probed"),
        "timings_ms": {
            "total": int(settings.timeout_s * 1000),
            "navigation": None,
            "screenshot": None,
            "text_extraction": None,
            "tls_probe": None,
        },
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app; settings=None means "read the environment at startup"."""

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        resolved: Settings = application.state.settings or Settings.from_env()
        application.state.settings = resolved
        proxy = ForwardProxy(resolved)
        await proxy.start()
        collector = PageCollector(resolved, proxy)
        await collector.start()
        application.state.proxy = proxy
        application.state.collector = collector
        application.state.semaphore = asyncio.Semaphore(resolved.max_concurrency)
        try:
            yield
        finally:
            await collector.close()
            await proxy.close()

    app = FastAPI(
        title="Phish360 Collector",
        version="1.0.0",
        description="Isolated page collector (US17 / BR-07) — spec docs/collector_spec_v1.md",
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.exception_handler(ApiError)
    async def handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code, "detail": exc.detail},
        )

    @app.exception_handler(urlrules.InvalidURL)
    async def handle_invalid_url(request: Request, exc: urlrules.InvalidURL) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"code": exc.code.value, "detail": "URL rejected by validation"},
        )

    @app.exception_handler(RequestValidationError)
    async def handle_bad_body(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "code": "invalid_request",
                "detail": 'body must be {"url": "https://..."}',
            },
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/collect", response_model=CollectResponse)
    async def collect(
        payload: CollectRequest,
        request: Request,
        authorized: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        settings_value: Settings = request.app.state.settings
        validated = urlrules.validate_url(
            payload.url, settings_value.allow_private_hosts
        )
        semaphore: asyncio.Semaphore = request.app.state.semaphore
        if semaphore.locked():
            raise ApiError(503, "busy", "collector is at capacity, retry later")
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    request.app.state.collector.collect(validated.url),
                    timeout=settings_value.timeout_s,
                )
            except (asyncio.TimeoutError, TimeoutError):
                logger.warning("collection exceeded the total deadline")
                return _timeout_payload(validated.url, settings_value)

    return app
