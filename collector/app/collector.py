"""Playwright capture: one fresh context per request (spec v1 sections 3 and 5.5)."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import Browser, Playwright, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from . import extract, tlsprobe, urlrules
from .config import Settings
from .proxy import ForwardProxy

logger = logging.getLogger("collector.capture")

DOC_MAX_BYTES = 5_000_000
SCREENSHOT_MAX_BYTES = 5_000_000
MAX_REDIRECTS = 10
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 960
SCREENSHOT_TIMEOUT_MS = 10_000
# Only used when the "load" event did not fire inside COLLECTOR_LOAD_GRACE_S.
LOAD_SETTLE_S = 0.3


async def _close_quietly(page: Any) -> None:
    try:
        await page.close()
    except PlaywrightError:
        pass


def _header_value_int(headers: Any, name: str) -> int | None:
    """Content-Length from a CDP headers map (dict) or header list (pairs)."""
    value: Any = None
    if isinstance(headers, dict):
        for key, item in headers.items():
            if str(key).lower() == name:
                value = item
                break
    elif isinstance(headers, list):
        for item in headers:
            if str((item or {}).get("name", "")).lower() == name:
                value = item.get("value")
                break
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _classify_nav_error(exc: PlaywrightError) -> str:
    message = str(exc)
    logger.debug(
        "navigation failed: %s",
        message.splitlines()[0] if message else exc.__class__.__name__,
    )
    if "download" in message.lower():
        return "download"
    return "navigation"


def _resolve_on_download(evt: asyncio.Future[None]):
    """Playwright signals a `download` long before `load` ever fires."""

    def on_download(_download: Any) -> None:
        if not evt.done():
            evt.set_result(None)

    return on_download


def _nav_outcome(goto_task: asyncio.Task[Any]) -> tuple[str | None, Any]:
    if goto_task.cancelled():
        return "navigation", None
    exc = goto_task.exception()
    if exc is None:
        return None, goto_task.result()
    if isinstance(exc, PlaywrightTimeoutError):
        return "timeout", None
    return _classify_nav_error(exc), None


def _redirect_chain(response: Any) -> list[str]:
    chain: list[str] = []
    if response is None:
        return chain
    request = response.request
    walk = request.redirected_from
    while walk is not None:
        chain.append(walk.url)
        walk = walk.redirected_from
    chain.reverse()
    return chain


def _decode_html(body: bytes, content_type: str | None) -> str:
    encoding = "utf-8"
    if content_type:
        for part in content_type.split(";")[1:]:
            key, sep, value = part.strip().partition("=")
            if sep and key.lower() == "charset" and value:
                encoding = value.strip("\"' ")
                break
    try:
        return body.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        return body.decode("utf-8", errors="replace")


class PageCollector:
    """Owns one Chromium instance and performs the collect contract per request."""

    def __init__(self, settings: Settings, proxy: ForwardProxy) -> None:
        self.settings = settings
        self.proxy = proxy
        self.stats: dict[str, int] = {"popups_closed": 0, "contexts": 0}
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._contexts_since_recycle = 0

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        await self._launch()

    async def _launch(self) -> None:
        if self._playwright is None:
            raise RuntimeError("collector playwright is not started")
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            proxy={
                "server": f"http://127.0.0.1:{self.settings.proxy_port}",
                "bypass": "<-loopback>",
            },
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        self._contexts_since_recycle = 0

    async def close(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    def _gate_page_event(self, main_page: Any):
        """Close every page EXCEPT the main one (popups, spec v1 section 5.5)."""

        def on_page(candidate: Any) -> None:
            if candidate is main_page:
                return
            self.stats["popups_closed"] += 1
            asyncio.ensure_future(_close_quietly(candidate))

        return on_page

    async def _route_by_scheme(self, route: Any) -> None:
        scheme = urlsplit(route.request.url).scheme.lower()
        if scheme in ("http", "https"):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    async def collect(self, url: str) -> dict[str, Any]:
        """Fetch `url` behind the proxy and return the /collect contract payload."""
        if self._browser is None:
            raise RuntimeError("collector browser is not running")
        if self._contexts_since_recycle >= self.settings.browser_recycle_every:
            logger.info(
                "recycling chromium after %d contexts", self._contexts_since_recycle
            )
            await self._browser.close()
            await self._launch()
        started = time.perf_counter()
        context = await self._browser.new_context(
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            device_scale_factor=1.0,
            accept_downloads=False,
            ignore_https_errors=True,
            service_workers="block",
            # Spec v1.1: match the language/timezone of the English training
            # corpus. No User-Agent change, no fingerprint evasion.
            locale="en-US",
            timezone_id="UTC",
        )
        self.stats["contexts"] += 1
        self._contexts_since_recycle += 1
        hosts: set[str] = set()
        track = {"total_bytes": 0, "redirects": 0}
        flags = {"over_size": False, "too_many_redirects": False}
        timings: dict[str, int | None] = {
            "navigation": None,
            "screenshot": None,
            "text_extraction": None,
            "tls_probe": None,
        }
        nav_error: str | None = None
        response = None
        goto_task: asyncio.Task[Any] | None = None
        download_evt: asyncio.Future[None] = (
            asyncio.get_running_loop().create_future()
        )
        try:
            page = await context.new_page()
            # Subscribed AFTER the main page exists: the identity gate keeps
            # the main page alive even if the event is delivered late.
            context.on("page", self._gate_page_event(page))
            page.on("download", _resolve_on_download(download_evt))
            await context.route("**/*", self._route_by_scheme)
            cdp = await context.new_cdp_session(page)
            cdp.on(
                "Network.requestWillBeSent",
                _make_request_tracker(page, hosts, track, flags),
            )
            cdp.on("Network.responseReceived", _make_response_tracker(page, flags))
            cdp.on(
                "Network.loadingFinished",
                _make_finished_tracker(page, track, flags, self.settings),
            )
            await cdp.send("Network.enable")
            # Playwright normalises Accept-Language to "en-US" from `locale`.
            # Chromium serialises the CDP acceptLanguage and appends the
            # default q-weight, so "en-US,en" becomes the exact header
            # "en-US,en;q=0.9" (verified end-to-end via a real echo page).
            # The User-Agent is re-sent unchanged.
            user_agent = await page.evaluate("navigator.userAgent")
            await cdp.send(
                "Emulation.setUserAgentOverride",
                {"userAgent": user_agent, "acceptLanguage": "en-US,en"},
            )

            nav_started = time.perf_counter()
            goto_task = asyncio.ensure_future(
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=(self.settings.timeout_s + 2) * 1000,
                )
            )
            await asyncio.wait(
                (goto_task, download_evt),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if download_evt.done() and not goto_task.done():
                nav_error = "download"
            elif goto_task.done() and not goto_task.cancelled():
                nav_error, response = _nav_outcome(goto_task)
            if not goto_task.done():
                goto_task.cancel()
            await asyncio.gather(goto_task, return_exceptions=True)
            timings["navigation"] = int((time.perf_counter() - nav_started) * 1000)

            # DOM is parsed; give the "load" event a bounded grace instead of
            # waiting for it until the total deadline (heavy legit pages).
            load_complete = False
            if nav_error is None:
                load_complete = await self._wait_for_load(page)
                if not load_complete:
                    await asyncio.sleep(LOAD_SETTLE_S)

            final_url = self._final_url(page, url)
            chain = _redirect_chain(response)

            text_started = time.perf_counter()
            text, text_failed = await self._extract_text(page, response)
            timings["text_extraction"] = int((time.perf_counter() - text_started) * 1000)

            shot_started = time.perf_counter()
            screenshot, screenshot_failed = await self._screenshot(page)
            timings["screenshot"] = int((time.perf_counter() - shot_started) * 1000)

            features = extract.url_features(final_url)
            tls, timings["tls_probe"] = await self._probe(final_url, features.ssl)

            status, reason = self._decide(
                response=response,
                nav_error=nav_error,
                flags=flags,
                hosts=hosts,
                chain=chain,
                requested_url=url,
                final_url=final_url,
                text_failed=text_failed,
                screenshot_failed=screenshot_failed,
            )
            return {
                "status": status,
                "reason_code": reason,
                "final_url": final_url,
                "redirect_chain": chain,
                "http_status": response.status if response is not None else None,
                "text": text,
                "ssl": features.ssl,
                "tld": features.tld,
                "domain": features.domain,
                "fld": features.fld,
                "subdomain": features.subdomain,
                "screenshot_png_base64": screenshot,
                "load_complete": load_complete,
                "tls": tls,
                "timings_ms": {
                    "total": int((time.perf_counter() - started) * 1000),
                    "navigation": timings["navigation"],
                    "screenshot": timings["screenshot"],
                    "text_extraction": timings["text_extraction"],
                    "tls_probe": timings["tls_probe"],
                },
            }
        finally:
            if goto_task is not None and not goto_task.done():
                goto_task.cancel()
                await asyncio.gather(goto_task, return_exceptions=True)
            await context.close()

    async def _wait_for_load(self, page: Any) -> bool:
        """Wait at most COLLECTOR_LOAD_GRACE_S for the load event, never fatal."""
        try:
            await page.wait_for_load_state(
                "load", timeout=int(self.settings.load_grace_s * 1000)
            )
        except PlaywrightTimeoutError:
            return False
        except PlaywrightError:
            logger.debug("load state unavailable", exc_info=True)
            return False
        return True

    def _final_url(self, page: Any, requested: str) -> str:
        try:
            current = page.url
        except PlaywrightError:
            current = None
        if not current or current == "about:blank":
            return requested
        return current

    async def _extract_text(
        self, page: Any, response: Any
    ) -> tuple[str | None, bool]:
        """Response bytes first (spec v1 3.4), rendered DOM as fallback."""
        html: str | None = None
        if response is not None:
            body = None
            try:
                body = await response.body()
            except PlaywrightError:
                body = None
            if body is not None:
                content_type = None
                try:
                    content_type = response.headers.get("content-type")
                except PlaywrightError:
                    content_type = None
                html = _decode_html(body, content_type)
        if html is None:
            try:
                html = await page.content()
            except PlaywrightError:
                logger.debug("DOM content unavailable", exc_info=True)
                return None, True
        try:
            return extract.extract_text(html), False
        except Exception:
            logger.debug("text extraction failed", exc_info=True)
            return None, True

    async def _screenshot(self, page: Any) -> tuple[str | None, bool]:
        try:
            png = await page.screenshot(
                type="png", timeout=SCREENSHOT_TIMEOUT_MS, full_page=False
            )
        except PlaywrightError:
            logger.debug("screenshot failed", exc_info=True)
            return None, True
        if len(png) > SCREENSHOT_MAX_BYTES:
            logger.warning("screenshot of %d bytes exceeds the cap", len(png))
            return None, True
        return base64.b64encode(png).decode("ascii"), False

    async def _probe(
        self, url: str, ssl_flag: int
    ) -> tuple[dict[str, Any], int | None]:
        if ssl_flag != 1:
            return tlsprobe.empty_info("not_https"), 0
        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return tlsprobe.empty_info("not_probed"), None
        port = parts.port or 443
        try:
            addresses = urlrules.resolve_addresses(
                host, self.settings.allow_private_hosts
            )
        except urlrules.InvalidURL:
            return tlsprobe.empty_info("not_probed"), None
        probe_started = time.perf_counter()
        info = await tlsprobe.probe_tls(addresses[0], host, port)
        return info, int((time.perf_counter() - probe_started) * 1000)

    def _decide(
        self,
        response: Any,
        nav_error: str | None,
        flags: dict[str, bool],
        hosts: set[str],
        chain: list[str],
        requested_url: str,
        final_url: str,
        text_failed: bool,
        screenshot_failed: bool,
    ) -> tuple[str, str | None]:
        """Map the request outcome to status + stable reason code (spec v1 5.4)."""
        if flags["over_size"]:
            return "partial", "TOO_LARGE"
        if flags["too_many_redirects"]:
            return "partial", "NAVIGATION_ERROR"
        if nav_error == "timeout":
            return "partial", "TIMEOUT"
        if nav_error is not None:
            if nav_error == "download":
                return "partial", "NAVIGATION_ERROR"
            if self._refused(hosts, chain, requested_url, final_url):
                return "partial", "BLOCKED_ADDRESS"
            return "partial", "SITE_UNREACHABLE"
        if response is None:
            return "partial", "NAVIGATION_ERROR"
        if not 200 <= response.status < 300:
            if self._refused(hosts, chain, requested_url, final_url):
                return "partial", "BLOCKED_ADDRESS"
            return "partial", "NAVIGATION_ERROR"
        if text_failed:
            return "partial", "TEXT_EXTRACTION_FAILED"
        if screenshot_failed:
            return "partial", "SCREENSHOT_FAILED"
        return "complete", None

    def _refused(
        self, hosts: set[str], chain: list[str], *urls: str
    ) -> bool:
        candidates = set(hosts)
        for candidate in (*urls, *chain):
            if not candidate:
                continue
            host = urlsplit(candidate).hostname
            if host:
                candidates.add(host.lower().rstrip("."))
        return self.proxy.pop_refusal(candidates)


def _make_request_tracker(
    page: Any, hosts: set[str], track: dict[str, int], flags: dict[str, bool]
):
    def on_request(params: dict[str, Any]) -> None:
        request = params.get("request") or {}
        host = urlsplit(str(request.get("url") or "")).hostname
        if host:
            hosts.add(host.lower().rstrip("."))
        if "redirectResponse" in params:
            track["redirects"] += 1
            if track["redirects"] > MAX_REDIRECTS and not flags["too_many_redirects"]:
                flags["too_many_redirects"] = True
                asyncio.ensure_future(_close_quietly(page))

    return on_request


def _make_response_tracker(page: Any, flags: dict[str, bool]):
    def on_response(params: dict[str, Any]) -> None:
        if flags["over_size"] or params.get("type") != "Document":
            return
        response = params.get("response") or {}
        content_length = _header_value_int(response.get("headers"), "content-length")
        if content_length is not None and content_length > DOC_MAX_BYTES:
            flags["over_size"] = True
            asyncio.ensure_future(_close_quietly(page))

    return on_response


def _make_finished_tracker(
    page: Any,
    track: dict[str, int],
    flags: dict[str, bool],
    settings: Settings,
):
    def on_finished(params: dict[str, Any]) -> None:
        track["total_bytes"] += int(params.get("encodedDataLength") or 0)
        if track["total_bytes"] > settings.max_total_bytes and not flags["over_size"]:
            flags["over_size"] = True
            asyncio.ensure_future(_close_quietly(page))

    return on_finished
