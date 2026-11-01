"""Fixtures: local HTTP/TLS servers + one app (browser + proxy) per test.

The suite must run in Docker (or any host where `testserver` resolves to
127.0.0.1): the collector refuses private addresses, so the fixtures only use
the COLLECTOR_ALLOW_PRIVATE_HOSTS test escape hatch (spec v1 section 5.7).
"""
from __future__ import annotations

import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse

os.environ.setdefault("COLLECTOR_API_KEY", "test-collector-key-20261025")
os.environ.setdefault("COLLECTOR_ENV", "test")
os.environ.setdefault("COLLECTOR_ALLOW_PRIVATE_HOSTS", "testserver")
os.environ.setdefault("COLLECTOR_TIMEOUT_S", "5")
os.environ.setdefault("COLLECTOR_LOAD_GRACE_S", "1.5")
os.environ.setdefault("COLLECTOR_MAX_CONCURRENCY", "1")
os.environ.setdefault("COLLECTOR_PROXY_PORT", "3129")

import httpx
import pytest
from app.config import Settings
from app.main import create_app

HOST = "testserver"
AUTH = {"X-API-Key": os.environ["COLLECTOR_API_KEY"]}

MAIN_HTML = (
    "<!doctype html><html><head><title>main</title></head>"
    "<body><h1>collector test page</h1><p>COLLECT-MAIN-MARKER</p></body></html>"
)
FINAL_HTML = (
    "<!doctype html><html><head><title>final</title></head>"
    "<body><p>COLLECT-FINAL-MARKER</p></body></html>"
)
POPUP_HTML = (
    "<!doctype html><html><head><title>popup owner</title></head>"
    "<body><p>COLLECT-POPUP-OWNER</p>"
    "<script>window.open('/popup-hit');</script></body></html>"
)
POPUP_HIT_HTML = (
    "<!doctype html><html><body><p>POPUP-WINDOW-CONTENT</p></body></html>"
)
DOWNLOAD_PAGE_HTML = (
    "<!doctype html><html><head><title>dl</title></head>"
    "<body><p>COLLECT-DL-OWNER</p>"
    "<script>location.href = '/file.txt';</script></body></html>"
)
STALL_HTML = (
    "<!doctype html><html><head><title>stall</title></head>"
    "<body><p>COLLECT-STALL-MARKER</p>"
    "<img src='/hang' alt='never finishes'></body></html>"
)


def base_url(port: int) -> str:
    return f"http://{HOST}:{port}"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send_html(MAIN_HTML)
        elif path == "/final":
            self._send_html(FINAL_HTML)
        elif path == "/r1":
            self._redirect("/r2")
        elif path == "/r2":
            self._redirect("/final")
        elif path == "/rmeta":
            self._redirect("http://169.254.169.254/latest/meta-data/")
        elif path == "/slow":
            time.sleep(8)
            self._send_html(MAIN_HTML)
        elif path == "/stall":
            self._send_html(STALL_HTML)
        elif path == "/hang":
            time.sleep(8)
            self._send_bytes(b"", "image/gif")
        elif path == "/big":
            self._send_bytes(b"x" * 6_000_000, "application/octet-stream")
        elif path == "/popup":
            self._send_html(POPUP_HTML)
        elif path == "/popup-hit":
            self._send_html(POPUP_HIT_HTML)
        elif path == "/dl":
            self._send_html(DOWNLOAD_PAGE_HTML)
        elif path == "/file.txt":
            self._send_bytes(
                b"DROP-FILE-CONTENT",
                "application/octet-stream",
                extra=(("Content-Disposition", 'attachment; filename="drop.txt"'),),
            )
        else:
            self._send_bytes(b"not found", "text/plain", status=404)

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: int = 200,
        extra: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8")

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="session")
def web_port() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def tls_port() -> int:
    import trustme

    ca = trustme.CA()
    cert = ca.issue_cert("testserver")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(context)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def env():
    """One app instance: fresh proxy + fresh Chromium, closed after the test."""
    settings = Settings.from_env()
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://collector.local"
        ) as client:
            yield SimpleNamespace(
                app=application, client=client, settings=settings
            )
