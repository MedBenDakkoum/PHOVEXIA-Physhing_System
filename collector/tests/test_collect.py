"""Capture scenarios against the local HTTP server (spec v1 sections 5.3-5.5)."""
from __future__ import annotations

import asyncio
import base64
import struct

import pytest

from tests.conftest import AUTH, HOST, base_url

pytestmark = pytest.mark.anyio


async def test_complete_capture_of_a_simple_page(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert data["reason_code"] is None
    assert data["http_status"] == 200
    assert data["final_url"] == f"{base}/"
    assert data["redirect_chain"] == []
    assert data["text"] is not None and "COLLECT-MAIN-MARKER" in data["text"]
    assert data["ssl"] == 0
    assert data["tld"] == ""
    assert data["domain"] == HOST
    assert data["fld"] == ""
    assert data["subdomain"] == ""
    assert data["tls"]["ok"] is False
    assert data["tls"]["error"] == "not_https"
    png = base64.b64decode(data["screenshot_png_base64"])
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (1280, 960)
    timings = data["timings_ms"]
    assert timings["total"] >= 0
    assert timings["navigation"] is not None
    assert timings["screenshot"] is not None
    assert timings["text_extraction"] is not None
    assert timings["tls_probe"] == 0


async def test_redirect_chain_is_recorded(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/r1"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert data["final_url"] == f"{base}/final"
    assert data["redirect_chain"] == [f"{base}/r1", f"{base}/r2"]
    assert "COLLECT-FINAL-MARKER" in data["text"]


async def test_redirect_to_cloud_metadata_is_blocked(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/rmeta"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["reason_code"] == "BLOCKED_ADDRESS"
    assert data["final_url"].startswith("http://169.254.169.254/")
    assert data["http_status"] == 403


async def test_slow_page_hits_the_total_timeout(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/slow"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["reason_code"] == "TIMEOUT"
    assert data["text"] is None
    assert data["screenshot_png_base64"] is None
    assert data["timings_ms"]["total"] >= 5000
    assert data["tls"]["error"] == "not_probed"


async def test_oversized_document_is_refused(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/big"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["reason_code"] == "TOO_LARGE"


async def test_popup_windows_are_closed(env, web_port):
    base = base_url(web_port)
    collector = env.app.state.collector
    before = collector.stats["popups_closed"]
    response = await env.client.post(
        "/collect", json={"url": f"{base}/popup"}, headers=AUTH
    )
    assert response.status_code == 200
    assert response.json()["status"] == "complete"
    await asyncio.sleep(0.5)
    assert collector.stats["popups_closed"] >= before + 1


async def test_downloaded_files_do_not_break_collection(env, web_port):
    base = base_url(web_port)
    response = await env.client.post(
        "/collect", json={"url": f"{base}/dl"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("complete", "partial")
    if data["status"] == "partial":
        assert data["reason_code"] in ("NAVIGATION_ERROR", "SITE_UNREACHABLE")
