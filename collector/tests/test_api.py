"""Contract, authentication and capacity tests (spec v1 sections 5.1-5.3)."""
from __future__ import annotations

import asyncio

import pytest

from tests.conftest import AUTH, base_url

pytestmark = pytest.mark.anyio


async def test_health_is_public_and_openapi_is_published(env):
    response = await env.client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    schema = await env.client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/collect" in schema.json()["paths"]


async def test_collect_requires_the_api_key(env):
    body = {"url": "http://example.com/"}
    missing = await env.client.post("/collect", json=body)
    assert missing.status_code == 401
    assert missing.json()["code"] == "unauthorized"
    wrong = await env.client.post(
        "/collect", json=body, headers={"X-API-Key": "wrong-key"}
    )
    assert wrong.status_code == 401
    assert wrong.json()["code"] == "unauthorized"


async def test_invalid_urls_are_400_with_stable_codes(env):
    cases = [
        ("", "empty"),
        ("x" * 3000, "too_long"),
        ("ftp://example.com/page", "scheme_not_allowed"),
        ("http://user:pass@example.com/", "credentials_not_allowed"),
        ("http://localhost/admin", "blocked_host"),
        ("http://10.1.2.3/", "forbidden_address"),
    ]
    for url, expected in cases:
        response = await env.client.post("/collect", json={"url": url}, headers=AUTH)
        assert response.status_code == 400, (expected, response.text)
        assert response.json()["code"] == expected, url


async def test_busy_collector_answers_503_and_releases_the_slot(env, web_port):
    base = base_url(web_port)
    slow = asyncio.create_task(
        env.client.post("/collect", json={"url": f"{base}/slow"}, headers=AUTH)
    )
    await asyncio.sleep(1.0)
    busy = await env.client.post("/collect", json={"url": f"{base}/"}, headers=AUTH)
    assert busy.status_code == 503
    assert busy.json()["code"] == "busy"
    slow_response = await slow
    assert slow_response.status_code == 200
    assert slow_response.json()["reason_code"] == "TIMEOUT"
