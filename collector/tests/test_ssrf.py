"""SSRF edge cases: DNS rebinding at connection time (BR-07, spec v1 section 4)."""
from __future__ import annotations

import app.urlrules as urlrules_module
import pytest

from tests.conftest import AUTH

pytestmark = pytest.mark.anyio


async def test_dns_rebinding_is_refused_at_connection_time(env, monkeypatch):
    calls = {"count": 0}

    def resolver(host: str) -> list[str]:
        calls["count"] += 1
        if calls["count"] == 1:
            return ["93.184.216.34"]
        return ["10.0.0.5"]

    monkeypatch.setattr(urlrules_module, "_resolve_host", resolver)
    response = await env.client.post(
        "/collect", json={"url": "https://rebind.test/"}, headers=AUTH
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial"
    assert data["reason_code"] == "BLOCKED_ADDRESS"
    assert calls["count"] >= 2
