"""TLS recording against a locally issued certificate (spec v1 section 5.6)."""
from __future__ import annotations

import pytest

from tests.conftest import AUTH, HOST

pytestmark = pytest.mark.anyio


async def test_self_signed_capture_reports_the_real_tls_state(env, tls_port):
    url = f"https://{HOST}:{tls_port}/"
    response = await env.client.post("/collect", json={"url": url}, headers=AUTH)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert "COLLECT-MAIN-MARKER" in data["text"]
    assert data["ssl"] == 1
    assert data["final_url"] == url
    tls = data["tls"]
    assert tls["ok"] is False
    assert tls["error"] == "cert_verification_failed"
    assert tls["issuer"]
    assert tls["not_after"]
    assert tls["days_remaining"] is not None and tls["days_remaining"] > 0
    assert tls["self_signed"] is False
    assert data["timings_ms"]["tls_probe"] is not None
