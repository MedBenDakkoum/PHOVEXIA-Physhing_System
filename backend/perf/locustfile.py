"""Locust load test: the full Docker stack through nginx (Step 15, ISO-6.5).

What it measures: the API endpoints an END USER actually hits, with real
PostgreSQL + Redis + gunicorn + nginx + Celery in front of them. The model
is the deterministic mock (no ONNX weight in the image), so this run proves
the PLATFORM latency, not the model latency.

Run (host, venv active; the stack must already be up - see deploy/README.md):

    docker compose -f docker-compose.yml -f deploy/docker-compose.perf.yml \
        --profile full up --build -d
    docker compose exec -e ALLOW_SEED=1 web python manage.py seed_perf_users
    locust -f perf/locustfile.py --host http://127.0.0.1:8080 \
        --headless -u 20 -r 5 -t 60s --csv reports/perf --html reports/perf.html

The 20 accounts are created by `manage.py seed_perf_users`
(perf.userNN@example.org / PerfUser!2026x, role end_user).

Task mix (weight = share of the requests, documented in HANDOFF.md):
  60 %  GET  /api/scans/          list my history
  25 %  POST /api/scans/          submit a new scan (enqueues Celery)
  10 %  GET  /api/scans/quota/    remaining daily quota
   5 %  POST /api/quick-check/    anonymous quick check (no auth)

Throttles that would 429 a 20-user run from ONE IP (all users share
127.0.0.1 behind nginx) are raised by the perf-only override file
backend/deploy/docker-compose.perf.yml - never by editing the real .env:
  THROTTLE_LOGIN (10/min -> 10000/min, login is per-IP),
  SCAN_DAILY_QUOTA (20 -> 100000), QUICK_CHECK_HOURLY_LIMIT (5 -> 10000).
The DRF user rate stays at its default 120/min: the mix sends ~10-30
authenticated requests per user per minute, far below it, so the number
below is the real production throttle behaviour, not a disabled one.
"""
from __future__ import annotations

import itertools
import threading

from locust import HttpUser, between, task

PASSWORD = "PerfUser!2026x"
USER_COUNT = 20

# One email per simulated user, assigned in order (perf.user01 .. perf.user20).
_emails = (
    f"perf.user{index:02d}@example.org" for index in range(1, USER_COUNT + 1)
)
_email_lock = threading.Lock()

# Known-good public hosts (never an internal name: the URL validator and the
# SSRF guard refuse private/loopback hosts).
_TARGETS = (
    "https://example.com",
    "https://example.org",
    "https://example.net",
)
_url_counter = itertools.count(1)


def _next_url(path: str) -> str:
    host = _TARGETS[next(_url_counter) % len(_TARGETS)]
    return f"{host}{path}?n={next(_url_counter)}"


class PerfUser(HttpUser):
    """One authenticated end user (weight = share of the request mix)."""

    wait_time = between(0.5, 1.5)
    # host is normally passed with --host; stated here so a bare
    # `locust -f perf/locustfile.py` still hits the stack.
    host = "http://127.0.0.1:8080"

    def on_start(self) -> None:
        with _email_lock:
            self.email = next(_emails)
        response = self.client.post(
            "/api/auth/login/",
            json={"email": self.email, "password": PASSWORD},
            name="/api/auth/login/",
        )
        if response.status_code != 200:
            # Fail loudly in the report instead of silently 401-ing every task.
            raise RuntimeError(
                f"login failed for {self.email}: "
                f"{response.status_code} {response.text[:200]}"
            )
        self.client.headers.update(
            {"Authorization": f"Bearer {response.json()['access']}"}
        )

    @task(60)
    def list_scans(self) -> None:
        self.client.get("/api/scans/?limit=10", name="/api/scans/ [list]")

    @task(25)
    def create_scan(self) -> None:
        self.client.post(
            "/api/scans/",
            json={"url": _next_url("/perf")},
            name="/api/scans/ [create]",
        )

    @task(10)
    def scan_quota(self) -> None:
        self.client.get("/api/scans/quota/", name="/api/scans/quota/")

    @task(5)
    def quick_check(self) -> None:
        self.client.post(
            "/api/quick-check/",
            json={"url": _next_url("/quick")},
            name="/api/quick-check/",
        )
