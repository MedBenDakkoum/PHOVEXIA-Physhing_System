"""
Step 9 tests - anonymous quick check (US11 / BR-02, ISO-6.1, ISO-6.6).

DNS is ALWAYS mocked: no test touches the network. The suite runs unchanged
on SQLite and PostgreSQL (see docs/HANDOFF.md for the exact commands).

Essential cases only: happy path, the hourly limit (incl. a forged
X-Forwarded-For), the SSRF refusal, the isolation of owned scans and the
audit entry.
"""
import socket
from uuid import uuid4

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status as http_status

from audit.models import AuditLog
from scans.models import Scan
from scans.services import url_validation

VALID_URL = "https://example.com/login?user=1"
SECRET_URL = "https://example.com/login?user=secret-token"
DOMAIN = "example.com"
PUBLIC_V4 = "93.184.216.34"
SSRF_URL = "http://127.0.0.1/admin"

QUICK_CHECK = "quick-check"
QUICK_CHECK_DETAIL = "quick-check-detail"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Every hostname resolves to a public address (no real DNS)."""

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (PUBLIC_V4, port or 0),
            )
        ]

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", fake_getaddrinfo)


def submit(client, url=VALID_URL, **extra):
    return client.post(reverse(QUICK_CHECK), {"url": url}, format="json", **extra)


# --- POST: happy path --------------------------------------------------------


@pytest.mark.django_db
def test_post_creates_an_anonymous_fast_scan_and_returns_202(api_client):
    resp = submit(api_client)

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert set(resp.data) == {"id", "status"}
    assert resp.data["status"] == Scan.Status.SUBMITTED

    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.owner is None
    assert scan.mode == Scan.Mode.FAST
    assert scan.status == Scan.Status.SUBMITTED
    assert scan.domain == DOMAIN
    assert scan.verdict is None and scan.score is None
    # The exposed id is the public UUID, never the integer primary key.
    assert scan.pk != resp.data["id"]


@pytest.mark.django_db
def test_post_ignores_every_field_other_than_url(api_client):
    resp = api_client.post(
        reverse(QUICK_CHECK),
        {
            "url": VALID_URL,
            "mode": "full",
            "status": "blocked",
            "verdict": "legitimate",
            "score": 0.99,
            "owner": 999,
            "id": str(uuid4()),
        },
        format="json",
    )

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert Scan.objects.count() == 1
    scan = Scan.objects.get()
    assert scan.owner is None
    assert scan.mode == Scan.Mode.FAST
    assert scan.status == Scan.Status.SUBMITTED
    assert scan.verdict is None and scan.score is None


# --- BR-02: 5 per hour per IP ------------------------------------------------


@pytest.mark.django_db
def test_the_sixth_quick_check_of_the_hour_is_429_with_retry_after(api_client):
    assert settings.QUICK_CHECK_HOURLY_LIMIT == 5  # BR-02 default
    for _ in range(settings.QUICK_CHECK_HOURLY_LIMIT):
        assert submit(api_client).status_code == http_status.HTTP_202_ACCEPTED

    resp = submit(api_client)

    assert resp.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert resp.has_header("Retry-After")
    assert int(resp["Retry-After"]) > 0
    assert "5" in resp.json()["detail"]
    # Only the five allowed scans exist: the refused request created none.
    assert Scan.objects.count() == settings.QUICK_CHECK_HOURLY_LIMIT


@pytest.mark.django_db
def test_a_forged_x_forwarded_for_never_buys_a_new_budget(api_client):
    limit = settings.QUICK_CHECK_HOURLY_LIMIT
    for i in range(limit):
        resp = submit(
            api_client,
            REMOTE_ADDR="198.51.100.10",
            HTTP_X_FORWARDED_FOR=f"203.0.113.{i}",
        )
        assert resp.status_code == http_status.HTTP_202_ACCEPTED

    resp = submit(
        api_client,
        REMOTE_ADDR="198.51.100.10",
        HTTP_X_FORWARDED_FOR="203.0.113.200",
    )

    assert resp.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    # Another source IP keeps its own budget (the limit is per IP).
    assert submit(api_client, REMOTE_ADDR="198.51.100.11").status_code == 202


@pytest.mark.django_db
def test_a_refused_url_still_consumes_one_unit_of_the_budget(api_client):
    for _ in range(settings.QUICK_CHECK_HOURLY_LIMIT):
        resp = submit(api_client, SSRF_URL)
        assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
        assert resp.json()["code"] == "forbidden_address"

    resp = submit(api_client, SSRF_URL)

    assert resp.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert Scan.objects.count() == 0  # no scan, no audit entry, no task


# --- BR-07 on the anonymous endpoint ----------------------------------------


@pytest.mark.django_db
def test_an_ssrf_url_is_400_and_creates_no_scan(api_client):
    resp = submit(api_client, SSRF_URL)

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    body = resp.json()
    assert body["code"] == "forbidden_address"
    assert body["detail"]  # human message, never a resolver detail
    assert Scan.objects.count() == 0
    assert AuditLog.objects.count() == 0


# --- GET /api/quick-check/{uuid}/ -------------------------------------------


@pytest.mark.django_db
def test_the_detail_exposes_only_status_verdict_score_and_finished_at(api_client):
    resp = submit(api_client)
    detail = api_client.get(reverse(QUICK_CHECK_DETAIL, args=[resp.data["id"]]))

    assert detail.status_code == http_status.HTTP_200_OK
    assert set(detail.data) == {"status", "verdict", "score", "finished_at"}
    assert "url" not in detail.data and "id" not in detail.data
    assert detail.data["status"] == Scan.Status.SUBMITTED

    # A finished anonymous scan exposes its verdict and score.
    Scan.objects.create(
        owner=None,
        url=SECRET_URL,
        domain=DOMAIN,
        mode=Scan.Mode.FAST,
        status=Scan.Status.DETECTED,
        verdict="phishing",
        score=0.93,
        finished_at=timezone.now(),
    )
    done = Scan.objects.get(status=Scan.Status.DETECTED)
    detail = api_client.get(reverse(QUICK_CHECK_DETAIL, args=[done.public_id]))
    assert detail.status_code == http_status.HTTP_200_OK
    assert detail.data["verdict"] == "phishing"
    assert detail.data["score"] == pytest.approx(0.93)
    assert detail.data["finished_at"] is not None


@pytest.mark.django_db
def test_a_users_scan_is_never_readable_through_the_quick_check(api_client, viewer):
    # Worst case: an owned scan in FAST mode must still be invisible.
    scan = Scan.objects.create(
        owner=viewer, url=VALID_URL, domain=DOMAIN, mode=Scan.Mode.FAST
    )

    resp = api_client.get(reverse(QUICK_CHECK_DETAIL, args=[scan.public_id]))

    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_an_unknown_or_malformed_uuid_is_404(api_client):
    resp = api_client.get(reverse(QUICK_CHECK_DETAIL, args=[uuid4()]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND

    resp = api_client.get("/api/quick-check/not-a-uuid/")
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_the_detail_endpoint_is_throttled_at_60_per_minute(api_client):
    resp = submit(api_client)
    url = reverse(QUICK_CHECK_DETAIL, args=[resp.data["id"]])

    for _ in range(60):
        assert api_client.get(url).status_code == http_status.HTTP_200_OK

    assert (
        api_client.get(url).status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    )


# --- audit -------------------------------------------------------------------


@pytest.mark.django_db
def test_the_audit_entry_keeps_the_domain_and_the_ip_but_never_the_url(api_client):
    submit(api_client, SECRET_URL)

    entry = AuditLog.objects.get(action=AuditLog.Action.QUICK_CHECK_CREATED)
    assert entry.user is None
    assert entry.ip_address == "127.0.0.1"
    assert entry.metadata == {"domain": DOMAIN}
    assert "secret-token" not in str(entry.metadata)
    assert "secret-token" not in entry.target_repr
    assert entry.target_id  # the public UUID, not the integer pk
    assert entry.target_id != str(Scan.objects.get().pk)
