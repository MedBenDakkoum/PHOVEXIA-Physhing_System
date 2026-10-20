"""
Step 7 API tests - scans endpoints (US12, US13, US14, US15, US16 / BR-01, BR-07).

DNS is ALWAYS mocked: no test touches the network. The suite runs unchanged
on SQLite and PostgreSQL (see docs/HANDOFF.md for the exact commands).

Requirement tags: US12 (submit), US13 (URL validation), US14 (quota),
US15 (async run), US16 (follow-up), BR-01, BR-07, ISO-6.1, ISO-6.6.
"""
import json
import socket
import time
from unittest import mock
from uuid import uuid4

import pytest
from django.conf import settings
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status as http_status

from audit.models import AuditLog
from scans.models import Scan
from scans.services import url_validation
from scans.services.quota import get_quota_status

PUBLIC_V4 = "93.184.216.34"
VALID_URL = "https://example.com/login?user=1"
DOMAIN = "example.com"

SCAN_LIST = "scan-list"
SCAN_QUOTA = "scan-quota"
SCAN_DETAIL = "scan-detail"


def install_dns(monkeypatch, mapping, default=PUBLIC_V4):
    """Fake resolver: mapping[host] when present, else `default`.

    mapping[host] = None means "this host does not resolve".
    """

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        addresses = mapping.get(host, [default])
        if addresses is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        out = []
        for addr in addresses:
            if ":" in addr:
                out.append(
                    (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, 0, 0, 0))
                )
            else:
                out.append(
                    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))
                )
        return out

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Default: every hostname resolves to a public address (no real DNS)."""
    install_dns(monkeypatch, {})


def make_scan(owner, url=VALID_URL, domain=DOMAIN):
    return Scan.objects.create(owner=owner, url=url, domain=domain, mode="fast")


# --- permission matrix (401 / roles allowed) --------------------------------


@pytest.mark.django_db
def test_anonymous_post_is_401_and_creates_no_scan(api_client):
    resp = api_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED
    assert Scan.objects.count() == 0
    assert AuditLog.objects.count() == 0


@pytest.mark.django_db
def test_anonymous_list_is_401(api_client):
    resp = api_client.get(reverse(SCAN_LIST))
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_anonymous_quota_is_401(api_client):
    resp = api_client.get(reverse(SCAN_QUOTA))
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_anonymous_detail_is_401(api_client, viewer):
    scan = make_scan(viewer)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
@pytest.mark.parametrize("role", ["end_user", "analyst", "admin"])
def test_every_authenticated_role_can_submit(make_user, api_client, role):
    user = make_user(email=f"{role}@example.com", role=role)
    api_client.force_authenticate(user)
    resp = api_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert Scan.objects.count() == 1
    assert Scan.objects.get().owner == user


# --- POST /api/scans/ : 202 payload and server-side fields ------------------


@pytest.mark.django_db
def test_post_returns_202_with_scan_and_quota(auth_client, viewer):
    resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert set(resp.data) == {"id", "url", "status", "created_at", "quota"}
    assert set(resp.data["quota"]) == {"limit", "used", "remaining", "reset_at"}
    assert resp.data["url"] == VALID_URL
    assert resp.data["status"] == Scan.Status.SUBMITTED
    assert resp.data["quota"]["limit"] == settings.SCAN_DAILY_QUOTA
    assert resp.data["quota"]["used"] == 1
    assert resp.data["quota"]["remaining"] == settings.SCAN_DAILY_QUOTA - 1

    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.owner == viewer
    assert scan.domain == DOMAIN
    assert scan.mode == Scan.Mode.FULL
    assert scan.status == Scan.Status.SUBMITTED
    assert scan.verdict is None
    assert scan.score is None
    # Step 8a: the exposed id is the public UUID, never the integer pk.
    assert str(scan.public_id) == resp.data["id"]
    assert scan.pk != resp.data["id"]


@pytest.mark.django_db
def test_client_cannot_set_protected_fields(auth_client, viewer):
    """mode/status/verdict/score/owner sent by the client are ignored (US12)."""
    resp = auth_client.post(
        reverse(SCAN_LIST),
        {
            "url": VALID_URL,
            "id": 999,
            "mode": "fast",
            "status": Scan.Status.BLOCKED,
            "verdict": "phishing",
            "score": 0.99,
            "owner": 424_242,
            "error_message": "client says so",
        },
        format="json",
    )

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.mode == Scan.Mode.FULL
    assert scan.status == Scan.Status.SUBMITTED
    assert scan.verdict is None
    assert scan.score is None
    assert scan.owner == viewer
    assert scan.error_message is None
    assert resp.data["status"] == Scan.Status.SUBMITTED


# --- invalid body ------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body",
    [
        {},
        {"url": None},
        {"url": ["https://example.com"]},
        {"url": {"host": "example.com"}},
        {"url": True},
    ],
    ids=["missing", "null", "list", "object", "bool"],
)
def test_invalid_body_is_400_with_a_machine_readable_code(auth_client, body):
    resp = auth_client.post(reverse(SCAN_LIST), body, format="json")
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "invalid_request"
    assert "detail" in resp.data
    assert "url" in resp.data["errors"]
    assert Scan.objects.count() == 0


@pytest.mark.django_db
def test_huge_url_is_400_too_long_and_creates_no_scan(auth_client, viewer):
    resp = auth_client.post(
        reverse(SCAN_LIST), {"url": "https://example.com/" + "a" * 3000}, format="json"
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "too_long"
    assert Scan.objects.count() == 0
    assert get_quota_status(viewer).used == 0


# --- SSRF / BR-07 refusal ----------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "url,expected_code",
    [
        ("http://127.0.0.1/admin", "forbidden_address"),
        ("http://169.254.169.254/latest/meta-data/", "forbidden_address"),
        ("http://10.0.0.5/", "forbidden_address"),
        ("http://192.168.1.10/", "forbidden_address"),
        ("http://100.64.0.1/", "forbidden_address"),
        ("http://[::1]/", "forbidden_address"),
        ("http://localhost/admin", "blocked_host"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("ftp://example.com/", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("http://user:pass@example.com/", "credentials_not_allowed"),
        ("   ", "empty"),
        ("http:///nohost", "empty_host"),
    ],
    ids=[
        "loopback",
        "metadata",
        "rfc1918",
        "rfc1918-b",
        "cgnat",
        "ipv6-loopback",
        "localhost",
        "file-scheme",
        "ftp-scheme",
        "js-scheme",
        "credentials",
        "blank",
        "no-host",
    ],
)
def test_forbidden_url_is_400_without_creating_a_scan(
    auth_client, viewer, url, expected_code
):
    resp = auth_client.post(reverse(SCAN_LIST), {"url": url}, format="json")

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == expected_code
    assert isinstance(resp.data["detail"], str) and resp.data["detail"]
    assert Scan.objects.count() == 0
    assert get_quota_status(viewer).used == 0
    # The message never leaks internal details.
    assert "Traceback" not in resp.data["detail"]
    assert "socket" not in resp.data["detail"].lower()


@pytest.mark.django_db
def test_hostname_resolving_to_a_private_address_is_refused(
    auth_client, monkeypatch
):
    install_dns(monkeypatch, {"internal.corp": ["192.168.0.10"]})
    resp = auth_client.post(
        reverse(SCAN_LIST), {"url": "http://internal.corp/login"}, format="json"
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "forbidden_address"
    assert "192.168" not in resp.data["detail"]
    assert Scan.objects.count() == 0


@pytest.mark.django_db
def test_dns_failure_is_400_dns_failure(auth_client, monkeypatch):
    install_dns(monkeypatch, {"nowhere.example": None})
    resp = auth_client.post(
        reverse(SCAN_LIST), {"url": "http://nowhere.example/"}, format="json"
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "dns_failure"
    assert Scan.objects.count() == 0


@pytest.mark.django_db
def test_slow_dns_resolution_is_400_dns_timeout(auth_client, monkeypatch):
    """US13/US16: the API must never hang on a slow resolver (3 s budget)."""

    def slow_getaddrinfo(*args, **kwargs):
        time.sleep(0.3)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_V4, 0))
        ]

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", slow_getaddrinfo)
    monkeypatch.setattr(url_validation, "DNS_TIMEOUT_SECONDS", 0.05)

    started = time.monotonic()
    resp = auth_client.post(
        reverse(SCAN_LIST), {"url": "https://slow.example.com/"}, format="json"
    )
    elapsed = time.monotonic() - started

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "dns_timeout"
    assert elapsed < 0.3, "the request waited for the slow resolver"
    assert Scan.objects.count() == 0


# --- quota BR-01 : 429 -------------------------------------------------------


@pytest.mark.django_db
def test_quota_exceeded_is_429_with_retry_after_and_no_side_effect(
    auth_client, viewer, settings, django_capture_on_commit_callbacks
):
    settings.SCAN_DAILY_QUOTA = 1
    make_scan(viewer, url="https://example.com/already", domain=DOMAIN)

    with (
        mock.patch("scans.tasks.run_scan.delay") as delay,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")

    assert resp.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in resp
    assert int(resp["Retry-After"]) >= 1
    assert resp.data["limit"] == 1
    assert resp.data["used"] == 1
    assert resp.data["detail"]
    assert resp.data["reset_at"]

    assert Scan.objects.count() == 1  # no scan created by the refusal
    assert get_quota_status(viewer).used == 1  # no quota consumed
    delay.assert_not_called()  # nothing enqueued
    assert AuditLog.objects.filter(action="scan_created").count() == 0


@pytest.mark.django_db
def test_post_holds_the_user_row_lock(auth_client, viewer):
    """BR-01 race safety: SELECT ... FOR UPDATE inside the POST transaction."""
    with CaptureQueriesContext(connection) as ctx:
        resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED

    sql = " ".join(q["sql"] for q in ctx.captured_queries).upper()
    if connection.features.has_select_for_update:
        assert "FOR UPDATE" in sql
    else:
        # SQLite: select_for_update() is a documented no-op, no exception.
        assert "FOR UPDATE" not in sql


# --- US15 : one scan, one task ----------------------------------------------


@pytest.mark.django_db
def test_post_creates_exactly_one_scan_and_enqueues_the_task_once(
    auth_client, viewer, django_capture_on_commit_callbacks
):
    with (
        mock.patch("scans.tasks.run_scan.delay") as delay,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    scan = Scan.objects.get()
    delay.assert_called_once_with(scan.pk)


@pytest.mark.django_db
def test_post_without_commit_does_not_enqueue(auth_client, viewer):
    with mock.patch("scans.tasks.run_scan.delay") as delay:
        resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    delay.assert_not_called()


# --- US46 : audit entry ------------------------------------------------------


@pytest.mark.django_db
def test_post_writes_scan_created_audit_without_the_url_query_string(
    auth_client, viewer
):
    resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED

    entries = AuditLog.objects.filter(action="scan_created")
    assert entries.count() == 1
    entry = entries.get()
    assert entry.user_id == viewer.pk
    assert entry.target_type == "scan"
    assert entry.target_id == str(resp.data["id"])
    assert entry.metadata == {"domain": DOMAIN}
    assert entry.action == "scan_created"

    # domain only: the full URL and its query string never reach the audit log
    blob = json.dumps(entry.metadata) + entry.target_repr + entry.user_email
    assert "user=1" not in blob
    assert "https://" not in blob
    assert "?" not in entry.target_repr
    assert VALID_URL not in blob


# --- GET /api/scans/ : isolation, order, pagination --------------------------


@pytest.mark.django_db
def test_list_returns_only_my_scans_newest_first(make_user, api_client):
    me = make_user(email="me@example.com")
    other = make_user(email="other@example.com")
    mine = [make_scan(me, url=f"https://example.com/{i}") for i in range(2)]
    foreign = make_scan(other, url="https://example.com/foreign")

    api_client.force_authenticate(me)
    resp = api_client.get(reverse(SCAN_LIST))

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 2
    ids = [item["id"] for item in resp.data["results"]]
    assert set(ids) == {str(s.public_id) for s in mine}
    assert str(foreign.public_id) not in ids
    # newest first (UUIDs themselves are not ordered: creation order is)
    assert ids == [str(s.public_id) for s in reversed(mine)]


@pytest.mark.django_db
def test_list_shows_only_my_scans_even_for_an_analyst(make_user, api_client):
    analyst = make_user(email="a@example.com", role="analyst")
    other = make_user(email="b@example.com")
    mine = make_scan(analyst, url="https://example.com/mine")
    make_scan(other, url="https://example.com/theirs")

    api_client.force_authenticate(analyst)
    resp = api_client.get(reverse(SCAN_LIST))

    assert resp.data["count"] == 1
    assert resp.data["results"][0]["id"] == str(mine.public_id)


@pytest.mark.django_db
def test_list_item_fields_are_read_only_projection(auth_client, viewer):
    make_scan(viewer)
    resp = auth_client.get(reverse(SCAN_LIST))
    item = resp.data["results"][0]
    assert set(item) == {
        "id",
        "url",
        "domain",
        "mode",
        "status",
        "verdict",
        "score",
        "created_at",
        "finished_at",
        # Step 10 (US31/US34): owner-facing review flags, never the analyst.
        "has_report",
        "report_status",
        "reviewed_at",
    }
    assert "owner" not in item
    assert "reviewed_by" not in item
    assert "review_comment" not in item
    assert "notes" not in item


@pytest.mark.django_db
def test_list_is_paginated(auth_client, viewer):
    for i in range(25):
        make_scan(viewer, url=f"https://example.com/{i}")

    page1 = auth_client.get(reverse(SCAN_LIST))
    assert page1.status_code == http_status.HTTP_200_OK
    assert page1.data["count"] == 25
    assert len(page1.data["results"]) == 20
    assert page1.data["next"]
    assert page1.data["previous"] is None

    page2 = auth_client.get(reverse(SCAN_LIST), {"page": 2})
    assert len(page2.data["results"]) == 5
    assert page2.data["previous"]

    small = auth_client.get(reverse(SCAN_LIST), {"page_size": 7})
    assert len(small.data["results"]) == 7


# --- GET /api/scans/{uuid}/ --------------------------------------------------


@pytest.mark.django_db
def test_detail_owner_can_read_his_scan(auth_client, viewer):
    scan = make_scan(viewer)
    resp = auth_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_200_OK
    assert set(resp.data) == {
        "id",
        "url",
        "domain",
        "mode",
        "status",
        "verdict",
        "score",
        "created_at",
        "finished_at",
        # Step 10 (US31/US34): owner-facing review flags, never the analyst.
        "has_report",
        "report_status",
        "reviewed_at",
    }
    assert resp.data["id"] == str(scan.public_id)
    assert resp.data["url"] == VALID_URL
    assert resp.data["has_report"] is False
    assert resp.data["report_status"] is None
    assert resp.data["reviewed_at"] is None


@pytest.mark.django_db
def test_detail_of_another_end_user_is_404_not_403(make_user, api_client):
    owner = make_user(email="owner@example.com")
    stranger = make_user(email="stranger@example.com")
    scan = make_scan(owner)

    api_client.force_authenticate(stranger)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))

    assert resp.status_code == http_status.HTTP_404_NOT_FOUND
    assert resp.status_code != http_status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_detail_is_readable_by_analysts_and_admins(make_user, api_client, role):
    owner = make_user(email="owner@example.com")
    privileged = make_user(email=f"{role}@example.com", role=role)
    scan = make_scan(owner)

    api_client.force_authenticate(privileged)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["id"] == str(scan.public_id)


@pytest.mark.django_db
def test_detail_unknown_id_is_404_for_the_owner(auth_client, viewer):
    resp = auth_client.get(reverse(SCAN_DETAIL, args=[str(uuid4())]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_detail_of_an_existing_but_invisible_scan_is_404(make_user, api_client):
    owner = make_user(email="owner@example.com")
    stranger = make_user(email="stranger@example.com")
    scan = make_scan(owner)
    api_client.force_authenticate(stranger)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


# --- GET /api/scans/quota/ ---------------------------------------------------


@pytest.mark.django_db
def test_quota_endpoint_reports_my_quota(auth_client, viewer, make_user):
    resp = auth_client.get(reverse(SCAN_QUOTA))
    assert resp.status_code == http_status.HTTP_200_OK
    assert set(resp.data) == {"limit", "used", "remaining", "reset_at"}
    assert resp.data["limit"] == settings.SCAN_DAILY_QUOTA
    assert resp.data["used"] == 0
    assert resp.data["remaining"] == settings.SCAN_DAILY_QUOTA

    auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")

    resp = auth_client.get(reverse(SCAN_QUOTA))
    assert resp.data["used"] == 1
    assert resp.data["remaining"] == settings.SCAN_DAILY_QUOTA - 1
    assert resp.data["reset_at"]


@pytest.mark.django_db
def test_quota_endpoint_does_not_leak_other_users_quota(make_user, api_client):
    me = make_user(email="me@example.com")
    other = make_user(email="other@example.com")
    for _ in range(3):
        make_scan(other)

    api_client.force_authenticate(me)
    resp = api_client.get(reverse(SCAN_QUOTA))
    assert resp.data["used"] == 0
    assert resp.data["remaining"] == settings.SCAN_DAILY_QUOTA
