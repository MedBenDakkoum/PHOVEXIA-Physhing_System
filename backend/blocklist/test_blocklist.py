"""Step 11 tests - blocklist & protected brands (US38-US41, US55 / BR-03, BR-12).

Essential set: happy path, 401/403/404, main business rules, one security
edge case (CSV injection). Tags: BR-03, BR-12, US38, US39, US40, US41, US55.
"""
from __future__ import annotations

import csv
import io
import socket
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.urls import reverse
from rest_framework import status

from audit.models import AuditLog
from blocklist.models import BlocklistEntry, ProtectedBrand
from blocklist.services import (
    InvalidDomain,
    find_lookalike,
    is_blocked,
    normalize_domain,
)
from scans.models import Scan
from scans.services import url_validation

User = get_user_model()

PUBLIC_V4 = "93.184.216.34"

BLOCKLIST = "blocklist"
BLOCKLIST_EXPORT = "blocklist-export"
BLOCKLIST_DELETE = "blocklist-delete"
BRAND_LIST = "brand-list"
BRAND_DETAIL = "brand-detail"
SCAN_CREATE = "scan-list"
QUICK_CHECK = "quick-check"
REVIEW_DECISION = "review-decision"
REVIEW_DETAIL = "review-detail"


def _analyst_client(api_client, analyst):
    api_client.force_authenticate(analyst)
    return api_client


@pytest.fixture
def analyst_client(api_client, analyst):
    return _analyst_client(api_client, analyst)


def _add(client, domain="evil.com", reason="manual", note="", **extra):
    body = {"domain": domain, "reason": reason, "note": note}
    body.update(extra)
    return client.post(reverse(BLOCKLIST), body, format="json")


def _make_scan(owner, domain="example.com", url="https://example.com/login"):
    return Scan.objects.create(
        owner=owner, url=url, domain=domain, mode=Scan.Mode.FULL,
        status=Scan.Status.SUBMITTED,
    )


# --- BR-03: duplicate active entry -> 409 -----------------------------------

@pytest.mark.django_db
def test_duplicate_active_domain_is_409_and_only_one_row(analyst_client, analyst):
    first = _add(analyst_client, domain="Evil.COM", reason="manual")
    assert first.status_code == status.HTTP_201_CREATED
    # Normalization: stored lowercase, no trailing dot.
    assert first.data["domain"] == "evil.com"

    second = _add(analyst_client, domain="evil.com", reason="confirmed_phishing")
    assert second.status_code == status.HTTP_409_CONFLICT
    assert second.data["code"] == "already_blocked"
    assert BlocklistEntry.objects.filter(domain="evil.com", is_active=True).count() == 1

    # BR-03 database backstop: a second ACTIVE row is refused by the constraint.
    with pytest.raises(IntegrityError), transaction.atomic():
        BlocklistEntry.objects.create(
            domain="evil.com", reason="manual", added_by=analyst
        )


@pytest.mark.django_db
def test_removing_then_re_adding_the_same_domain_is_allowed(analyst_client, analyst):
    entry_id = _add(analyst_client, domain="second.com").data["id"]
    resp = analyst_client.delete(
        reverse(BLOCKLIST_DELETE, args=[entry_id]), {"reason": "false positive"},
        format="json",
    )
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    again = _add(analyst_client, domain="second.com")
    assert again.status_code == status.HTTP_201_CREATED


# --- BR-12: removal requires a reason ---------------------------------------

@pytest.mark.django_db
def test_removal_without_reason_is_400_and_with_reason_soft_deletes(analyst_client):
    entry_id = _add(analyst_client, domain="gone.com").data["id"]

    bad = analyst_client.delete(
        reverse(BLOCKLIST_DELETE, args=[entry_id]), {}, format="json"
    )
    assert bad.status_code == status.HTTP_400_BAD_REQUEST
    assert BlocklistEntry.objects.get(domain="gone.com").is_active is True

    blank = analyst_client.delete(
        reverse(BLOCKLIST_DELETE, args=[entry_id]), {"reason": "   "}, format="json"
    )
    assert blank.status_code == status.HTTP_400_BAD_REQUEST

    ok = analyst_client.delete(
        reverse(BLOCKLIST_DELETE, args=[entry_id]),
        {"reason": "faux positif confirmé"},
        format="json",
    )
    assert ok.status_code == status.HTTP_204_NO_CONTENT
    entry = BlocklistEntry.objects.get(domain="gone.com")
    assert entry.is_active is False
    assert entry.removal_reason == "faux positif confirmé"
    assert entry.removed_at is not None
    assert AuditLog.objects.filter(action=AuditLog.Action.BLOCKLIST_REMOVED).exists()


# --- Permissions: 401 anonymous, 403 end user, 200 analyst ------------------

@pytest.mark.django_db
def test_blocklist_requires_analyst_or_admin(api_client, viewer, analyst):
    # Anonymous: 401 (explicit permission class, never 403).
    assert api_client.get(reverse(BLOCKLIST)).status_code == status.HTTP_401_UNAUTHORIZED

    # End user: 403 on list AND create (no entry created).
    api_client.force_authenticate(viewer)
    assert api_client.get(reverse(BLOCKLIST)).status_code == status.HTTP_403_FORBIDDEN
    resp = api_client.post(
        reverse(BLOCKLIST), {"domain": "x.com", "reason": "manual"}, format="json"
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert not BlocklistEntry.objects.filter(domain="x.com").exists()

    # Analyst: 200.
    api_client.force_authenticate(analyst)
    assert api_client.get(reverse(BLOCKLIST)).status_code == status.HTTP_200_OK


# --- US41: pipeline integration ---------------------------------------------


@pytest.fixture
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


@pytest.mark.django_db
def test_subdomain_of_a_blocked_domain_is_immediate_phishing_without_a_task(
    auth_client, viewer, analyst, django_capture_on_commit_callbacks, fake_dns
):
    # Entry created through the ORM (the API path is covered by the BR-03 test).
    BlocklistEntry.objects.create(
        domain="blocked.example", reason="confirmed_phishing", added_by=analyst
    )

    with (
        mock.patch("scans.tasks.run_scan.delay") as mock_delay,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = auth_client.post(
            reverse(SCAN_CREATE), {"url": "https://sub.blocked.example/login"},
            format="json",
        )

    assert resp.status_code == status.HTTP_202_ACCEPTED
    assert resp.data["status"] == Scan.Status.DETECTED
    assert resp.data["detection_source"] == Scan.DetectionSource.BLOCKLIST
    mock_delay.assert_not_called()

    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == "phishing"
    assert scan.score == 1.0
    assert scan.detection_source == Scan.DetectionSource.BLOCKLIST
    # BR-04 audit trail still written (system actor).
    transitions = AuditLog.objects.filter(
        action=AuditLog.Action.SCAN_STATUS_CHANGED
    ).values_list("metadata", flat=True)
    assert any(t.get("to_status") == "analyzing" for t in transitions)
    assert any(t.get("to_status") == "detected" for t in transitions)


@pytest.mark.django_db
def test_non_blocked_domain_still_runs_the_model_path(
    auth_client, viewer, analyst, django_capture_on_commit_callbacks, fake_dns
):
    BlocklistEntry.objects.create(
        domain="other-blocked.tld", reason="manual", added_by=analyst
    )

    with (
        mock.patch("scans.tasks.run_scan.delay") as mock_delay,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = auth_client.post(
            reverse(SCAN_CREATE), {"url": "https://example.com/login"}, format="json"
        )

    assert resp.status_code == status.HTTP_202_ACCEPTED
    assert resp.data["status"] == Scan.Status.SUBMITTED
    assert resp.data["detection_source"] == Scan.DetectionSource.MODEL
    mock_delay.assert_called_once()


# --- US38 + review integration: add_to_blocklist on decision ----------------

@pytest.mark.django_db
def test_decision_with_add_to_blocklist_blocks_the_domain_and_the_scan(
    analyst_client, analyst, make_user, fake_dns, django_capture_on_commit_callbacks
):
    owner = make_user(email="owner-bl@example.com")
    scan = _make_scan(owner, domain="confirm-me.com", url="https://confirm-me.com/a")
    scan.status = Scan.Status.UNDER_REVIEW
    scan.verdict = "uncertain"
    scan.score = 0.55
    scan.save(update_fields=["status", "verdict", "score"])

    resp = analyst_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "confirm_phishing", "add_to_blocklist": True},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK

    scan.refresh_from_db()
    assert scan.status == Scan.Status.BLOCKED
    entry = BlocklistEntry.objects.get(domain="confirm-me.com")
    assert entry.is_active is True
    assert entry.reason == BlocklistEntry.Reason.CONFIRMED_PHISHING
    assert entry.added_by == analyst
    assert entry.source_scan == scan

    # A second submission of the same domain is now an immediate verdict.
    with mock.patch("scans.tasks.run_scan.delay") as mock_delay:
        second = analyst_client.post(
            reverse(SCAN_CREATE), {"url": "https://confirm-me.com/b"}, format="json"
        )
    assert second.data["detection_source"] == Scan.DetectionSource.BLOCKLIST
    mock_delay.assert_not_called()


@pytest.mark.django_db
def test_add_to_blocklist_with_false_positive_is_400(analyst_client):
    owner = User.objects.create_user(email="o2@example.com", password="x", role="end_user")
    scan = _make_scan(owner, domain="fp.com")
    scan.status = Scan.Status.UNDER_REVIEW
    scan.save(update_fields=["status"])

    resp = analyst_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "false_positive", "add_to_blocklist": True},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert not BlocklistEntry.objects.filter(domain="fp.com").exists()


# --- US40: CSV export + injection protection --------------------------------

@pytest.mark.django_db
def test_csv_export_lists_active_entries_and_neutralizes_formulas(
    analyst_client, analyst
):
    BlocklistEntry.objects.create(
        domain="safe.com", reason="manual", added_by=analyst, note="plain"
    )
    BlocklistEntry.objects.create(
        domain="evil.com", reason="campaign", added_by=analyst,
        note="=cmd|'/c calc'!A0",
    )
    BlocklistEntry.objects.create(
        domain="removed.com", reason="manual", added_by=analyst, is_active=False
    )

    resp = analyst_client.get(reverse(BLOCKLIST_EXPORT))
    assert resp.status_code == status.HTTP_200_OK
    assert resp["Content-Type"].startswith("text/csv")
    body = resp.getvalue().decode("utf-8")
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[0] == ["domain", "reason", "note", "added_by", "created_at"]
    domains = [r[0] for r in rows[1:]]
    assert "safe.com" in domains and "evil.com" in domains
    assert "removed.com" not in domains  # active entries only
    # Security edge case: the formula cell is prefixed with an apostrophe.
    note_row = next(r for r in rows[1:] if r[0] == "evil.com")
    assert note_row[2].startswith("'=cmd")
    assert AuditLog.objects.filter(action=AuditLog.Action.BLOCKLIST_EXPORTED).exists()


# --- US55: brands are Admin only --------------------------------------------

@pytest.mark.django_db
def test_brands_are_admin_only(api_client, viewer, analyst, admin):
    # Anonymous: 401.
    assert api_client.get(reverse(BRAND_LIST)).status_code == status.HTTP_401_UNAUTHORIZED

    # End user: 403.
    api_client.force_authenticate(viewer)
    assert api_client.get(reverse(BRAND_LIST)).status_code == status.HTTP_403_FORBIDDEN

    # Analyst: 403 on list AND create.
    api_client.force_authenticate(analyst)
    assert api_client.get(reverse(BRAND_LIST)).status_code == status.HTTP_403_FORBIDDEN
    resp = api_client.post(
        reverse(BRAND_LIST), {"name": "X", "domain": "x.com"}, format="json"
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN

    # Admin: 201 then 200 on detail.
    api_client.force_authenticate(admin)
    created = api_client.post(
        reverse(BRAND_LIST), {"name": "PayPal", "domain": "PayPal.com"}, format="json"
    )
    assert created.status_code == status.HTTP_201_CREATED
    assert created.data["domain"] == "paypal.com"
    detail = api_client.get(reverse(BRAND_DETAIL, args=[created.data["id"]]))
    assert detail.status_code == status.HTTP_200_OK
    assert detail.data["name"] == "PayPal"


@pytest.mark.django_db
def test_seed_brands_loads_the_three_brands(admin):
    call_command("seed_brands")
    domains = set(ProtectedBrand.objects.values_list("domain", flat=True))
    assert domains == {"paypal.com", "microsoft.com", "google.com"}
    # Idempotent.
    call_command("seed_brands")
    assert ProtectedBrand.objects.count() == 3


# --- US19 groundwork: lookalike service -------------------------------------

@pytest.mark.django_db
def test_find_lookalike_hits_homoglyphs_and_ignores_the_real_brand(admin):
    ProtectedBrand.objects.create(name="PayPal", domain="paypal.com", created_by=admin)
    ProtectedBrand.objects.create(
        name="Microsoft", domain="microsoft.com", created_by=admin
    )

    hit1 = find_lookalike("paypa1.com")
    assert hit1 is not None
    assert hit1.brand.domain == "paypal.com"
    assert hit1.distance <= 2

    hit2 = find_lookalike("rnicrosoft.com")
    assert hit2 is not None
    assert hit2.brand.domain == "microsoft.com"

    # Exact brand domain and its subdomain are NOT lookalikes.
    assert find_lookalike("paypal.com") is None
    assert find_lookalike("www.paypal.com") is None
    assert find_lookalike("login.microsoft.com") is None


@pytest.mark.django_db
def test_normalize_domain_refuses_ip_and_invalid_hostnames():
    assert normalize_domain(" Example.COM. ") == "example.com"
    for bad in ("", "   ", "127.0.0.1", "10.0.0.1", "localhost", "http://x.com",
                "a b.com", "-bad.com"):
        with pytest.raises(InvalidDomain):
            normalize_domain(bad)
    # is_blocked never matches a malformed value.
    assert is_blocked("not a domain") is None
