"""
Step 10 tests - human review workflow (US31, US33-US36, US57 / BR-04, BR-05).

DNS is ALWAYS mocked: no test touches the network. The suite runs unchanged
on SQLite and PostgreSQL (see docs/HANDOFF.md for the exact commands).

Essential cases only: the happy path of each endpoint, the permission matrix
(401 anonymous / 403 insufficient role / 404 owner isolation), the two
blocking business rules (BR-05 one report per scan, BR-04 decision only from
`under_review`), one security edge case (SSRF URL refused on rescan) and the
immutable audit entries (BR-06).
"""
import socket
from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from rest_framework import status as http_status

from audit.models import AuditLog
from reviews.models import AnalystNote, Notification, Report
from scans.models import Scan
from scans.services import url_validation

VALID_URL = "https://example.com/login?user=1"
DOMAIN = "example.com"
PUBLIC_V4 = "93.184.216.34"

SCAN_REPORT = "scan-report"
SCAN_DETAIL = "scan-detail"
REVIEW_QUEUE = "review-queue"
REVIEW_DETAIL = "review-detail"
REVIEW_DECISION = "review-decision"
REVIEW_NOTE = "review-note"
REVIEW_RESCAN = "review-rescan"
NOTIFICATION_LIST = "notification-list"
NOTIFICATION_READ = "notification-read"


def install_dns(monkeypatch, mapping):
    """Fake resolver: mapping[host] when present, else a public IPv4."""

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        addresses = mapping.get(host, [PUBLIC_V4])
        if addresses is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))
            for addr in addresses
        ]

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Every hostname resolves to a public address (no real DNS)."""
    install_dns(monkeypatch, {})


def make_scan(owner, *, status=Scan.Status.DETECTED, url=VALID_URL, **fields):
    return Scan.objects.create(
        owner=owner, url=url, domain=DOMAIN, mode="fast", status=status, **fields
    )


def post_report(client, scan, label="safe", comment="le site est réel"):
    return client.post(
        reverse(SCAN_REPORT, args=[scan.public_id]),
        {"claimed_label": label, "comment": comment},
        format="json",
    )


def make_report(scan, reporter, label="safe"):
    return Report.objects.create(scan=scan, reporter=reporter, claimed_label=label)


# --- US31 / BR-05: the owner reports a wrong verdict -------------------------


@pytest.mark.django_db
def test_report_by_owner_is_201_moves_scan_to_under_review_and_writes_audit(
    auth_client, viewer
):
    scan = make_scan(viewer)

    resp = post_report(auth_client, scan)

    assert resp.status_code == http_status.HTTP_201_CREATED
    assert resp.data["scan"] == str(scan.public_id)
    assert resp.data["claimed_label"] == "safe"
    assert resp.data["comment"] == "le site est réel"
    assert resp.data["status"] == "open"

    scan.refresh_from_db()
    assert scan.status == Scan.Status.UNDER_REVIEW
    assert Report.objects.filter(scan=scan, reporter=viewer).count() == 1

    # BR-06: the report action and the BR-04 transition are both audited, and
    # the audit target is the public UUID (never the integer pk).
    entry = AuditLog.objects.get(action=AuditLog.Action.REPORT_CREATED)
    assert entry.user == viewer
    assert entry.target_id == str(scan.public_id)
    assert entry.metadata == {"claimed_label": "safe"}
    assert AuditLog.objects.filter(
        action=AuditLog.Action.SCAN_STATUS_CHANGED,
        metadata__transition="detected_under_review",
    ).exists()

    # Owner-facing projection now exposes the report (US31).
    detail = auth_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert detail.data["has_report"] is True
    assert detail.data["report_status"] == "open"


@pytest.mark.django_db
def test_second_report_is_409_and_the_database_blocks_a_second_row(
    auth_client, viewer
):
    scan = make_scan(viewer)
    assert post_report(auth_client, scan).status_code == http_status.HTTP_201_CREATED

    resp = post_report(auth_client, scan, label="phishing")

    assert resp.status_code == http_status.HTTP_409_CONFLICT
    assert resp.data["code"] == "already_reported"
    assert Report.objects.count() == 1

    # BR-05 backstop: even a direct ORM insert is refused by the constraint.
    with pytest.raises(IntegrityError), transaction.atomic():
        Report.objects.create(scan=scan, reporter=viewer, claimed_label="phishing")


@pytest.mark.django_db
def test_report_of_a_foreign_scan_is_404_and_anonymous_is_401(api_client, make_user):
    owner = make_user(email="owner@example.com")
    stranger = make_user(email="stranger@example.com")
    scan = make_scan(owner)

    resp = api_client.post(
        reverse(SCAN_REPORT, args=[scan.public_id]),
        {"claimed_label": "safe"},
        format="json",
    )
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED

    api_client.force_authenticate(stranger)
    resp = post_report(api_client, scan)

    assert resp.status_code == http_status.HTTP_404_NOT_FOUND
    assert resp.status_code != http_status.HTTP_403_FORBIDDEN
    assert not Report.objects.exists()
    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED


@pytest.mark.django_db
def test_report_rejects_a_bad_body_and_a_non_reportable_status(auth_client, viewer):
    scan = make_scan(viewer)
    resp = auth_client.post(
        reverse(SCAN_REPORT, args=[scan.public_id]),
        {"claimed_label": "maybe"},
        format="json",
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "invalid_request"
    assert not Report.objects.exists()

    failed = make_scan(viewer, status=Scan.Status.FAILED, url="https://example.com/other")
    resp = post_report(auth_client, failed)

    assert resp.status_code == http_status.HTTP_409_CONFLICT
    assert resp.data["code"] == "not_reportable"
    failed.refresh_from_db()
    assert failed.status == Scan.Status.FAILED


# --- US33: the analyst review queue -----------------------------------------


@pytest.mark.django_db
def test_queue_is_401_for_anonymous_and_403_for_end_user(api_client, viewer):
    assert api_client.get(reverse(REVIEW_QUEUE)).status_code == (
        http_status.HTTP_401_UNAUTHORIZED
    )

    api_client.force_authenticate(viewer)
    assert api_client.get(reverse(REVIEW_QUEUE)).status_code == (
        http_status.HTTP_403_FORBIDDEN
    )


@pytest.mark.django_db
def test_queue_lists_only_under_review_scans_oldest_first(analyst, api_client):
    older = make_scan(analyst, status=Scan.Status.UNDER_REVIEW, url="https://example.com/older")
    newer = make_scan(analyst, status=Scan.Status.UNDER_REVIEW, url="https://example.com/newer")
    Scan.objects.filter(pk=older.pk).update(created_at=older.created_at - timedelta(days=1))
    skipped = make_scan(analyst, status=Scan.Status.DETECTED, url="https://example.com/skipped")

    api_client.force_authenticate(analyst)
    resp = api_client.get(reverse(REVIEW_QUEUE))

    assert resp.status_code == http_status.HTTP_200_OK
    ids = [row["id"] for row in resp.data["results"]]
    assert ids == [str(older.public_id), str(newer.public_id)]
    assert str(skipped.public_id) not in ids
    row = resp.data["results"][0]
    assert row["owner_email"] == analyst.email
    assert row["reported"] is False
    assert row["claimed_label"] is None


@pytest.mark.django_db
def test_queue_source_filter_and_uncertainty_ordering(analyst, viewer, api_client):
    reported = make_scan(viewer, status=Scan.Status.UNDER_REVIEW, url="https://example.com/reported")
    make_report(reported, viewer)
    unsure = make_scan(
        viewer,
        status=Scan.Status.UNDER_REVIEW,
        url="https://example.com/unsure",
        score=0.55,
    )
    urgent = make_scan(
        viewer,
        status=Scan.Status.UNDER_REVIEW,
        url="https://example.com/urgent",
        score=0.69,
    )
    api_client.force_authenticate(analyst)

    resp = api_client.get(reverse(REVIEW_QUEUE), {"source": "reported"})
    assert [row["id"] for row in resp.data["results"]] == [str(reported.public_id)]
    assert resp.data["results"][0]["claimed_label"] == "safe"

    resp = api_client.get(reverse(REVIEW_QUEUE), {"source": "uncertain"})
    uncertain_ids = [row["id"] for row in resp.data["results"]]
    assert str(reported.public_id) not in uncertain_ids
    assert str(urgent.public_id) in uncertain_ids

    # Ascending uncertainty = closest to a decision threshold first (0.69
    # before 0.55), not the created_at order.
    resp = api_client.get(reverse(REVIEW_QUEUE), {"ordering": "uncertainty"})
    ids = [row["id"] for row in resp.data["results"]]
    assert ids.index(str(urgent.public_id)) < ids.index(str(unsure.public_id))


# --- US33 / US35: the case detail, notes included, analysts only -------------


@pytest.mark.django_db
def test_review_detail_is_analyst_only_and_returns_report_and_notes(
    analyst, viewer, api_client
):
    scan = make_scan(viewer, status=Scan.Status.UNDER_REVIEW)
    reported = make_report(scan, viewer)
    AnalystNote.objects.create(scan=scan, author=analyst, text="score 0.62, capture floue")

    assert api_client.get(reverse(REVIEW_DETAIL, args=[scan.public_id])).status_code == (
        http_status.HTTP_401_UNAUTHORIZED
    )
    api_client.force_authenticate(viewer)
    assert api_client.get(reverse(REVIEW_DETAIL, args=[scan.public_id])).status_code == (
        http_status.HTTP_403_FORBIDDEN
    )

    api_client.force_authenticate(analyst)
    resp = api_client.get(reverse(REVIEW_DETAIL, args=[scan.public_id]))

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["id"] == str(scan.public_id)
    assert resp.data["report"]["claimed_label"] == "safe"
    assert resp.data["report"]["reporter_email"] == viewer.email
    assert resp.data["notes"][0]["author_email"] == analyst.email
    assert resp.data["notes"][0]["text"] == "score 0.62, capture floue"
    assert resp.data["reviewed_by_email"] is None
    assert Report.objects.get(pk=reported.pk).status == Report.Status.OPEN


# --- US34 / BR-04: the decision ---------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("decision", "expected_status", "fragment"),
    [
        ("confirm_phishing", Scan.Status.CONFIRMED, "phishing confirmé"),
        ("false_positive", Scan.Status.FALSE_POSITIVE, "légitime"),
    ],
)
def test_decision_is_200_resolves_the_report_and_notifies_the_reporter(
    analyst, api_client, make_user, decision, expected_status, fragment
):
    reporter = make_user(email="reporter@example.com")
    scan = make_scan(reporter, status=Scan.Status.UNDER_REVIEW)
    make_report(scan, reporter)

    api_client.force_authenticate(analyst)
    resp = api_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": decision, "comment": "analyse manuelle terminée"},
        format="json",
    )

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["status"] == expected_status
    assert resp.data["reviewed_by_email"] == analyst.email
    assert resp.data["review_comment"] == "analyse manuelle terminée"

    scan.refresh_from_db()
    assert scan.reviewed_by == analyst
    assert scan.reviewed_at is not None
    assert Report.objects.get(scan=scan).status == Report.Status.RESOLVED

    notification = Notification.objects.get(scan=scan)
    assert notification.user == reporter
    assert notification.read_at is None
    assert fragment in notification.message

    entry = AuditLog.objects.get(action=AuditLog.Action.SCAN_DECIDED)
    assert entry.user == analyst
    assert entry.target_id == str(scan.public_id)
    assert entry.metadata["decision"] == decision
    assert entry.metadata["to_status"] == expected_status
    assert entry.metadata["had_report"] is True
    assert AuditLog.objects.filter(
        action=AuditLog.Action.SCAN_STATUS_CHANGED,
        metadata__transition="review_decided",
    ).exists()


@pytest.mark.django_db
def test_decision_from_detected_is_409_and_changes_nothing(analyst, api_client):
    scan = make_scan(analyst, status=Scan.Status.DETECTED)

    api_client.force_authenticate(analyst)
    bad_body = api_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "maybe"},
        format="json",
    )
    assert bad_body.status_code == http_status.HTTP_400_BAD_REQUEST
    assert bad_body.data["code"] == "invalid_request"
    assert not AuditLog.objects.filter(action=AuditLog.Action.SCAN_DECIDED).exists()

    resp = api_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "false_positive"},
        format="json",
    )

    assert resp.status_code == http_status.HTTP_409_CONFLICT
    assert resp.data["code"] == "not_decidable"
    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.reviewed_at is None
    assert not AuditLog.objects.filter(action=AuditLog.Action.SCAN_DECIDED).exists()


@pytest.mark.django_db
def test_end_user_cannot_decide_and_anonymous_gets_401(api_client, viewer, analyst):
    scan = make_scan(viewer, status=Scan.Status.UNDER_REVIEW)

    assert api_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "confirm_phishing"},
        format="json",
    ).status_code == http_status.HTTP_401_UNAUTHORIZED

    api_client.force_authenticate(viewer)
    assert api_client.post(
        reverse(REVIEW_DECISION, args=[scan.public_id]),
        {"decision": "confirm_phishing"},
        format="json",
    ).status_code == http_status.HTTP_403_FORBIDDEN

    scan.refresh_from_db()
    assert scan.status == Scan.Status.UNDER_REVIEW


# --- US35: internal notes ---------------------------------------------------


@pytest.mark.django_db
def test_note_is_201_never_visible_to_the_owner_and_audited_without_its_text(
    analyst, viewer, api_client
):
    scan = make_scan(viewer, status=Scan.Status.UNDER_REVIEW)
    text = "logo déformé sur la capture"

    api_client.force_authenticate(analyst)
    resp = api_client.post(
        reverse(REVIEW_NOTE, args=[scan.public_id]), {"text": text}, format="json"
    )

    assert resp.status_code == http_status.HTTP_201_CREATED
    assert resp.data["author_email"] == analyst.email
    assert resp.data["text"] == text

    blank = api_client.post(
        reverse(REVIEW_NOTE, args=[scan.public_id]), {"text": ""}, format="json"
    )
    assert blank.status_code == http_status.HTTP_400_BAD_REQUEST
    assert blank.data["code"] == "invalid_request"
    assert AnalystNote.objects.count() == 1

    entry = AuditLog.objects.get(action=AuditLog.Action.NOTE_ADDED)
    assert entry.user == analyst
    assert entry.target_id == str(scan.public_id)
    assert entry.metadata == {"note_length": len(text)}
    assert text not in str(entry.metadata)

    # ISO-6.6: the owner never sees the note, the analyst comment or the
    # reviewing analyst on his own scan detail.
    api_client.force_authenticate(viewer)
    detail = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert detail.status_code == http_status.HTTP_200_OK
    assert "notes" not in detail.data
    assert "review_comment" not in detail.data
    assert "reviewed_by" not in detail.data

    assert api_client.post(
        reverse(REVIEW_NOTE, args=[scan.public_id]), {"text": "x"}, format="json"
    ).status_code == http_status.HTTP_403_FORBIDDEN


# --- US36: rescan -----------------------------------------------------------


@pytest.mark.django_db
def test_rescan_is_202_and_creates_a_new_scan_owned_by_the_analyst(
    analyst, viewer, api_client
):
    original = make_scan(viewer, status=Scan.Status.CONFIRMED)

    api_client.force_authenticate(analyst)
    resp = api_client.post(reverse(REVIEW_RESCAN, args=[original.public_id]))

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert resp.data["status"] == Scan.Status.SUBMITTED
    new_scan = Scan.objects.get(public_id=resp.data["id"])
    assert new_scan.owner == analyst
    assert new_scan.rescan_of == original
    assert new_scan.mode == Scan.Mode.FULL
    assert new_scan.url == original.url
    original.refresh_from_db()
    assert original.status == Scan.Status.CONFIRMED

    entry = AuditLog.objects.get(action=AuditLog.Action.SCAN_RESCANNED)
    assert entry.user == analyst
    assert entry.target_id == str(new_scan.public_id)
    assert entry.metadata == {"rescan_of": str(original.public_id)}


@pytest.mark.django_db
def test_rescan_refuses_a_now_private_url_and_creates_nothing(
    analyst, api_client, monkeypatch
):
    original = make_scan(
        analyst, status=Scan.Status.CONFIRMED, url="https://internal.example/login"
    )
    # BR-07: the URL was fine when first seen, but resolves to a private
    # address now - the rescan validation must refuse it again.
    install_dns(monkeypatch, {"internal.example": ["10.0.0.5"]})

    api_client.force_authenticate(analyst)
    resp = api_client.post(reverse(REVIEW_RESCAN, args=[original.public_id]))

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "forbidden_address"
    assert Scan.objects.count() == 1
    assert not AuditLog.objects.filter(action=AuditLog.Action.SCAN_RESCANNED).exists()


@pytest.mark.django_db
def test_rescan_counts_in_the_analyst_daily_quota(analyst, api_client, settings):
    settings.SCAN_DAILY_QUOTA = 0
    original = make_scan(analyst, status=Scan.Status.CONFIRMED)

    api_client.force_authenticate(analyst)
    resp = api_client.post(reverse(REVIEW_RESCAN, args=[original.public_id]))

    assert resp.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in resp
    assert Scan.objects.count() == 1


# --- US57: notifications ----------------------------------------------------


@pytest.mark.django_db
def test_notifications_are_only_mine_unread_first_and_counted(api_client, make_user):
    viewer = make_user(email="viewer@example.com")
    other = make_user(email="other@example.com")
    read = Notification.objects.create(
        user=viewer,
        kind=Notification.Kind.REPORT_DECISION,
        message="déjà lu",
        read_at=timezone.now(),
    )
    unread = Notification.objects.create(
        user=viewer, kind=Notification.Kind.REPORT_DECISION, message="non lu"
    )
    Notification.objects.create(
        user=other, kind=Notification.Kind.REPORT_DECISION, message="autre compte"
    )

    assert api_client.get(reverse(NOTIFICATION_LIST)).status_code == (
        http_status.HTTP_401_UNAUTHORIZED
    )

    api_client.force_authenticate(viewer)
    resp = api_client.get(reverse(NOTIFICATION_LIST))

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 2
    assert resp.data["unread_count"] == 1
    assert [row["message"] for row in resp.data["results"]] == ["non lu", "déjà lu"]
    assert resp.data["results"][0]["id"] == str(unread.public_id)
    assert read.read_at is not None


@pytest.mark.django_db
def test_notification_read_is_own_only_and_idempotent(api_client, viewer, make_user):
    stranger = make_user(email="stranger@example.com")
    own = Notification.objects.create(
        user=viewer, kind=Notification.Kind.REPORT_DECISION, message="la mienne"
    )
    foreign = Notification.objects.create(
        user=stranger, kind=Notification.Kind.REPORT_DECISION, message="la sienne"
    )

    assert api_client.post(reverse(NOTIFICATION_READ, args=[own.public_id])).status_code == (
        http_status.HTTP_401_UNAUTHORIZED
    )

    api_client.force_authenticate(viewer)
    resp = api_client.post(reverse(NOTIFICATION_READ, args=[foreign.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND
    foreign.refresh_from_db()
    assert foreign.read_at is None

    resp = api_client.post(reverse(NOTIFICATION_READ, args=[own.public_id]))
    assert resp.status_code == http_status.HTTP_200_OK
    first_read_at = resp.data["read_at"]
    assert first_read_at is not None

    again = api_client.post(reverse(NOTIFICATION_READ, args=[own.public_id]))
    assert again.status_code == http_status.HTTP_200_OK
    assert again.data["read_at"] == first_read_at
