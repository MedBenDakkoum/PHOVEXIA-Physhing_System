"""Outbound n8n integration tests (feature/n8n-events).

Covers: disabled mode, on_commit enqueue, privacy-safe payload, HMAC
signature, fixed destination, retry/audit path, the three emit triggers,
and the read-only `monitor:read` API key scope.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from audit.models import AuditLog
from controlpanel.services.api_keys import create_api_key
from integrations import services as integration_services
from integrations.events import SCAN_CONFIRMED, SCAN_NEEDS_REVIEW, TEST_EVENT
from integrations.tasks import deliver_event
from reviews.services import DECISION_CONFIRM_PHISHING, report_scan, submit_decision
from scans.models import Scan
from scans.services.workflows import change_status

ENABLED = {
    "N8N_WEBHOOK_BASE_URL": "http://n8n:5678",
    "N8N_WEBHOOK_SECRET": "test-webhook-secret",
}
SECRET = ENABLED["N8N_WEBHOOK_SECRET"]
VALID_URL = "https://login.example.com/session"


def _scan(owner=None, **overrides):
    values = {
        "url": VALID_URL,
        "domain": "login.example.com",
        "mode": Scan.Mode.FULL,
        "status": Scan.Status.DETECTED,
        "verdict": "phishing",
        "model_verdict": "phishing",
        "score": 0.93,
        "model_score": 0.93,
        "detection_source": Scan.DetectionSource.MODEL,
        "partial": False,
    }
    values.update(overrides)
    return Scan.objects.create(owner=owner, **values)


def _key_client(owner, scopes):
    _key, secret = create_api_key(name="test-key", owner=owner, scopes=scopes)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Api-Key {secret}")
    return client


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_disabled_feature_is_a_noop(delay, settings):
    settings.N8N_WEBHOOK_BASE_URL = ""
    settings.N8N_WEBHOOK_SECRET = ""

    assert integration_services.is_enabled() is False
    assert integration_services.emit_event(TEST_EVENT, {"any": "data"}) is None
    delay.assert_not_called()


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_event_is_enqueued_once_after_commit(
    delay, settings, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET

    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        event_id = integration_services.emit_event(TEST_EVENT, {"k": "v"})

    assert event_id
    assert len(callbacks) == 1
    delay.assert_called_once()
    event = delay.call_args.args[0]
    assert event["id"] == event_id
    assert event["type"] == TEST_EVENT
    assert event["data"] == {"k": "v"}
    assert set(event) == {"id", "type", "occurred_at", "data"}


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_scan_payload_has_no_full_url_email_or_name(
    delay, settings, make_user, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    owner = make_user(
        email="victim@example.com", first_name="Victim", last_name="Person"
    )
    scan = _scan(
        owner=owner,
        url="https://login.example.com/secret-path?token=abcdef",
    )

    with django_capture_on_commit_callbacks(execute=True):
        integration_services.emit_scan_confirmed(scan)

    event = delay.call_args.args[0]
    body = json.dumps(event, sort_keys=True)
    assert scan.url not in body
    assert "/secret-path" not in body
    assert "victim@example.com" not in body
    assert "Victim" not in body
    assert "Person" not in body

    data = event["data"]
    assert data["scan_id"] == str(scan.public_id)
    assert data["domain"] == "login.example.com"
    assert data["review_url"].endswith(f"/review/{scan.public_id}")
    assert set(data) == {
        "scan_id",
        "domain",
        "verdict",
        "model_verdict",
        "risk_index",
        "source",
        "review_url",
    }


@pytest.mark.django_db
@patch("integrations.tasks.requests.post")
def test_delivery_signs_body_and_uses_fixed_path(post, settings):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    post.return_value.status_code = 200
    post.return_value.raise_for_status.return_value = None
    event = {
        "id": "evt-1",
        "type": SCAN_CONFIRMED,
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "data": {"domain": "example.com"},
    }

    deliver_event.apply(args=[event]).get()

    _args, kwargs = post.call_args
    assert post.call_args.args[0] == "http://n8n:5678/webhook/scan-confirmed"
    body = kwargs["data"]
    headers = kwargs["headers"]
    assert headers["X-Event-Id"] == "evt-1"
    assert headers["X-Webhook-Secret"] == SECRET
    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-Signature"] == expected
    assert kwargs["timeout"] == 5


@pytest.mark.django_db
@patch("integrations.tasks.requests.post")
def test_destination_never_comes_from_the_payload(post, settings):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    post.return_value.status_code = 200
    post.return_value.raise_for_status.return_value = None
    event = {
        "id": "evt-2",
        "type": TEST_EVENT,
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "data": {
            "url": "http://attacker.example/ssrf",
            "webhook_url": "http://attacker.example/steal",
            "base_url": "http://attacker.example",
        },
    }

    deliver_event.apply(args=[event]).get()

    assert post.call_args.args[0] == "http://n8n:5678/webhook/test-event"


@pytest.mark.django_db
@patch("integrations.tasks.requests.post")
def test_failed_delivery_retries_three_times_then_audits(post, settings):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    post.side_effect = ConnectionError("n8n unreachable")
    event = {
        "id": "evt-3",
        "type": SCAN_NEEDS_REVIEW,
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "data": {"domain": "example.com"},
    }
    # Celery only follows the Retry signatures when eager propagation is off
    # (the autouse fixture turns it on for every other test).
    from config.celery import app as celery_app

    celery_app.conf.task_eager_propagates = False

    deliver_event.apply(args=[event]).get()

    assert post.call_count == 4  # initial attempt + 3 retries
    entry = AuditLog.objects.get(
        action=AuditLog.Action.INTEGRATION_DELIVERY_FAILED
    )
    assert entry.metadata == {
        "event_type": SCAN_NEEDS_REVIEW,
        "event_id": "evt-3",
    }


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_confirm_phishing_emits_scan_confirmed(
    delay, settings, viewer, analyst, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    scan = _scan(owner=viewer, status=Scan.Status.UNDER_REVIEW)

    with django_capture_on_commit_callbacks(execute=True):
        submit_decision(
            scan=scan,
            analyst=analyst,
            decision=DECISION_CONFIRM_PHISHING,
        )

    delay.assert_called_once()
    event = delay.call_args.args[0]
    assert event["type"] == SCAN_CONFIRMED
    assert event["data"]["scan_id"] == str(scan.public_id)


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_false_positive_does_not_emit_confirmed(
    delay, settings, viewer, analyst, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    scan = _scan(owner=viewer, status=Scan.Status.UNDER_REVIEW)

    with django_capture_on_commit_callbacks(execute=True):
        submit_decision(scan=scan, analyst=analyst, decision="false_positive")

    delay.assert_not_called()


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_owner_report_emits_needs_review_with_reason(
    delay, settings, viewer, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    scan = _scan(owner=viewer)

    with django_capture_on_commit_callbacks(execute=True):
        report_scan(scan=scan, reporter=viewer, claimed_label="safe")

    delay.assert_called_once()
    event = delay.call_args.args[0]
    assert event["type"] == SCAN_NEEDS_REVIEW
    assert event["data"]["review_reason"] == "reported"


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_uncertain_complete_scan_emits_needs_review(
    delay, settings, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    scan = _scan(verdict="uncertain", model_verdict="uncertain", partial=False)

    with django_capture_on_commit_callbacks(execute=True):
        change_status(scan, Scan.Status.UNDER_REVIEW, None)

    delay.assert_called_once()
    event = delay.call_args.args[0]
    assert event["type"] == SCAN_NEEDS_REVIEW
    assert event["data"]["review_reason"] == "uncertain"


@pytest.mark.django_db
@patch("integrations.services.deliver_event.delay")
def test_partial_uncertain_scan_does_not_emit(
    delay, settings, django_capture_on_commit_callbacks
):
    settings.N8N_WEBHOOK_BASE_URL = ENABLED["N8N_WEBHOOK_BASE_URL"]
    settings.N8N_WEBHOOK_SECRET = SECRET
    scan = _scan(verdict="uncertain", model_verdict="uncertain", partial=True)

    with django_capture_on_commit_callbacks(execute=True):
        change_status(scan, Scan.Status.UNDER_REVIEW, None)

    delay.assert_not_called()


@pytest.mark.django_db
def test_monitor_scope_allows_health_and_dashboard(admin):
    client = _key_client(admin, ["monitor:read"])

    assert client.get(reverse("admin-health")).status_code == 200
    assert client.get(reverse("admin-dashboard")).status_code == 200


@pytest.mark.django_db
def test_monitor_scope_is_refused_everywhere_else(admin):
    client = _key_client(admin, ["monitor:read"])

    assert client.post(
        reverse("scan-list"), {"url": VALID_URL}, format="json"
    ).status_code == 403
    assert client.get(reverse("admin-apikey-list")).status_code == 401

    # A scan key is still refused (401) on the monitoring endpoints.
    scan_key_client = _key_client(admin, ["scan:create", "scan:read"])
    assert scan_key_client.get(reverse("admin-health")).status_code == 401
