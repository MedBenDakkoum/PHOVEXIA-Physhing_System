"""Worker-wiring pipeline tests (US17, US20, US26, part. US27/US28).

No HTTP and no DNS happen here: CollectorClient / InferenceClient are replaced
with fakes at the task level (`scans.tasks.CollectorClient` / `InferenceClient`),
while the real client JSON-shape validation is exercised separately against a
mocked `requests` session. The MOCK path (no active version, or a MOCK/ONNX
active version) must keep working unchanged.

Requirement tags: US17 (collector), US20 (inference + screenshots),
US26 (worker wiring), US27 (partial results), US28 (fail-closed FAILED),
BR-04 (status graph), BR-07 (blocklist short-circuit), BR-11 (one active
model), ISO-6.5 (retries then FAILED), ISO-6.6 (404 never 403).
"""
import base64
import socket
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from rest_framework import status as http_status
from rest_framework.test import APIClient

from controlpanel.models import ModelVersion
from scans.models import Scan
from scans.services.collector_client import (
    CollectorClient,
    CollectorError,
    CollectorResponse,
)
from scans.services.inference_client import (
    InferenceClient,
    InferenceError,
    InferenceResponse,
)
from scans.services.screenshots import prepare_screenshot
from scans.tasks import run_scan

User = get_user_model()

VALID_URL = "https://example.com/login?user=1"
DOMAIN = "example.com"
SCAN_DETAIL = "scan-detail"
SCAN_SCREENSHOT = "scan-screenshot"
SCAN_CREATE = "scan-list"

# 1x1 transparent PNG (valid signature, a few dozen bytes).
PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


# --- helpers ----------------------------------------------------------------


def install_dns(monkeypatch, mapping=None, default="93.184.216.34"):
    """Fake resolver so no test ever touches the network."""

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        addresses = (mapping or {}).get(host, [default])
        out = []
        for addr in addresses:
            out.append(
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, 0, 0, 0))
            )
        return out

    monkeypatch.setattr("scans.services.url_validation.socket.getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def _fake_dns(monkeypatch):
    install_dns(monkeypatch)


@pytest.fixture
def media_root(settings, tmp_path):
    """Screenshots are written under a throw-away directory, never the repo."""
    settings.MEDIA_ROOT = tmp_path
    return tmp_path


def make_user(email="u@example.com", role="end_user"):
    return User.objects.create_user(email=email, password="StrongPass!234", role=role)


def make_scan(owner, url=VALID_URL, domain=DOMAIN, mode=Scan.Mode.FULL):
    return Scan.objects.create(
        owner=owner, url=url, domain=domain, mode=mode, status=Scan.Status.SUBMITTED
    )


def make_bundle(version="bundle-1", kind=ModelVersion.Kind.TORCH_BUNDLE, active=True):
    if active:
        # BR-11: at most ONE active version. The 0001_initial migration seeds
        # an active MOCK "mock-0", so it must be deactivated first.
        ModelVersion.objects.filter(is_active=True).update(is_active=False)
    return ModelVersion.objects.create(
        name="torch-bundle",
        version=version,
        kind=kind,
        is_active=active,
        file_path="",
        sha256="",
        metrics={},
    )


def capture(**overrides):
    base = {
        "status": "complete",
        "reason_code": None,
        "final_url": "https://example.com/",
        "redirect_chain": ["https://example.com/"],
        "http_status": 200,
        "text": "page text",
        "ssl": 1,
        "tld": "com",
        "domain": "example.com",
        "fld": "example.com",
        "subdomain": "",
        "screenshot_png_base64": PNG_B64,
        "tls": {},
        "timings_ms": {},
    }
    base.update(overrides)
    return CollectorResponse(base)


def inference(**overrides):
    base = {
        "status": "complete",
        "partial": False,
        "prediction": "phishing",
        "phishing_probability": 0.9,
        "model_bundle_version": "bundle-1",
        "base_probabilities": {
            "mobilenet_phishing_probability": 0.91,
            "distilbert_phishing_probability": 0.88,
            "url_cnn_phishing_probability": 0.93,
            "metadata_phishing_probability": 0.70,
        },
        "reason_code": None,
        "available_signals": ["url", "text", "metadata"],
        "unavailable_signals": [],
    }
    base.update(overrides)
    return InferenceResponse(base)


def install_collector(monkeypatch, *, response=None, error=None, calls=None):
    class _FakeCollector:
        def collect(self, url):
            if calls is not None:
                calls.append(url)
            if error is not None:
                raise error
            return response

    monkeypatch.setattr("scans.tasks.CollectorClient", _FakeCollector)


def install_inference(monkeypatch, *, response=None, error=None, calls=None):
    class _FakeInference:
        def predict(self, **kwargs):
            if calls is not None:
                calls.append(kwargs)
            if error is not None:
                raise error
            return response

    monkeypatch.setattr("scans.tasks.InferenceClient", _FakeInference)


# --- MOCK path stays unchanged (US48 / BR-11) -------------------------------


@pytest.mark.django_db
def test_no_active_version_uses_the_mock_path_and_never_the_services(monkeypatch):
    # The migration seeds an active MOCK "mock-0"; remove it to exercise the
    # "no active version" branch (still the MOCK path, empty model_version).
    ModelVersion.objects.all().delete()
    calls = SimpleNamespace(collector=[], inference=[])
    install_collector(monkeypatch, calls=calls.collector)
    install_inference(monkeypatch, calls=calls.inference)
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status in (Scan.Status.DETECTED, Scan.Status.UNDER_REVIEW)
    assert scan.model_version == ""
    assert scan.partial is False
    assert scan.model_bundle_version == ""
    assert scan.screenshot_path == ""
    assert calls.collector == [] and calls.inference == []


@pytest.mark.django_db
def test_active_mock_version_still_uses_the_mock_path(monkeypatch):
    calls = SimpleNamespace(collector=[], inference=[])
    install_collector(monkeypatch, calls=calls.collector)
    install_inference(monkeypatch, calls=calls.inference)
    bundle = make_bundle(version="mock-0", kind=ModelVersion.Kind.MOCK)
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status in (Scan.Status.DETECTED, Scan.Status.UNDER_REVIEW)
    assert scan.model_version == bundle.version
    assert scan.partial is False
    assert calls.collector == [] and calls.inference == []


# --- real pipeline happy path (US20 / US26) ---------------------------------


@pytest.mark.django_db
def test_complete_phishing_result_stores_every_real_pipeline_field(
    monkeypatch, media_root
):
    calls = SimpleNamespace(collector=[], inference=[])
    install_collector(monkeypatch, response=capture(), calls=calls.collector)
    install_inference(monkeypatch, response=inference(), calls=calls.inference)
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == "phishing"
    assert scan.score == pytest.approx(0.9)
    assert scan.partial is False
    assert scan.reason_code == ""
    assert scan.final_url == "https://example.com/"
    assert scan.model_version == "bundle-1"
    assert scan.model_bundle_version == "bundle-1"
    assert scan.signals == {
        "ssl": 1,
        "tld": "com",
        "domain": "example.com",
        "fld": "example.com",
        "subdomain": "",
    }
    assert scan.probabilities["fusion"] == pytest.approx(0.9)
    assert scan.probabilities["url"] == pytest.approx(0.91)
    assert scan.probabilities["metadata"] == pytest.approx(0.70)
    assert scan.screenshot_path == f"screenshots/{scan.public_id}.png"
    assert (media_root / scan.screenshot_path).is_file()
    # The screenshot bytes were forwarded to inference exactly once.
    assert len(calls.inference) == 1
    assert calls.inference[0]["screenshot_png"] is not None
    assert base64.b64decode(PNG_B64)[:8] == calls.inference[0]["screenshot_png"][:8]


@pytest.mark.django_db
def test_complete_uncertain_fusion_goes_to_under_review(monkeypatch, media_root):
    install_collector(monkeypatch, response=capture())
    install_inference(
        monkeypatch,
        response=inference(phishing_probability=0.55, prediction="uncertain"),
    )
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.UNDER_REVIEW
    assert scan.verdict == "uncertain"
    assert scan.partial is False
    assert scan.probabilities["fusion"] == pytest.approx(0.55)


# --- partial results (US27) -------------------------------------------------


@pytest.mark.django_db
def test_collector_partial_skips_inference_and_stays_detected_not_under_review(
    monkeypatch
):
    calls = SimpleNamespace(inference=[])
    install_collector(
        monkeypatch, response=capture(status="partial", reason_code="SITE_UNREACHABLE")
    )
    install_inference(monkeypatch, calls=calls.inference)
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    # Business rule: a partial result is DETECTED (user-visible), never queued
    # for an analyst, and inference is never called without a complete capture.
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == "uncertain"
    assert scan.partial is True
    assert scan.reason_code == "SITE_UNREACHABLE"
    assert scan.model_bundle_version == ""
    assert calls.inference == []


@pytest.mark.django_db
def test_inference_uncertain_partial_stays_detected_with_friendly_probabilities(
    monkeypatch, media_root
):
    install_collector(monkeypatch, response=capture())
    install_inference(
        monkeypatch,
        response=inference(
            status="uncertain",
            partial=True,
            reason_code="MISSING_SCREENSHOT",
            prediction=None,
            phishing_probability=None,
            base_probabilities={
                "mobilenet_phishing_probability": None,
                "distilbert_phishing_probability": 0.88,
                "url_cnn_phishing_probability": None,
                "metadata_phishing_probability": 0.70,
            },
        ),
    )
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == "uncertain"
    assert scan.partial is True
    assert scan.reason_code == "MISSING_SCREENSHOT"
    assert scan.probabilities["fusion"] is None
    assert scan.probabilities["page_text"] == pytest.approx(0.88)


# --- infrastructure failures (US28 / ISO-6.5) -------------------------------


@pytest.mark.django_db
def test_collector_unreachable_is_retried_then_failed(monkeypatch):
    monkeypatch.setattr("scans.tasks.time.sleep", lambda *a, **k: None)
    calls = SimpleNamespace(collector=[])
    install_collector(
        monkeypatch,
        error=CollectorError("COLLECTOR_UNREACHABLE"),
        calls=calls.collector,
    )
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert scan.reason_code == "COLLECTOR_UNREACHABLE"
    assert scan.error_message == "COLLECTOR_UNREACHABLE"
    # 1 attempt + 2 retries.
    assert len(calls.collector) == 3


@pytest.mark.django_db
def test_inference_unreachable_is_retried_then_failed(monkeypatch):
    monkeypatch.setattr("scans.tasks.time.sleep", lambda *a, **k: None)
    calls = SimpleNamespace(inference=[])
    install_collector(monkeypatch, response=capture())
    install_inference(
        monkeypatch,
        error=InferenceError("INFERENCE_UNREACHABLE"),
        calls=calls.inference,
    )
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert scan.reason_code == "INFERENCE_UNREACHABLE"
    assert len(calls.inference) == 3


@pytest.mark.django_db
def test_model_bundle_version_mismatch_fails_without_retry(monkeypatch):
    monkeypatch.setattr("scans.tasks.time.sleep", lambda *a, **k: None)
    calls = SimpleNamespace(inference=[])
    install_collector(monkeypatch, response=capture())
    install_inference(
        monkeypatch,
        response=inference(model_bundle_version="bundle-9"),
        calls=calls.inference,
    )
    make_bundle(version="bundle-1")
    scan = make_scan(make_user())

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert scan.reason_code == "MODEL_MISMATCH"
    assert "model_mismatch" in scan.error_message
    # No retry: the mismatch is decided after a successful inference call.
    assert len(calls.inference) == 1


# --- blocklist short-circuit (BR-07 / US41) ---------------------------------


@pytest.mark.django_db
def test_blocklist_short_circuit_never_touches_collector_or_inference(
    monkeypatch, analyst, django_capture_on_commit_callbacks
):
    from blocklist.models import BlocklistEntry

    calls = SimpleNamespace(collector=[], inference=[])
    install_collector(monkeypatch, calls=calls.collector)
    install_inference(monkeypatch, calls=calls.inference)
    make_bundle(version="bundle-1")
    BlocklistEntry.objects.create(
        domain="blocked.example", reason="confirmed_phishing", added_by=analyst
    )
    client = APIClient()
    client.force_authenticate(make_user())

    with django_capture_on_commit_callbacks(execute=True):
        resp = client.post(
            reverse(SCAN_CREATE),
            {"url": "https://sub.blocked.example/login"},
            format="json",
        )

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    assert resp.data["status"] == Scan.Status.DETECTED
    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.verdict == "phishing"
    assert scan.score == 1.0
    assert scan.partial is False
    assert calls.collector == [] and calls.inference == []


# --- screenshot endpoint (US20 / ISO-6.6) -----------------------------------


@pytest.mark.django_db
def test_screenshot_is_readable_by_owner_and_analyst(media_root):
    owner = make_user("owner@example.com")
    scan = make_scan(owner)
    path, _raw = prepare_screenshot(scan.public_id, PNG_B64)
    scan.screenshot_path = path
    scan.save(update_fields=["screenshot_path"])

    owner_client = APIClient()
    owner_client.force_authenticate(owner)
    resp = owner_client.get(reverse(SCAN_SCREENSHOT, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp["Content-Type"] == "image/png"
    assert resp["X-Content-Type-Options"] == "nosniff"
    assert resp.content[:8] == b"\x89PNG\r\n\x1a\n"

    analyst_client = APIClient()
    analyst_client.force_authenticate(make_user("a@example.com", role="analyst"))
    assert (
        analyst_client.get(reverse(SCAN_SCREENSHOT, args=[scan.public_id])).status_code
        == http_status.HTTP_200_OK
    )


@pytest.mark.django_db
def test_screenshot_is_404_for_another_user_and_401_for_anonymous(media_root):
    owner = make_user("owner@example.com")
    scan = make_scan(owner)
    path, _raw = prepare_screenshot(scan.public_id, PNG_B64)
    scan.screenshot_path = path
    scan.save(update_fields=["screenshot_path"])

    other_client = APIClient()
    other_client.force_authenticate(make_user("other@example.com"))
    other_resp = other_client.get(reverse(SCAN_SCREENSHOT, args=[scan.public_id]))
    assert other_resp.status_code == http_status.HTTP_404_NOT_FOUND  # never 403

    anon_resp = APIClient().get(reverse(SCAN_SCREENSHOT, args=[scan.public_id]))
    assert anon_resp.status_code == http_status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_screenshot_without_capture_is_404(media_root):
    owner = make_user("owner@example.com")
    scan = make_scan(owner)  # screenshot_path stays ""

    client = APIClient()
    client.force_authenticate(owner)
    resp = client.get(reverse(SCAN_SCREENSHOT, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_screenshot_path_traversal_is_refused(media_root, settings):
    """Security edge case: a tampered screenshot_path never escapes MEDIA_ROOT."""
    owner = make_user("owner@example.com")
    scan = make_scan(owner)
    scan.screenshot_path = "../config/settings.py"
    scan.save(update_fields=["screenshot_path"])
    # A real file exists just outside MEDIA_ROOT: it must NOT be servable.
    (media_root.parent / "leaked.txt").write_bytes(b"secret")

    client = APIClient()
    client.force_authenticate(owner)
    resp = client.get(reverse(SCAN_SCREENSHOT, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


# --- sync_model_version command (US48 / BR-11) ------------------------------


class _FakeHealthResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


@pytest.mark.django_db
def test_sync_model_version_registers_a_bundle_without_activating(monkeypatch):
    payload = {
        "status": "ready",
        "model_bundle_version": "bundle-1",
        "checks": {"url_model": "ok", "fusion": "ok"},
    }
    monkeypatch.setattr(
        "scans.management.commands.sync_model_version.requests.get",
        lambda *a, **k: _FakeHealthResponse(payload),
    )

    call_command("sync_model_version", url="http://inference:8000")

    version = ModelVersion.objects.get(name="torch-bundle", version="bundle-1")
    assert version.kind == ModelVersion.Kind.TORCH_BUNDLE
    assert version.is_active is False  # BR-11: only an admin activates
    assert version.metrics == payload["checks"]
    assert version.sha256 == ""  # /health does not expose the manifest hash

    # Idempotent: a second run registers nothing new.
    call_command("sync_model_version", url="http://inference:8000")
    assert ModelVersion.objects.filter(name="torch-bundle").count() == 1


@pytest.mark.django_db
def test_sync_model_version_fails_closed_when_inference_is_down(monkeypatch):
    import requests

    def _raise(*a, **k):
        raise requests.exceptions.ConnectionError("inference is down")

    monkeypatch.setattr(
        "scans.management.commands.sync_model_version.requests.get", _raise
    )

    from django.core.management.base import CommandError

    with pytest.raises(CommandError):
        call_command("sync_model_version", url="http://inference:8000")
    assert ModelVersion.objects.count() == 1  # only the seeded mock-0 remains


# --- real client shape validation (no fake here) ----------------------------


class _FakeSession:
    def __init__(self, *, status_code=200, body=b"{}", headers=None):
        self._status_code = status_code
        self._body = body
        self.headers = headers or {}

    def post(self, *a, **k):
        return _FakeRawResponse(self._status_code, self._body)


class _FakeRawResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def iter_content(self, chunk_size=65536):
        yield self._body


def test_collector_client_refuses_5xx_and_bad_shape(settings):
    settings.COLLECTOR_URL = "http://collector:8000"
    client = CollectorClient()
    client._session = _FakeSession(status_code=500)
    with pytest.raises(CollectorError) as exc:
        client.collect("https://example.com/")
    assert exc.value.reason == "COLLECTOR_HTTP_500"

    client._session = _FakeSession(status_code=200, body=b"not json")
    with pytest.raises(CollectorError) as exc:
        client.collect("https://example.com/")
    assert exc.value.reason == "COLLECTOR_BAD_SHAPE"


def test_inference_client_refuses_missing_bundle_and_bad_shape(settings):
    settings.INFERENCE_URL = "http://inference:8000"
    client = InferenceClient()
    # A 200 whose body is not the contract shape is refused, not trusted.
    client._session = _FakeSession(status_code=200, body=b'{"status": "weird"}')
    with pytest.raises(InferenceError) as exc:
        client.predict(
            url="https://example.com/",
            text="",
            screenshot_png=None,
            ssl=1,
            tld="com",
            subdomain="",
        )
    assert exc.value.reason == "INFERENCE_BAD_SHAPE"
