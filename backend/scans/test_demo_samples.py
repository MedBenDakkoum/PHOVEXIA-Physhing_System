"""
Demo environment tests: load_demo_samples + demo_setup (docs/DEMO_RUNBOOK.md).

Requirement tags: BR-01 (dataset_sample never consumes the daily quota),
BR-04 (every status move goes through change_status / TRANSITIONS), BR-08
(roles are provisioned server-side only, never from a client input), BR-11
(single active TORCH_BUNDLE), US16 (follow-up), US47 (read-only audit),
ISO-6.1 (functional suitability), ISO-6.5 (idempotence after a failure),
ISO-6.6 (the demo password is never written to disk or printed when it
comes from .env).

No HTTP and no DNS: InferenceClient is replaced with a fake, and the happy-
path test additionally asserts that requests.Session.request and the
collector are NEVER called - a golden sample's original URL cannot be
contacted (BR-07 is not even triggered: nothing is crawled).
"""
import base64
import csv
import io
from types import SimpleNamespace
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError

from audit.models import AuditLog
from controlpanel.models import ModelVersion
from scans.models import Scan
from scans.services.inference_client import InferenceResponse
from scans.services.quota import check_quota, get_quota_status

User = get_user_model()

# 1x1 transparent PNG: enough for prepare_screenshot's signature + size checks.
PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

CSV_COLUMNS = [
    "sample_index",
    "URL",
    "html_text",
    "SSL",
    "TLD",
    "Subdomain",
    "label",
    "mobilenet_phishing_probability",
    "distilbert_phishing_probability",
    "url_cnn_phishing_probability",
    "metadata_phishing_probability",
    "fusion_mlp_phishing_probability",
    "fusion_decision_05",
]

# label=1 rows are the "phishing" golden samples, label=0 the legitimate ones;
# T3/T4 sit inside the uncertain band (0.40 < fusion < 0.70, DetectionSettings).
GOLDEN_ROWS = [
    {
        "sample_index": "T1",
        "URL": "https://demo-golden.test/phish-one",
        "html_text": "<html><p>verify your account</p></html>",
        "SSL": "1",
        "TLD": "test",
        "Subdomain": "demo-golden",
        "label": "1",
        "mobilenet_phishing_probability": "0.9100",
        "distilbert_phishing_probability": "0.9200",
        "url_cnn_phishing_probability": "0.9300",
        "metadata_phishing_probability": "0.9400",
        "fusion_mlp_phishing_probability": "0.9500",
        "fusion_decision_05": "1",
    },
    {
        "sample_index": "T2",
        "URL": "https://demo-golden.test/legit-two",
        "html_text": "<html><p>news home page</p></html>",
        "SSL": "1",
        "TLD": "test",
        "Subdomain": "",
        "label": "0",
        "mobilenet_phishing_probability": "0.1000",
        "distilbert_phishing_probability": "0.1100",
        "url_cnn_phishing_probability": "0.1200",
        "metadata_phishing_probability": "0.1300",
        "fusion_mlp_phishing_probability": "0.1400",
        "fusion_decision_05": "0",
    },
    {
        "sample_index": "T3",
        "URL": "https://demo-golden.test/uncertain-three",
        "html_text": "<html><p>borderline page</p></html>",
        "SSL": "0",
        "TLD": "test",
        "Subdomain": "",
        "label": "1",
        "mobilenet_phishing_probability": "0.5000",
        "distilbert_phishing_probability": "0.5200",
        "url_cnn_phishing_probability": "0.5400",
        "metadata_phishing_probability": "0.5600",
        "fusion_mlp_phishing_probability": "0.5500",
        "fusion_decision_05": "1",
    },
    {
        "sample_index": "T4",
        "URL": "https://demo-golden.test/uncertain-four",
        "html_text": "<html><p>other borderline page</p></html>",
        "SSL": "1",
        "TLD": "test",
        "Subdomain": "",
        "label": "1",
        "mobilenet_phishing_probability": "0.4400",
        "distilbert_phishing_probability": "0.4500",
        "url_cnn_phishing_probability": "0.4600",
        "metadata_phishing_probability": "0.4700",
        "fusion_mlp_phishing_probability": "0.4500",
        "fusion_decision_05": "1",
    },
]


@pytest.fixture
def golden_dir(tmp_path):
    """Synthetic golden bundle (same layout as the real git-ignored one)."""
    path = tmp_path / "golden"
    path.mkdir()
    with (path / "golden_samples.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(GOLDEN_ROWS)
    for row in GOLDEN_ROWS:
        (path / f"{row['sample_index']}.txt").write_text(
            row["html_text"], encoding="utf-8"
        )
        (path / f"{row['sample_index']}.png").write_bytes(PNG_1PX)
    return path


@pytest.fixture
def media_root(settings, tmp_path):
    """Screenshots are written under a throw-away directory, never the repo."""
    settings.MEDIA_ROOT = tmp_path / "media"
    return settings.MEDIA_ROOT


def make_fake_inference(rows_by_url, offset=0.0, calls=None):
    """Fake InferenceClient returning the golden probabilities (+offset)."""

    class _FakeInference:
        def predict(self, url, text, screenshot_png, ssl, tld, subdomain):
            if calls is not None:
                calls.append(
                    {
                        "url": url,
                        "text": text,
                        "screenshot_png": screenshot_png,
                        "ssl": ssl,
                        "tld": tld,
                        "subdomain": subdomain,
                    }
                )
            row = rows_by_url[url]
            # Raw inference keys -> their golden CSV column, BY NAME (the
            # InferenceResponse converts them to friendly modality names).
            base = {
                "mobilenet_phishing_probability": (
                    float(row["mobilenet_phishing_probability"]) + offset
                ),
                "distilbert_phishing_probability": (
                    float(row["distilbert_phishing_probability"]) + offset
                ),
                "url_cnn_phishing_probability": (
                    float(row["url_cnn_phishing_probability"]) + offset
                ),
                "metadata_phishing_probability": (
                    float(row["metadata_phishing_probability"]) + offset
                ),
            }
            fusion = float(row["fusion_mlp_phishing_probability"]) + offset
            return InferenceResponse(
                {
                    "status": "complete",
                    "partial": False,
                    "prediction": "phishing" if fusion >= 0.5 else "legitimate",
                    "phishing_probability": fusion,
                    "base_probabilities": base,
                    "model_bundle_version": "2026-10-25",
                }
            )

    return _FakeInference


def run_load(golden_dir, owner_email, count=4, stdout=None):
    return call_command(
        "load_demo_samples",
        owner=owner_email,
        count=count,
        samples_dir=str(golden_dir),
        stdout=stdout or io.StringIO(),
    )


# --- 1. happy path: real workflow, stored inputs, no network ---------------


@pytest.mark.django_db
def test_load_uses_stored_inputs_and_the_normal_workflow(
    golden_dir, media_root, make_user, monkeypatch
):
    """US16 / BR-04 / ISO-6.1: statuses via change_status, inputs from the
    bundle, screenshots on disk, and NO collector / NO raw HTTP call."""
    user = make_user(email="demo.owner@example.com")
    rows_by_url = {row["URL"]: row for row in GOLDEN_ROWS}
    calls = []
    fake = make_fake_inference(rows_by_url, calls=calls)
    monkeypatch.setattr(
        "scans.management.commands.load_demo_samples.InferenceClient", fake
    )
    out = io.StringIO()
    with (
        mock.patch("requests.sessions.Session.request") as session_request,
        mock.patch(
            "scans.services.collector_client.CollectorClient.collect"
        ) as collector,
    ):
        run_load(golden_dir, user.email, stdout=out)
    # The original URL must never be contacted: only the (mocked) inference
    # client ran, no requests at all, no collector call.
    session_request.assert_not_called()
    collector.assert_not_called()

    text = out.getvalue()
    assert "4 created, 0 skipped, 0 failed, 0 mismatch(es)" in text
    # Every inference call carried the STORED inputs of one golden sample.
    assert len(calls) == 4
    assert calls[0]["url"] in rows_by_url
    assert calls[0]["screenshot_png"] == PNG_1PX

    scans = {s.demo_sample_id: s for s in Scan.objects.filter(owner=user)}
    assert set(scans) == {"T1", "T2", "T3", "T4"}
    # BR-04: SUBMITTED -> ANALYZING -> DETECTED (or UNDER_REVIEW when uncertain).
    assert scans["T1"].status == Scan.Status.DETECTED
    assert scans["T1"].verdict == "phishing"
    assert scans["T2"].verdict == "legitimate"
    assert scans["T3"].verdict == "uncertain"
    assert scans["T3"].status == Scan.Status.UNDER_REVIEW
    assert scans["T4"].status == Scan.Status.UNDER_REVIEW
    # Every scan carries the demo source and its screenshot on MEDIA_ROOT.
    assert all(
        s.detection_source == Scan.DetectionSource.DATASET_SAMPLE
        for s in scans.values()
    )
    assert all((media_root / s.screenshot_path).is_file() for s in scans.values())
    # change_status wrote the immutable audit entries (US46 / ISO-6.6).
    assert (
        AuditLog.objects.filter(
            action=AuditLog.Action.SCAN_STATUS_CHANGED, user=None
        ).count()
        >= 8
    )  # 4 x (SUBMITTED->ANALYZING + ANALYZING->...) at minimum


# --- 2. by-name mapping (a positional mapping must fail) --------------------


@pytest.mark.django_db
def test_golden_comparison_maps_by_name_not_by_position(
    golden_dir, media_root, make_user, monkeypatch
):
    """The 4 golden columns carry DISTINCT values (0.91/0.92/0.93/0.94 for T1):
    a loader that zipped them by position would compare mobilenet (0.91) with
    the url probability (0.93) and report a mismatch. By name, nothing is
    reported and each stored modality keeps its own value."""
    user = make_user(email="demo.owner@example.com")
    rows_by_url = {row["URL"]: row for row in GOLDEN_ROWS}
    monkeypatch.setattr(
        "scans.management.commands.load_demo_samples.InferenceClient",
        make_fake_inference(rows_by_url),
    )
    out = io.StringIO()
    run_load(golden_dir, user.email, count=1, stdout=out)
    text = out.getvalue()
    assert "MISMATCH" not in text
    assert "1 created, 0 skipped, 0 failed, 0 mismatch(es)" in text
    scan = Scan.objects.get(demo_sample_id="T1")
    assert scan.probabilities["screenshot"] == pytest.approx(0.91)
    assert scan.probabilities["page_text"] == pytest.approx(0.92)
    assert scan.probabilities["url"] == pytest.approx(0.93)
    assert scan.probabilities["metadata"] == pytest.approx(0.94)


# --- 3. mismatch detection (1e-4 tolerance) ---------------------------------


@pytest.mark.django_db
def test_load_reports_probability_mismatches_without_stopping(
    golden_dir, media_root, make_user, monkeypatch
):
    """Golden rule: a returned probability differing from golden_samples.csv
    by more than 1e-4 is printed; the load still completes (no invention)."""
    user = make_user(email="demo.owner@example.com")
    rows_by_url = {row["URL"]: row for row in GOLDEN_ROWS}
    fake = make_fake_inference(rows_by_url, offset=0.01)
    monkeypatch.setattr(
        "scans.management.commands.load_demo_samples.InferenceClient", fake
    )
    out = io.StringIO()
    run_load(golden_dir, user.email, stdout=out)
    text = out.getvalue()
    assert "MISMATCH sample T1 mobilenet_phishing_probability" in text
    assert "MISMATCH sample T1 fusion_mlp_phishing_probability" in text
    assert "delta 1.000e-02 > 0.0001" in text
    # 4 samples x (4 base probabilities + fusion), every one beyond 1e-4.
    assert "20 mismatch(es) at 0.0001 tolerance" in text
    assert "4 created, 0 skipped, 0 failed" in text
    assert Scan.objects.filter(owner=user).count() == 4


# --- 3. idempotence ---------------------------------------------------------


@pytest.mark.django_db
def test_load_is_idempotent(golden_dir, media_root, make_user, monkeypatch):
    """ISO-6.5: a second run skips every stored sample (demo_sample_id)."""
    user = make_user(email="demo.owner@example.com")
    rows_by_url = {row["URL"]: row for row in GOLDEN_ROWS}
    monkeypatch.setattr(
        "scans.management.commands.load_demo_samples.InferenceClient",
        make_fake_inference(rows_by_url),
    )
    first = io.StringIO()
    run_load(golden_dir, user.email, stdout=first)
    second = io.StringIO()
    run_load(golden_dir, user.email, stdout=second)
    assert "4 created" in first.getvalue()
    assert "0 created, 4 skipped, 0 failed" in second.getvalue()
    assert Scan.objects.filter(owner=user).count() == 4


# --- 4. BR-01: demo scans never consume a quota -----------------------------


@pytest.mark.django_db
def test_dataset_sample_scans_never_count_in_quota(make_user):
    """BR-01 / US14: DATASET_SAMPLE rows are pre-loaded samples, not user
    submissions, so they must not consume the daily quota."""
    user = make_user(email="demo.user@example.com")
    for index in range(20):
        Scan.objects.create(
            owner=user,
            url=f"https://demo-golden.test/{index}",
            domain="demo-golden.test",
            status=Scan.Status.DETECTED,
            detection_source=Scan.DetectionSource.DATASET_SAMPLE,
        )
    status = get_quota_status(user)
    assert status.used == 0
    assert status.remaining == status.limit
    check_quota(user)  # must NOT raise QuotaExceeded with 20 demo rows
    # A regular submission still counts.
    Scan.objects.create(
        owner=user, url="https://example.com/x", domain="example.com",
        status=Scan.Status.SUBMITTED,
    )
    assert get_quota_status(user).used == 1


# --- 5. demo_setup guard -----------------------------------------------------


@pytest.mark.django_db
def test_demo_setup_refuses_without_allow_flag(settings, golden_dir):
    """Guard: no ALLOW_DEMO_SETUP=1, no provisioning (same idea as ALLOW_SEED)."""
    settings.ALLOW_DEMO_SETUP = False
    out, err = io.StringIO(), io.StringIO()
    with pytest.raises(CommandError) as excinfo:
        call_command("demo_setup", stdout=out, stderr=err)
    assert "ALLOW_DEMO_SETUP=1" in str(excinfo.value)
    assert User.objects.filter(email="demo.admin@example.org").count() == 0
    assert Scan.objects.count() == 0


# --- 6. demo_setup full flow (accounts, model, samples, queue) ---------------


@pytest.mark.django_db
def test_demo_setup_provisions_everything_idempotently(
    golden_dir, media_root, settings, monkeypatch
):
    """End-to-end command: accounts + roles, brand seeds, TORCH_BUNDLE
    registered AND active (BR-11), golden scans loaded, 2 scans in the review
    queue, and a second run creates nothing new."""
    settings.ALLOW_DEMO_SETUP = True
    settings.DEMO_PASSWORD = "DemoPass!123"
    settings.DEMO_SAMPLES_DIR = str(golden_dir)
    # Docker compose sets http://inference:8000 inside the container; the
    # local .env leaves it empty, so mirror the container value here.
    settings.INFERENCE_URL = "http://inference.test:8000"
    rows_by_url = {row["URL"]: row for row in GOLDEN_ROWS}
    monkeypatch.setattr(
        "scans.management.commands.load_demo_samples.InferenceClient",
        make_fake_inference(rows_by_url),
    )
    health = SimpleNamespace(
        status_code=200,
        json=lambda: {"model_bundle_version": "2026-10-25", "checks": {}},
    )
    with mock.patch(
        "scans.management.commands.sync_model_version.requests.get",
        return_value=health,
    ):
        first = io.StringIO()
        call_command("demo_setup", count=4, stdout=first)
        second = io.StringIO()
        call_command("demo_setup", count=4, stdout=second)

    # 1. accounts with their REAL roles; the .env password is used and the
    #    password value itself is never printed (ISO-6.6).
    assert User.objects.filter(
        email="demo.admin@example.org", role="admin"
    ).count() == 1
    assert User.objects.filter(
        email="demo.analyst@example.org", role="analyst"
    ).count() == 1
    assert User.objects.filter(
        email="demo.user@example.org", role="end_user"
    ).count() == 1
    admin = User.objects.get(email="demo.admin@example.org")
    assert admin.check_password("DemoPass!123")
    assert "DemoPass!123" not in first.getvalue()
    assert "from DEMO_PASSWORD in .env" in first.getvalue()

    # 2. one single active TORCH_BUNDLE (BR-11), registered from /health.
    active = ModelVersion.objects.filter(is_active=True)
    assert active.count() == 1
    assert active.first().kind == ModelVersion.Kind.TORCH_BUNDLE
    assert active.first().version == "2026-10-25"

    # 3. golden scans for the demo user + review queue of 2 (uncertain ones
    #    got there through change_status, no fabricated verdicts).
    demo_user = User.objects.get(email="demo.user@example.org")
    scans = Scan.objects.filter(
        owner=demo_user, detection_source=Scan.DetectionSource.DATASET_SAMPLE
    )
    assert scans.count() == 4
    verdicts = {s.demo_sample_id: s.verdict for s in scans}
    assert verdicts["T1"] == "phishing"
    assert verdicts["T2"] == "legitimate"
    assert scans.filter(status=Scan.Status.UNDER_REVIEW).count() == 2
    assert "review queue: 2 scan(s) UNDER_REVIEW" in first.getvalue()
    assert "0 mismatch(es)" in first.getvalue()

    # 4. idempotence: the second run adds nothing.
    assert User.objects.count() == 4  # 3 demo + seed@localhost from seed_brands
    assert scans.count() == 4
    assert "0 created, 4 skipped" in second.getvalue()
