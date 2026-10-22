"""
Step 12 tests - admin control panel (US45, US48, US49, US52, US53, US54 / BR-11).

DNS is ALWAYS mocked: no test touches the network. The suite runs unchanged
on SQLite and PostgreSQL.

Requirement tags: US45 (dashboard), US48 (model versions), US49 (compare),
US52 (detection settings), US53 (health), US54 (API keys), BR-11 (one active
model), ISO-6.1 (tests), ISO-6.6 (public UUIDs, no secrets leaked).
"""
import hashlib
import socket
from unittest import mock

import pytest
from celery import current_app
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from rest_framework import status as http_status
from rest_framework.test import APIClient

from audit.models import AuditLog
from controlpanel.models import ApiKey, DetectionSettings, ModelVersion
from controlpanel.services import get_detection_settings
from controlpanel.services.health import (
    _redis_client,
    build_health,
    check_celery,
    check_queue_length,
    check_redis,
    check_stuck_scans,
)
from scans.models import Scan
from scans.services import url_validation
from scans.tasks import run_scan

PUBLIC_V4 = "93.184.216.34"
VALID_URL = "https://example.com/login?user=1"
DOMAIN = "example.com"

SETTINGS_URL = reverse("admin-settings")
DASHBOARD_URL = reverse("admin-dashboard")
ADMIN_HEALTH_URL = reverse("admin-health")
PUBLIC_HEALTH_URL = reverse("public-health")
MODEL_LIST_URL = reverse("admin-model-list")
APIKEY_LIST_URL = reverse("admin-apikey-list")

MOCK_VERSION = "mock-0"


def install_dns(monkeypatch, mapping, default=PUBLIC_V4):
    """Fake resolver: mapping[host] when present, else `default`."""

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        addresses = mapping.get(host, [default])
        if addresses is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        out = []
        for addr in addresses:
            out.append(
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))
            )
        return out

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Default: every hostname resolves to a public address (no real DNS)."""
    install_dns(monkeypatch, {})


@pytest.fixture
def mock0(db):
    return ModelVersion.objects.get(version=MOCK_VERSION)


def register_model(admin_client, name="cnn-v1", version="cnn-1", **extra):
    payload = {"name": name, "version": version, "kind": "MOCK", **extra}
    return admin_client.post(MODEL_LIST_URL, payload, format="json")


def create_key(admin_client, **extra):
    payload = {
        "name": extra.pop("name", "ci-key"),
        "scopes": extra.pop("scopes", ["scan:create", "scan:read"]),
        **extra,
    }
    resp = admin_client.post(APIKEY_LIST_URL, payload, format="json")
    assert resp.status_code == http_status.HTTP_201_CREATED, resp.data
    return resp.data


# --- US52: detection settings ------------------------------------------------


@pytest.mark.django_db
def test_settings_get_falls_back_to_django_values_when_the_table_is_empty(admin_client):
    assert not DetectionSettings.objects.exists()

    resp = admin_client.get(SETTINGS_URL)

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["phishing_threshold"] == 0.70
    assert resp.data["uncertain_lower"] == 0.40
    assert resp.data["daily_scan_quota"] == 20
    assert resp.data["quick_check_hourly_limit"] == 5
    assert resp.data["updated_at"] is None
    assert resp.data["updated_by_email"] is None


@pytest.mark.django_db
def test_settings_patch_validation_refuses_bad_ranges_and_quotas(admin_client):
    # Cross-field rule: 0 < uncertain_lower < phishing_threshold <= 1.
    resp = admin_client.patch(
        SETTINGS_URL,
        {"phishing_threshold": 0.30, "uncertain_lower": 0.50},
        format="json",
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "invalid_settings"

    # Quotas: integers >= 1 and <= a sane maximum.
    resp = admin_client.patch(SETTINGS_URL, {"daily_scan_quota": 0}, format="json")
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    resp = admin_client.patch(
        SETTINGS_URL, {"quick_check_hourly_limit": 10_000_000}, format="json"
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    resp = admin_client.patch(
        SETTINGS_URL, {"phishing_threshold": 1.5}, format="json"
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST

    # Nothing was written by the refusals.
    assert not DetectionSettings.objects.exists()
    assert get_detection_settings().phishing_threshold == 0.70


@pytest.mark.django_db
def test_settings_patch_refreshes_the_cache_and_audits_old_and_new(admin_client):
    resp = admin_client.patch(
        SETTINGS_URL,
        {"phishing_threshold": 0.90, "uncertain_lower": 0.50},
        format="json",
    )
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["phishing_threshold"] == 0.90

    # The 30 s cache is cleared on PATCH: the very next read is fresh.
    assert get_detection_settings().phishing_threshold == 0.90
    again = admin_client.get(SETTINGS_URL)
    assert again.data["phishing_threshold"] == 0.90
    assert again.data["updated_by_email"] == "admin@example.com"

    entry = AuditLog.objects.get(action=AuditLog.Action.SETTINGS_CHANGED)
    assert entry.metadata["old"]["phishing_threshold"] == 0.70
    assert entry.metadata["new"]["phishing_threshold"] == 0.90


# --- US48 / BR-11: model versions --------------------------------------------


@pytest.mark.django_db
def test_only_one_model_version_is_ever_active_and_activation_is_audited(
    admin_client, mock0
):
    created = register_model(admin_client)
    assert created.status_code == http_status.HTTP_201_CREATED
    version = ModelVersion.objects.get(public_id=created.data["id"])
    assert version.is_active is False

    resp = admin_client.post(
        reverse("admin-model-activate", args=[version.public_id])
    )
    assert resp.status_code == http_status.HTTP_200_OK

    mock0.refresh_from_db()
    version.refresh_from_db()
    assert mock0.is_active is False
    assert version.is_active is True
    assert ModelVersion.objects.filter(is_active=True).count() == 1

    entry = AuditLog.objects.get(action=AuditLog.Action.MODEL_ACTIVATED)
    assert entry.metadata["version"] == "cnn-1"
    assert entry.metadata["rollback"] is False

    # BR-11 database backstop: a second ACTIVE row is refused outright.
    other = ModelVersion.objects.create(name="x", version="x-1", kind="MOCK")
    other.is_active = True
    with pytest.raises(IntegrityError), transaction.atomic():
        other.save(update_fields=["is_active"])


@pytest.mark.django_db
def test_activation_verifies_the_file_hash_and_refuses_path_traversal(
    admin_client, settings, tmp_path, mock0
):
    settings.MODELS_DIR = tmp_path
    model_file = tmp_path / "v1.onnx"
    model_file.write_bytes(b"weights-v1")
    good_sha = hashlib.sha256(b"weights-v1").hexdigest()

    created = register_model(
        admin_client, name="onnx-v1", version="onnx-1", kind="ONNX",
        file_path="v1.onnx",
    )
    assert created.status_code == http_status.HTTP_201_CREATED, created.data
    assert created.data["sha256"] == good_sha
    version = ModelVersion.objects.get(public_id=created.data["id"])

    # Path traversal must be refused at registration.
    traversal = register_model(
        admin_client, name="evil", version="evil-1", kind="ONNX",
        file_path="../evil.onnx",
    )
    assert traversal.status_code == http_status.HTTP_400_BAD_REQUEST
    assert traversal.data["code"] == "path_traversal"

    # Tampering with the file after registration blocks activation.
    model_file.write_bytes(b"tampered!")
    resp = admin_client.post(
        reverse("admin-model-activate", args=[version.public_id])
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "sha256_mismatch"
    assert mock0.is_active is True


@pytest.mark.django_db
def test_model_list_and_detail_expose_versions_and_bad_metrics_are_400(
    admin_client, mock0
):
    created = register_model(
        admin_client, metrics={"precision": 0.91, "dataset": "test-v3"}
    )
    assert created.status_code == http_status.HTTP_201_CREATED

    # US48: the admin can consult every version, newest first.
    listed = admin_client.get(MODEL_LIST_URL)
    assert listed.status_code == http_status.HTTP_200_OK
    versions = [item["version"] for item in listed.data["results"]]
    assert versions[0] == "cnn-1"
    assert MOCK_VERSION in versions

    detail = admin_client.get(reverse("admin-model-detail", args=[mock0.public_id]))
    assert detail.status_code == http_status.HTTP_200_OK
    assert detail.data["version"] == MOCK_VERSION
    assert detail.data["is_active"] is True

    # Metrics must stay numbers/strings/simple values, never nested.
    for index, bad_metrics in enumerate(
        ({"precision": "high"}, {"dataset": 42}, {"extra": {"nested": True}})
    ):
        resp = register_model(
            admin_client,
            name=f"bad-{index}",
            version=f"bad-{index}",
            metrics=bad_metrics,
        )
        assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
        assert resp.data["code"] == "invalid_request"


@pytest.mark.django_db
def test_rollback_reactivates_the_previous_version_and_409_when_none(admin_client, mock0):
    # Fresh install: mock-0 is active and was never preceded by another one.
    resp = admin_client.post(reverse("admin-model-rollback"))
    assert resp.status_code == http_status.HTTP_409_CONFLICT
    assert resp.data["code"] == "no_previous_version"

    created = register_model(admin_client)
    version = ModelVersion.objects.get(public_id=created.data["id"])
    admin_client.post(reverse("admin-model-activate", args=[version.public_id]))

    resp = admin_client.post(reverse("admin-model-rollback"))
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["version"] == MOCK_VERSION

    mock0.refresh_from_db()
    version.refresh_from_db()
    assert mock0.is_active is True
    assert version.is_active is False
    entry = AuditLog.objects.filter(action=AuditLog.Action.MODEL_ACTIVATED).latest(
        "created_at"
    )
    assert entry.metadata["rollback"] is True


@pytest.mark.django_db
def test_compare_shows_metrics_side_by_side_and_refuses_short_or_unknown_ids(
    admin_client, mock0
):
    created = register_model(
        admin_client,
        metrics={"precision": 0.91, "recall": 0.80, "f1": 0.85},
    )
    assert created.status_code == http_status.HTTP_201_CREATED

    # Fewer than 2 ids -> 400.
    resp = admin_client.get(
        reverse("admin-model-compare"), {"ids": str(mock0.public_id)}
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    # Unknown id -> 400.
    resp = admin_client.get(
        reverse("admin-model-compare"),
        {"ids": f"{mock0.public_id},11111111-1111-1111-1111-111111111111"},
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "unknown_id"

    resp = admin_client.get(
        reverse("admin-model-compare"),
        {"ids": f"{created.data['id']},{mock0.public_id}"},
    )
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["baseline_id"] == str(created.data["id"])
    assert [m["version"] for m in resp.data["models"]] == ["cnn-1", MOCK_VERSION]
    precision = next(m for m in resp.data["metrics"] if m["metric"] == "precision")
    assert precision["values"] == [0.91, None]
    assert precision["delta_vs_baseline"] == [0, None]


# --- US48: scan.model_version filled at prediction time ----------------------


@pytest.mark.django_db
def test_the_scan_is_stamped_with_the_active_model_version(viewer, mock0):
    scan = Scan.objects.create(owner=viewer, url=VALID_URL, domain=DOMAIN)

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.model_version == MOCK_VERSION
    assert scan.verdict in ("phishing", "legitimate", "uncertain")


# --- US45: dashboard ---------------------------------------------------------


@pytest.mark.django_db
def test_dashboard_totals_on_a_small_fixed_dataset(make_user, admin_client):
    owner = make_user(email="u1@example.com", role="end_user")

    def scan(**fields):
        defaults = {"url": VALID_URL, "domain": DOMAIN, "mode": "fast", "owner": owner}
        defaults.update(fields)
        return Scan.objects.create(**defaults)

    now = timezone.now()
    scan(
        verdict="phishing", status="confirmed", finished_at=now, domain="bad.example"
    )
    scan(
        verdict="phishing", status="false_positive", finished_at=now,
        domain="bad.example",
    )
    scan(verdict="uncertain", status="under_review", domain="other.example")
    scan(
        owner=None, verdict="phishing", status="blocked", finished_at=now,
        detection_source="blocklist", domain="blocked.example",
    )

    resp = admin_client.get(DASHBOARD_URL, {"period": "7d"})

    assert resp.status_code == http_status.HTTP_200_OK
    data = resp.data
    assert data["period"]["label"] == "7d"
    assert data["totals"]["scans"] == 4
    assert data["scans_by_verdict"]["phishing"] == 3
    assert data["scans_by_verdict"]["uncertain"] == 1
    assert data["scans_by_status"]["under_review"] == 1
    assert data["scans_by_detection_source"]["blocklist"] == 1
    assert data["phishing_rate"] == pytest.approx(0.75)
    # FALSE_POSITIVE / (CONFIRMED + FALSE_POSITIVE) = 1 / 2.
    assert data["false_positive_rate"] == pytest.approx(0.5)
    assert data["pending_reviews"] == 1
    assert data["median_scan_duration_seconds"] is not None
    assert data["quick_checks"] == 1
    assert data["top_phishing_domains"][0]["domain"] == "bad.example"
    assert data["top_phishing_domains"][0]["count"] == 2
    assert data["users_by_role"]["end_user"] == 1
    assert len(data["scans_per_day"]) >= 1

    # Invalid period -> 400, never 500.
    resp = admin_client.get(DASHBOARD_URL, {"period": "1y"})
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    resp = admin_client.get(DASHBOARD_URL, {"from": "2026-10-05"})
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_dashboard_custom_date_range_is_inclusive_and_bad_ranges_are_400(
    admin_client,
):
    # No parameter at all -> the default period.
    resp = admin_client.get(DASHBOARD_URL)
    assert resp.status_code == http_status.HTTP_200_OK

    # Custom from/to: both bounds inclusive, label = the raw pair.
    resp = admin_client.get(DASHBOARD_URL, {"from": "2026-10-01", "to": "2026-10-21"})
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["period"]["label"] == "2026-10-01:2026-10-21"

    # Second call inside the 60 s cache -> identical payload, no rebuild.
    cached = admin_client.get(DASHBOARD_URL, {"from": "2026-10-01", "to": "2026-10-21"})
    assert cached.data == resp.data

    # An empty window keeps the shape and the ratios at null (no division by 0).
    empty = admin_client.get(DASHBOARD_URL, {"from": "2027-01-01", "to": "2027-01-02"})
    assert empty.status_code == http_status.HTTP_200_OK
    assert empty.data["totals"]["scans"] == 0
    assert empty.data["phishing_rate"] is None
    assert empty.data["false_positive_rate"] is None
    assert empty.data["median_scan_duration_seconds"] is None

    # period and from/to are mutually exclusive.
    resp = admin_client.get(
        DASHBOARD_URL, {"period": "7d", "from": "2026-10-01", "to": "2026-10-21"}
    )
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST

    # from after to -> 400; malformed date -> 400.
    resp = admin_client.get(DASHBOARD_URL, {"from": "2026-10-21", "to": "2026-10-01"})
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    resp = admin_client.get(DASHBOARD_URL, {"from": "01-10-2026", "to": "2026-10-21"})
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST


# --- US53: health ------------------------------------------------------------


@pytest.mark.django_db
def test_public_health_is_minimal_and_admin_health_reports_failures_without_crashing(
    admin_client, monkeypatch, settings
):
    resp = admin_client.get(PUBLIC_HEALTH_URL)
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data == {"status": "ok"}

    # Real client construction (no I/O at all) -> the import path is covered.
    assert _redis_client("redis://localhost:6379/1") is not None

    # Success / not-configured branches of redis + queue, still without any
    # network call: _redis_client is replaced by a tiny fake.
    class FakeRedis:
        def ping(self):
            return True

        def llen(self, key):
            return 0

    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(
        "controlpanel.services.health._redis_client", lambda url: FakeRedis()
    )
    assert check_redis() == {"ok": True, "message": "ok", "value": None}
    assert check_queue_length()["ok"] is True
    assert check_queue_length()["value"] == 0

    # A broker that refuses the connection is reported, never raised.
    def _refused(url):
        raise OSError("conn refused")

    monkeypatch.setattr("controlpanel.services.health._redis_client", _refused)
    result = check_queue_length()
    assert result["ok"] is False
    assert result["message"] == "error (OSError)"
    assert check_redis()["ok"] is False

    monkeypatch.delenv("REDIS_URL", raising=False)
    assert check_redis() == {
        "ok": False,
        "message": "not configured",
        "value": None,
    }
    settings.CELERY_BROKER_URL = ""
    assert check_queue_length()["message"] == "not configured"

    # Celery: no worker / worker / broker failure (ping is stubbed).
    control = current_app.control
    with mock.patch.object(control, "ping", return_value=[]):
        assert check_celery() == {
            "ok": False,
            "message": "unreachable (no worker)",
            "value": 0,
        }
    with mock.patch.object(control, "ping", return_value=[{"worker@1": "pong"}]):
        assert check_celery() == {
            "ok": True,
            "message": "1 worker(s)",
            "value": 1,
        }
    with mock.patch.object(control, "ping", side_effect=OSError("broker down")):
        result = check_celery()
        assert result["ok"] is False
        assert result["message"] == "unreachable (OSError)"

    # The view must run with redis configured so `boom` really executes and
    # the SECRET embedded in its message proves it never leaks.
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")

    def boom(*args, **kwargs):
        raise ConnectionError("redis://user:SECRET@host/0 boom")

    monkeypatch.setattr(
        "controlpanel.services.health._redis_client", boom
    )
    monkeypatch.setattr(
        "controlpanel.services.health.check_celery",
        lambda: {"ok": False, "message": "unreachable (ping failed)", "value": None},
    )

    resp = admin_client.get(ADMIN_HEALTH_URL)

    assert resp.status_code == http_status.HTTP_200_OK
    data = resp.data
    assert data["status"] == "degraded"
    assert data["checks"]["database"]["ok"] is True
    assert data["checks"]["redis"]["ok"] is False
    assert data["checks"]["celery"]["ok"] is False
    body = resp.content.decode()
    assert "SECRET" not in body
    assert "Traceback" not in body

    # A check that blows up entirely is caught by build_health itself and
    # reported as a safe `error (<class>)` message (never str(exc)).
    monkeypatch.setattr("controlpanel.services.health.check_database", boom)
    health = build_health()
    assert health["checks"]["database"] == {
        "ok": False,
        "message": "error (ConnectionError)",
        "value": None,
    }
    assert health["status"] == "degraded"
    assert isinstance(build_health()["checks"], dict)
    assert check_stuck_scans()["ok"] is True


# --- US54: API keys ----------------------------------------------------------


@pytest.mark.django_db
def test_api_key_secret_is_shown_once_and_never_stored_or_listed_again(admin_client):
    data = create_key(admin_client)
    secret = data["secret"]

    assert len(secret) >= 40
    assert data["key_prefix"] == secret[:8]
    assert "key_hash" not in data
    assert "revoked_at" in data

    listed = admin_client.get(APIKEY_LIST_URL)
    assert listed.status_code == http_status.HTTP_200_OK
    assert secret not in str(listed.data)
    assert "secret" not in listed.data["results"][0]

    row = ApiKey.objects.get(public_id=data["id"])
    assert row.key_hash == hashlib.sha256(secret.encode()).hexdigest()
    assert secret != row.key_hash
    assert secret not in row.key_prefix

    # Bad body (missing scopes) -> 400 with the DRF field errors.
    resp = admin_client.post(APIKEY_LIST_URL, {"name": "no-scope"}, format="json")
    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert resp.data["code"] == "invalid_request"
    assert "scopes" in resp.data["errors"]


@pytest.mark.django_db
def test_api_key_authenticates_scan_create_and_detail_as_its_owner(admin_client, admin):
    data = create_key(admin_client)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Api-Key {data['secret']}")

    created = client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert created.status_code == http_status.HTTP_202_ACCEPTED, created.data

    scan = Scan.objects.get(public_id=created.data["id"])
    assert scan.owner == admin  # the key acts as its OWNER

    detail = client.get(reverse("scan-detail", args=[scan.public_id]))
    assert detail.status_code == http_status.HTTP_200_OK
    # The Celery task never runs inside a test transaction (on_commit not
    # fired), so the scan is still un-predicted: model_version is empty.
    assert detail.data["model_version"] == ""

    # A read-only key may not create (scope enforced -> 403).
    readonly = create_key(admin_client, name="ro", scopes=["scan:read"])
    ro_client = APIClient()
    ro_client.credentials(HTTP_AUTHORIZATION=f"Api-Key {readonly['secret']}")
    refused = ro_client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert refused.status_code == http_status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_api_key_is_refused_on_every_other_endpoint(admin_client):
    data = create_key(admin_client)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Api-Key {data['secret']}")

    # Not in the allowlist (list, quick check, admin endpoints) -> 401.
    assert client.get(reverse("scan-list")).status_code == http_status.HTTP_401_UNAUTHORIZED
    assert client.get(SETTINGS_URL).status_code == http_status.HTTP_401_UNAUTHORIZED
    assert client.get(DASHBOARD_URL).status_code == http_status.HTTP_401_UNAUTHORIZED
    quick = client.post(
        reverse("quick-check"), {"url": VALID_URL}, format="json"
    )
    assert quick.status_code == http_status.HTTP_401_UNAUTHORIZED
    # The public health endpoint is not in the allowlist either.
    assert client.get(PUBLIC_HEALTH_URL).status_code == http_status.HTTP_401_UNAUTHORIZED

    # The same key still works where it is allowed.
    ok = client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert ok.status_code == http_status.HTTP_202_ACCEPTED


@pytest.mark.django_db
def test_revoked_and_expired_keys_are_refused(admin_client):
    revoked = create_key(admin_client, name="to-revoke")
    resp = admin_client.delete(
        reverse("admin-apikey-revoke", args=[revoked["id"]])
    )
    assert resp.status_code == http_status.HTTP_204_NO_CONTENT
    entry = AuditLog.objects.get(action=AuditLog.Action.APIKEY_REVOKED)
    assert revoked["secret"] not in str(entry.metadata)

    expired = create_key(
        admin_client,
        name="expired",
        expires_at=(timezone.now() - timezone.timedelta(minutes=1)).isoformat(),
    )

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Api-Key {revoked['secret']}")
    resp = client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED

    client.credentials(HTTP_AUTHORIZATION=f"Api-Key {expired['secret']}")
    resp = client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED

    # Unknown secret -> 401 too (hash lookup finds nothing).
    client.credentials(HTTP_AUTHORIZATION="Api-Key totally-made-up-secret")
    resp = client.post(reverse("scan-list"), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED


# --- permissions: every endpoint is admin only -------------------------------


@pytest.mark.django_db
def test_every_controlpanel_endpoint_refuses_anonymous_and_non_admins(api_client, mock0):
    mid = mock0.public_id
    cases = [
        ("get", SETTINGS_URL),
        ("patch", SETTINGS_URL),
        ("get", MODEL_LIST_URL),
        ("post", MODEL_LIST_URL),
        ("get", reverse("admin-model-detail", args=[mid])),
        ("post", reverse("admin-model-activate", args=[mid])),
        ("post", reverse("admin-model-rollback")),
        ("get", reverse("admin-model-compare") + "?ids=a,b"),
        ("get", DASHBOARD_URL),
        ("get", ADMIN_HEALTH_URL),
        ("get", APIKEY_LIST_URL),
        ("post", APIKEY_LIST_URL),
        ("delete", reverse("admin-apikey-revoke", args=[mid])),
    ]

    # 1) anonymous -> 401 everywhere (the public health endpoint is the only
    #    non-admin route and is not part of this list).
    for method, url in cases:
        resp = _call(api_client, method, url)
        assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED, (
            method,
            url,
            resp.status_code,
        )

    # 2) authenticated but NOT admin -> 403 everywhere.
    api_client.force_authenticate(
        get_user_model().objects.create_user(
            email="someone@example.com", password="x", role="analyst"
        )
    )
    for method, url in cases:
        resp = _call(api_client, method, url)
        assert resp.status_code == http_status.HTTP_403_FORBIDDEN, (
            method,
            url,
            resp.status_code,
        )


def _call(client, method: str, url: str):
    """GET without a body (the query string stays in the URL), others with {}."""
    if method == "get":
        return client.get(url)
    return getattr(client, method)(url, {}, format="json")
