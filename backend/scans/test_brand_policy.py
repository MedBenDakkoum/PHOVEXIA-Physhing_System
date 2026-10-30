"""Transparent non-DL brand policy (US19 / US55 / ISO-6.1).

The model verdict is never erased: these tests prove that the final verdict
may be adjusted by a documented brand rule while model_verdict/model_score keep
the raw model output, that deep links and lookalikes go to the analyst queue
and are never auto-classified as PHISHING, and that the blocklist
short-circuit still wins before any model runs.
"""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status as http_status
from rest_framework.test import APIClient

from blocklist.models import BlocklistEntry, ProtectedBrand
from controlpanel.models import ModelVersion
from scans.models import Scan
from scans.services.brand_policy import (
    BRAND_LOOKALIKE,
    OFFICIAL_BRAND_HOMEPAGE,
    OFFICIAL_DOMAIN_DEEP_LINK,
    apply_brand_policy,
)
from scans.services.collector_client import CollectorResponse
from scans.services.inference_client import InferenceResponse
from scans.tasks import run_scan

User = get_user_model()

SCAN_CREATE = "scan-list"
SCAN_DETAIL = "scan-detail"
PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def install_dns(monkeypatch):
    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 0, 0, 0),
            )
        ]

    monkeypatch.setattr(
        "scans.services.url_validation.socket.getaddrinfo", fake_getaddrinfo
    )


@pytest.fixture(autouse=True)
def _fake_dns(monkeypatch):
    install_dns(monkeypatch)


@pytest.fixture
def google(admin):
    return ProtectedBrand.objects.create(
        name="Google", domain="google.com", is_active=True, created_by=admin
    )


@pytest.fixture
def paypal(admin):
    return ProtectedBrand.objects.create(
        name="PayPal", domain="paypal.com", is_active=True, created_by=admin
    )


@pytest.fixture
def media_root(settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path
    return tmp_path


def make_bundle(version="bundle-1"):
    ModelVersion.objects.filter(is_active=True).update(is_active=False)
    return ModelVersion.objects.create(
        name="torch-bundle",
        version=version,
        kind=ModelVersion.Kind.TORCH_BUNDLE,
        is_active=True,
        file_path="",
        sha256="",
        metrics={},
    )


def capture(url="https://www.google.com/"):
    return CollectorResponse(
        {
            "status": "complete",
            "reason_code": None,
            "final_url": url,
            "redirect_chain": [url],
            "http_status": 200,
            "text": "page text",
            "ssl": 1,
            "tld": "com",
            "domain": "google.com",
            "fld": "google.com",
            "subdomain": "www",
            "screenshot_png_base64": PNG_B64,
            "tls": {},
            "timings_ms": {},
        }
    )


def inference(probability=0.93):
    return InferenceResponse(
        {
            "status": "complete",
            "partial": False,
            "prediction": "phishing",
            "phishing_probability": probability,
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
    )


def install_pipeline(monkeypatch, *, probability=0.93, capture_url="https://www.google.com/"):
    class _FakeCollector:
        def collect(self, url):
            return capture(capture_url)

    class _FakeInference:
        def predict(self, **kwargs):
            return inference(probability)

    monkeypatch.setattr("scans.tasks.CollectorClient", _FakeCollector)
    monkeypatch.setattr("scans.tasks.InferenceClient", _FakeInference)


def make_scan(owner, *, url="https://www.google.com/", domain="www.google.com"):
    return Scan.objects.create(
        owner=owner,
        url=url,
        domain=domain,
        mode=Scan.Mode.FULL,
        status=Scan.Status.SUBMITTED,
    )


# --- 1. official home page overridden when the model says PHISHING -----------


@pytest.mark.django_db
def test_official_homepage_is_overridden_and_the_raw_model_verdict_is_kept(
    monkeypatch, media_root, google, viewer
):
    make_bundle()
    install_pipeline(monkeypatch, probability=0.93)
    scan = make_scan(viewer)

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.DETECTED
    assert scan.verdict == "legitimate"  # FINAL decision
    assert scan.score == pytest.approx(0.93)
    assert scan.model_verdict == "phishing"  # raw output preserved
    assert scan.model_score == pytest.approx(0.93)
    assert scan.detection_source == Scan.DetectionSource.BRAND_POLICY
    assert scan.policy_flags == [
        {"code": OFFICIAL_BRAND_HOMEPAGE, "brand": "google.com"}
    ]
    assert "Page d'accueil officielle" in scan.policy_note


# --- 2. deep link: not overridden, sent to review ---------------------------


@pytest.mark.django_db
def test_official_domain_deep_link_is_not_overridden_but_goes_to_review(
    monkeypatch, media_root, google, viewer
):
    make_bundle()
    install_pipeline(
        monkeypatch, probability=0.93, capture_url="https://www.google.com/search?q=a"
    )
    scan = make_scan(
        viewer, url="https://www.google.com/search?q=a", domain="www.google.com"
    )

    run_scan(scan.pk)

    scan.refresh_from_db()
    assert scan.status == Scan.Status.UNDER_REVIEW
    assert scan.verdict == "phishing"  # model verdict untouched
    assert scan.model_verdict == "phishing"
    assert scan.detection_source == Scan.DetectionSource.MODEL
    assert scan.policy_flags[0]["code"] == OFFICIAL_DOMAIN_DEEP_LINK
    assert scan.policy_flags[0]["brand"] == "google.com"


# --- 3. www is official, another subdomain is not ---------------------------


@pytest.mark.django_db
def test_www_variant_is_official_but_another_subdomain_is_not(google):
    www = apply_brand_policy(
        url="https://www.google.com/",
        host="www.google.com",
        model_verdict="phishing",
        model_score=0.9,
    )
    assert www.verdict == "legitimate"
    assert www.detection_source == Scan.DetectionSource.BRAND_POLICY

    mail = apply_brand_policy(
        url="https://mail.google.com/",
        host="mail.google.com",
        model_verdict="phishing",
        model_score=0.9,
    )
    assert mail.verdict == "phishing"  # never auto-legitimate
    assert mail.detection_source == Scan.DetectionSource.MODEL
    assert mail.escalate_to_review is True
    assert mail.flags[0]["code"] == OFFICIAL_DOMAIN_DEEP_LINK


# --- 4. lookalike: review, never auto-PHISHING ------------------------------


@pytest.mark.django_db
def test_lookalike_escalates_a_legitimate_verdict_to_review_without_changing_it(
    paypal,
):
    result = apply_brand_policy(
        url="https://paypa1.com/",
        host="paypa1.com",
        model_verdict="legitimate",
        model_score=0.1,
    )

    assert result.verdict == "legitimate"  # never auto-PHISHING
    assert result.escalate_to_review is True
    assert result.flags[0]["code"] == BRAND_LOOKALIKE
    assert result.flags[0]["brand"] == "paypal.com"
    assert isinstance(result.flags[0]["distance"], int)


@pytest.mark.django_db
def test_lookalike_does_not_turn_an_uncertain_scan_into_phishing(paypal):
    result = apply_brand_policy(
        url="https://paypa1.com/",
        host="paypa1.com",
        model_verdict="uncertain",
        model_score=0.55,
    )

    assert result.verdict == "uncertain"
    assert result.escalate_to_review is True
    assert result.flags[0]["code"] == BRAND_LOOKALIKE


# --- 5. model verdict preserved / no flag without a rule --------------------


@pytest.mark.django_db
def test_unrelated_domain_is_never_flagged_and_the_model_decision_stays_final(
    google,
):
    result = apply_brand_policy(
        url="https://example.com/login",
        host="example.com",
        model_verdict="phishing",
        model_score=0.88,
    )

    assert result.verdict == "phishing"
    assert result.score == pytest.approx(0.88)
    assert result.flags == []
    assert result.detection_source == Scan.DetectionSource.MODEL
    assert result.escalate_to_review is False


# --- 6. blocklist short-circuit still wins ----------------------------------


@pytest.mark.django_db
def test_blocklist_short_circuit_wins_over_the_brand_policy(
    monkeypatch, google, analyst, viewer
):
    calls = SimpleNamespace(collector=[], inference=[])

    class _FakeCollector:
        def collect(self, url):
            calls.collector.append(url)

    class _FakeInference:
        def predict(self, **kwargs):
            calls.inference.append(kwargs)

    monkeypatch.setattr("scans.tasks.CollectorClient", _FakeCollector)
    monkeypatch.setattr("scans.tasks.InferenceClient", _FakeInference)
    make_bundle()
    BlocklistEntry.objects.create(
        domain="google.com", reason="confirmed_phishing", added_by=analyst
    )

    client = APIClient()
    client.force_authenticate(viewer)
    resp = client.post(
        reverse(SCAN_CREATE), {"url": "https://www.google.com/"}, format="json"
    )

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    scan = Scan.objects.get(public_id=resp.data["id"])
    assert scan.verdict == "phishing"
    assert scan.score == 1.0
    assert scan.detection_source == Scan.DetectionSource.BLOCKLIST
    assert scan.model_verdict is None
    assert scan.policy_flags == []
    assert calls.collector == [] and calls.inference == []


# --- 7. serializers: owner and analyst see the raw output + flags -----------


@pytest.mark.django_db
def test_owner_and_analyst_see_model_verdict_and_policy_flags(google, viewer, analyst):
    scan = make_scan(viewer, url="https://www.google.com/", domain="www.google.com")
    scan.verdict = "legitimate"
    scan.score = 0.9
    scan.model_verdict = "phishing"
    scan.model_score = 0.9
    scan.policy_flags = [{"code": OFFICIAL_BRAND_HOMEPAGE, "brand": "google.com"}]
    scan.detection_source = Scan.DetectionSource.BRAND_POLICY
    scan.status = Scan.Status.DETECTED
    scan.save()

    owner_client = APIClient()
    owner_client.force_authenticate(viewer)
    owner_data = owner_client.get(reverse(SCAN_DETAIL, args=[scan.public_id])).data
    assert owner_data["model_verdict"] == "phishing"
    assert owner_data["model_score"] == pytest.approx(0.9)
    assert owner_data["policy_flags"][0]["code"] == OFFICIAL_BRAND_HOMEPAGE

    analyst_client = APIClient()
    analyst_client.force_authenticate(analyst)
    analyst_data = analyst_client.get(reverse(SCAN_DETAIL, args=[scan.public_id])).data
    assert analyst_data["model_verdict"] == "phishing"
    assert analyst_data["policy_flags"][0]["code"] == OFFICIAL_BRAND_HOMEPAGE


# --- 8. homepage means no query / fragment / credentials --------------------


@pytest.mark.django_db
def test_homepage_requires_no_query_fragment_or_credentials(google):
    with_query = apply_brand_policy(
        url="https://google.com/?q=1",
        host="google.com",
        model_verdict="phishing",
        model_score=0.9,
    )
    assert with_query.verdict == "phishing"
    assert with_query.flags[0]["code"] == OFFICIAL_DOMAIN_DEEP_LINK

    with_fragment = apply_brand_policy(
        url="https://google.com/#top",
        host="google.com",
        model_verdict="phishing",
        model_score=0.9,
    )
    assert with_fragment.verdict == "phishing"
    assert with_fragment.flags[0]["code"] == OFFICIAL_DOMAIN_DEEP_LINK
