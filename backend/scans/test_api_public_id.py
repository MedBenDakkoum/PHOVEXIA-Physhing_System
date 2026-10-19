"""
Step 8a tests - public UUID id on scans (US12, US16, US30 / ISO-6.6).

The API must never expose the sequential integer primary key: every response
carries the public UUID (`public_id`) and every scan URL is
/api/scans/<uuid>/. The Celery task keeps receiving the internal pk.

DNS is ALWAYS mocked: no test touches the network. The suite runs unchanged
on SQLite and PostgreSQL (see docs/HANDOFF.md for the exact commands).

Requirement tags: US12, US16, US30, ISO-6.6, BR-04.
"""
import re
import socket
from uuid import uuid4

import pytest
from django.urls import reverse
from rest_framework import status as http_status

from audit.models import AuditLog
from scans.models import Scan
from scans.services import url_validation

PUBLIC_V4 = "93.184.216.34"
VALID_URL = "https://example.com/login?user=1"
DOMAIN = "example.com"

SCAN_LIST = "scan-list"
SCAN_DETAIL = "scan-detail"

# A JSON body that contains an integer-valued "id" key (the old contract).
INTEGER_ID_PATTERN = re.compile(r'"id":\s*\d+')


def install_dns(monkeypatch, mapping, default=PUBLIC_V4):
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


# --- public_id on the model --------------------------------------------------


@pytest.mark.django_db
def test_public_id_is_auto_generated_and_unique():
    a = Scan.objects.create(url=VALID_URL, domain=DOMAIN)
    b = Scan.objects.create(url=VALID_URL, domain=DOMAIN)
    assert a.public_id is not None
    assert b.public_id is not None
    assert a.public_id != b.public_id


@pytest.mark.django_db
def test_public_id_is_not_editable_through_the_orm_default():
    """The field carries editable=False (admin/forms cannot set it)."""
    field = Scan._meta.get_field("public_id")
    assert field.editable is False
    assert field.unique is True


# --- the integer pk never appears in a response ------------------------------


@pytest.mark.django_db
def test_post_202_id_is_the_uuid_and_never_the_integer_pk(auth_client, viewer):
    resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED

    scan = Scan.objects.get(public_id=resp.data["id"])
    assert resp.data["id"] == str(scan.public_id)
    assert resp.data["id"] != str(scan.pk)
    assert not INTEGER_ID_PATTERN.search(resp.content.decode())


@pytest.mark.django_db
def test_list_ids_are_uuids_and_never_integer_pks(auth_client, viewer):
    scans = [make_scan(viewer, url=f"https://example.com/{i}") for i in range(3)]
    resp = auth_client.get(reverse(SCAN_LIST))
    assert resp.status_code == http_status.HTTP_200_OK

    body = resp.content.decode()
    assert not INTEGER_ID_PATTERN.search(body)
    ids = [item["id"] for item in resp.data["results"]]
    assert ids == [str(s.public_id) for s in reversed(scans)]
    for item in resp.data["results"]:
        assert item["id"] != str(next(s.pk for s in scans if str(s.public_id) == item["id"]))


@pytest.mark.django_db
def test_detail_id_is_the_uuid_and_never_the_integer_pk(auth_client, viewer):
    scan = make_scan(viewer)
    resp = auth_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["id"] == str(scan.public_id)
    assert resp.data["id"] != str(scan.pk)
    assert not INTEGER_ID_PATTERN.search(resp.content.decode())


@pytest.mark.django_db
def test_the_integer_pk_in_the_url_is_404(auth_client, viewer):
    """The old /api/scans/<int>/ contract is dead: the converter refuses it."""
    scan = make_scan(viewer)
    resp = auth_client.get(f"/api/scans/{scan.pk}/")
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


# --- unknown / malformed / foreign ids ---------------------------------------


@pytest.mark.django_db
def test_detail_unknown_but_well_formed_uuid_is_404(auth_client, viewer):
    make_scan(viewer)
    resp = auth_client.get(reverse(SCAN_DETAIL, args=[str(uuid4())]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
@pytest.mark.parametrize(
    "raw",
    [
        "not-a-uuid",
        "123",
        "00000000-0000-0000-0000-00000000000g",
        "12345678123412341234123456789012",
        "12345678-1234-1234-1234-12345678901",
        "../../../etc/passwd",
        "<script>",
    ],
    ids=[
        "words",
        "int-like",
        "bad-hex",
        "no-dashes",
        "too-short",
        "traversal",
        "xss",
    ],
)
def test_detail_malformed_id_is_404_never_500(auth_client, viewer, raw):
    make_scan(viewer)
    resp = auth_client.get(f"/api/scans/{raw}/")
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND
    assert resp.status_code != http_status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.django_db
def test_detail_another_users_scan_by_uuid_is_404(make_user, api_client):
    owner = make_user(email="owner@example.com")
    stranger = make_user(email="stranger@example.com")
    scan = make_scan(owner)

    api_client.force_authenticate(stranger)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_detail_foreign_scan_is_404_even_for_an_analyst_end_user_scope(
    make_user, api_client
):
    """An end_user never sees a foreign scan, UUID known or not (US30)."""
    owner = make_user(email="owner@example.com")
    other_end_user = make_user(email="eu@example.com", role="end_user")
    scan = make_scan(owner)

    api_client.force_authenticate(other_end_user)
    resp = api_client.get(reverse(SCAN_DETAIL, args=[scan.public_id]))
    assert resp.status_code == http_status.HTTP_404_NOT_FOUND


# --- audit -------------------------------------------------------------------


@pytest.mark.django_db
def test_audit_target_id_is_the_public_uuid(auth_client, viewer):
    resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")
    assert resp.status_code == http_status.HTTP_202_ACCEPTED

    scan = Scan.objects.get()
    entry = AuditLog.objects.get(action="scan_created")
    assert entry.target_id == str(scan.public_id)
    assert entry.target_id != str(scan.pk)
    assert str(scan.public_id) in entry.target_repr


# --- Celery still gets the internal pk ---------------------------------------


@pytest.mark.django_db
def test_celery_task_receives_the_internal_pk_not_the_uuid(
    auth_client, viewer, django_capture_on_commit_callbacks
):
    from unittest import mock

    with (
        mock.patch("scans.tasks.run_scan.delay") as delay,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = auth_client.post(reverse(SCAN_LIST), {"url": VALID_URL}, format="json")

    assert resp.status_code == http_status.HTTP_202_ACCEPTED
    scan = Scan.objects.get()
    delay.assert_called_once_with(scan.pk)
    assert delay.call_args[0][0] == scan.pk
    assert delay.call_args[0][0] != str(scan.public_id)
