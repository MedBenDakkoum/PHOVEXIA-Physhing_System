"""
Step 8b API tests - scan history filters and ordering (US29 / US30 / ISO-6.1).

GET /api/scans/ filters (django-filter):
    q, verdict, status, created_after, created_before
plus the whitelisted `ordering` query parameter (views.ScanListCreateView).

No network access: scans are created straight through the ORM and the list
endpoint performs no DNS lookup. The suite runs unchanged on SQLite and
PostgreSQL (see docs/HANDOFF.md).

Requirement tags: US29 (history with search and filters), US16 (follow-up),
US30 (scan detail unchanged), ISO-6.1 (functional suitability),
ISO-6.6 (a filter can never widen the owner scope).
"""
from datetime import UTC, datetime

import pytest
from django.db import connection
from django.urls import reverse
from rest_framework import status as http_status

from scans.models import Scan
from scans.views import ORDERING_VALUES, ORDERING_WHITELIST

SCAN_LIST = "scan-list"

D_2026_10_10_NOON = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
D_2026_10_12_NOON = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)


def iso(moment: datetime) -> str:
    """ISO 8601 with a trailing Z, as a frontend would send it."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_scan(owner, url="https://example.com/login", *, created_at=None, **fields):
    """Create a scan through the ORM; backdate created_at if needed.

    auto_now_add ignores a value passed to create(), so the date is written
    with a queryset update (same helper as scans/test_quota.py).
    """
    host = url.split("/")[2] if "//" in url else ""
    scan = Scan.objects.create(owner=owner, url=url, domain=host, mode="fast", **fields)
    if created_at is not None:
        Scan.objects.filter(pk=scan.pk).update(created_at=created_at)
    return scan


def results(resp):
    return [item["id"] for item in resp.data["results"]]


# --- GET /api/scans/ : baseline ----------------------------------------------


@pytest.mark.django_db
def test_no_filter_returns_my_scans_newest_first(auth_client, viewer):
    old = make_scan(viewer, url="https://example.com/old", created_at=D_2026_10_10_NOON)
    new = make_scan(viewer, url="https://example.com/new", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST))

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 2
    assert results(resp) == [str(new.public_id), str(old.public_id)]


# --- filter q (substring of url or domain, case-insensitive) ------------------


@pytest.mark.django_db
def test_q_matches_the_url_ignoring_case(auth_client, viewer):
    match = make_scan(viewer, url="https://Example.com/Login?user=1")
    make_scan(viewer, url="https://other.org/pay")

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "LOGIN"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(match.public_id)]


@pytest.mark.django_db
def test_q_matches_the_domain(auth_client, viewer):
    match = make_scan(viewer, url="https://secure-bank.example/login")
    make_scan(viewer, url="https://example.org/other")

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "secure-bank"})

    assert results(resp) == [str(match.public_id)]


@pytest.mark.django_db
def test_q_matches_inside_the_query_string(auth_client, viewer):
    match = make_scan(viewer, url="https://example.com/login?token=abc123")
    make_scan(viewer, url="https://example.com/logout")

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "token=abc"})

    assert results(resp) == [str(match.public_id)]


@pytest.mark.django_db
def test_q_without_match_returns_an_empty_page(auth_client, viewer):
    make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "nothing-matches"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 0
    assert resp.data["results"] == []


@pytest.mark.django_db
def test_blank_q_is_ignored(auth_client, viewer):
    scan = make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "   "})

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 1
    assert results(resp) == [str(scan.public_id)]


@pytest.mark.django_db
def test_q_never_returns_another_users_scans(make_user, api_client):
    me = make_user(email="me@example.com")
    other = make_user(email="other@example.com")
    make_scan(me, url="https://example.com/mine")
    foreign = make_scan(other, url="https://example.com/foreign")

    api_client.force_authenticate(me)
    resp = api_client.get(reverse(SCAN_LIST), {"q": "example.com"})

    assert resp.data["count"] == 1
    assert str(foreign.public_id) not in results(resp)


@pytest.mark.django_db
def test_q_with_sql_like_wildcards_does_not_break_the_query(auth_client, viewer):
    make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "100%_x"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 0


# --- filter verdict / status (choices read from the model) --------------------


@pytest.mark.django_db
def test_verdict_filter_returns_only_that_verdict(auth_client, viewer):
    phishing = make_scan(viewer, url="https://a.example.com", verdict="phishing", score=0.9)
    make_scan(viewer, url="https://b.example.com", verdict="legitimate", score=0.1)
    make_scan(viewer, url="https://c.example.com", verdict=None, score=None)

    resp = auth_client.get(reverse(SCAN_LIST), {"verdict": "phishing"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(phishing.public_id)]


@pytest.mark.django_db
def test_verdict_filter_excludes_scans_without_a_verdict(auth_client, viewer):
    make_scan(viewer, url="https://a.example.com", verdict="phishing")
    make_scan(viewer, url="https://b.example.com", verdict=None)

    resp = auth_client.get(reverse(SCAN_LIST), {"verdict": "uncertain"})

    assert resp.data["count"] == 0


@pytest.mark.django_db
def test_unknown_verdict_is_400_and_runs_no_query(auth_client, viewer):
    make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"verdict": "not-a-verdict"})

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert "verdict" in resp.data


@pytest.mark.django_db
def test_status_filter_returns_only_that_status(auth_client, viewer):
    detected = make_scan(viewer, url="https://a.example.com", status=Scan.Status.DETECTED)
    make_scan(viewer, url="https://b.example.com", status=Scan.Status.SUBMITTED)

    resp = auth_client.get(reverse(SCAN_LIST), {"status": "detected"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(detected.public_id)]


@pytest.mark.django_db
def test_unknown_status_is_400(auth_client, viewer):
    make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"status": "wondering"})

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert "status" in resp.data


# --- filter created_after / created_before (inclusive bounds) -----------------


@pytest.mark.django_db
def test_created_after_is_inclusive(auth_client, viewer):
    before = make_scan(
        viewer, url="https://a.example.com", created_at=datetime(2026, 10, 1, tzinfo=UTC)
    )
    at_bound = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_10_NOON)
    after = make_scan(viewer, url="https://c.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST), {"created_after": iso(D_2026_10_10_NOON)})

    assert resp.status_code == http_status.HTTP_200_OK
    # the scan created exactly at the bound is kept (>=, inclusive)
    assert results(resp) == [str(after.public_id), str(at_bound.public_id)]
    assert str(before.public_id) not in results(resp)


@pytest.mark.django_db
def test_created_before_is_inclusive(auth_client, viewer):
    scan = make_scan(viewer, created_at=D_2026_10_10_NOON)
    make_scan(viewer, url="https://later.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(
        reverse(SCAN_LIST), {"created_before": iso(D_2026_10_10_NOON)}
    )

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(scan.public_id)]


@pytest.mark.django_db
def test_created_after_and_before_form_a_closed_range(auth_client, viewer):
    before = make_scan(
        viewer, url="https://a.example.com", created_at=datetime(2026, 10, 1, tzinfo=UTC)
    )
    lower = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_10_NOON)
    inside = make_scan(viewer, url="https://c.example.com", created_at=D_2026_10_12_NOON)
    after = make_scan(
        viewer, url="https://d.example.com", created_at=datetime(2026, 10, 15, tzinfo=UTC)
    )

    resp = auth_client.get(
        reverse(SCAN_LIST),
        {
            "created_after": iso(D_2026_10_10_NOON),
            "created_before": iso(D_2026_10_12_NOON),
        },
    )

    assert resp.status_code == http_status.HTTP_200_OK
    # both bounds are inclusive; scans outside the range are excluded
    assert results(resp) == [str(inside.public_id), str(lower.public_id)]
    assert str(before.public_id) not in results(resp)
    assert str(after.public_id) not in results(resp)


@pytest.mark.django_db
def test_created_after_a_moment_with_no_scan_returns_empty(auth_client, viewer):
    make_scan(viewer, created_at=D_2026_10_10_NOON)

    resp = auth_client.get(reverse(SCAN_LIST), {"created_after": iso(D_2026_10_12_NOON)})

    assert resp.status_code == http_status.HTTP_200_OK
    assert resp.data["count"] == 0


@pytest.mark.django_db
@pytest.mark.parametrize("value", ["not-a-date", "2026-99-99T00:00:00Z", "10/12/2026"])
def test_malformed_date_is_400(auth_client, viewer, value):
    make_scan(viewer)

    resp = auth_client.get(reverse(SCAN_LIST), {"created_after": value})

    assert resp.status_code == http_status.HTTP_400_BAD_REQUEST
    assert "created_after" in resp.data


# --- combinations, isolation and permissions ----------------------------------


@pytest.mark.django_db
def test_filters_combine_with_and(auth_client, viewer):
    match = make_scan(
        viewer,
        url="https://a.example.com/login",
        created_at=D_2026_10_12_NOON,
        verdict="phishing",
        status=Scan.Status.DETECTED,
    )
    make_scan(
        viewer,
        url="https://b.example.com/login",
        created_at=D_2026_10_12_NOON,
        verdict="phishing",
        status=Scan.Status.SUBMITTED,
    )
    make_scan(
        viewer,
        url="https://c.example.com/login",
        created_at=D_2026_10_10_NOON,
        verdict="phishing",
        status=Scan.Status.DETECTED,
    )

    resp = auth_client.get(
        reverse(SCAN_LIST),
        {
            "q": "a.example.com",
            "verdict": "phishing",
            "status": "detected",
            "created_after": iso(datetime(2026, 10, 12, 0, 0, 0, tzinfo=UTC)),
        },
    )

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(match.public_id)]


@pytest.mark.django_db
def test_analyst_filters_still_see_only_their_own_scans(make_user, api_client):
    analyst = make_user(email="a@example.com", role="analyst")
    other = make_user(email="b@example.com")
    mine = make_scan(analyst, url="https://mine.example.com")
    make_scan(other, url="https://theirs.example.com")

    api_client.force_authenticate(analyst)
    resp = api_client.get(reverse(SCAN_LIST), {"q": "example.com"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(mine.public_id)]


@pytest.mark.django_db
def test_anonymous_request_with_filters_is_401(api_client):
    resp = api_client.get(reverse(SCAN_LIST), {"q": "x", "verdict": "phishing"})

    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_filters_are_applied_before_pagination(auth_client, viewer):
    for i in range(25):
        make_scan(viewer, url=f"https://phish{i}.example.com")
    for i in range(5):
        make_scan(viewer, url=f"https://safe{i}.example.com")

    resp = auth_client.get(reverse(SCAN_LIST), {"q": "safe"})

    assert resp.data["count"] == 5
    assert len(resp.data["results"]) == 5
    assert resp.data["next"] is None


# --- ordering whitelist --------------------------------------------------------


@pytest.mark.django_db
def test_default_ordering_is_newest_first(auth_client, viewer):
    old = make_scan(viewer, url="https://a.example.com", created_at=D_2026_10_10_NOON)
    new = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST))

    assert results(resp) == [str(new.public_id), str(old.public_id)]


@pytest.mark.django_db
def test_ordering_by_score_ascending(auth_client, viewer):
    low = make_scan(viewer, url="https://a.example.com", score=0.10)
    high = make_scan(viewer, url="https://b.example.com", score=0.90)

    resp = auth_client.get(reverse(SCAN_LIST), {"ordering": "score"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(low.public_id), str(high.public_id)]


@pytest.mark.django_db
def test_ordering_by_minus_score_descends(auth_client, viewer):
    low = make_scan(viewer, url="https://a.example.com", score=0.10)
    high = make_scan(viewer, url="https://b.example.com", score=0.90)

    resp = auth_client.get(reverse(SCAN_LIST), {"ordering": "-score"})

    assert results(resp) == [str(high.public_id), str(low.public_id)]


@pytest.mark.django_db
def test_ordering_by_created_at_ascending(auth_client, viewer):
    old = make_scan(viewer, url="https://a.example.com", created_at=D_2026_10_10_NOON)
    new = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST), {"ordering": "created_at"})

    assert results(resp) == [str(old.public_id), str(new.public_id)]


@pytest.mark.django_db
def test_ordering_outside_the_whitelist_falls_back_to_the_default(auth_client, viewer):
    # `url` is a real column but is deliberately NOT in ordering_fields.
    old = make_scan(viewer, url="https://a.example.com", created_at=D_2026_10_10_NOON)
    new = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST), {"ordering": "url"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(new.public_id), str(old.public_id)]


@pytest.mark.django_db
def test_ordering_by_an_unknown_field_falls_back_to_the_default(auth_client, viewer):
    old = make_scan(viewer, url="https://a.example.com", created_at=D_2026_10_10_NOON)
    new = make_scan(viewer, url="https://b.example.com", created_at=D_2026_10_12_NOON)

    resp = auth_client.get(reverse(SCAN_LIST), {"ordering": "hack"})

    assert resp.status_code == http_status.HTTP_200_OK
    assert results(resp) == [str(new.public_id), str(old.public_id)]


# --- database indexes (US29 / ISO-6.2 evidence) --------------------------------


@pytest.mark.django_db
def test_history_indexes_are_declared_on_the_model():
    declared = {index.name for index in Scan._meta.indexes}

    assert "scans_scan_owner_created_idx" in declared
    assert "scans_scan_verdict_idx" in declared


@pytest.mark.django_db
def test_history_indexes_exist_in_the_database():
    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(
            cursor, Scan._meta.db_table
        )

    owner_idx = constraints.get("scans_scan_owner_created_idx", {})
    verdict_idx = constraints.get("scans_scan_verdict_idx", {})
    # the FK column is physically named owner_id on both engines
    owner_column = Scan._meta.get_field("owner").column

    assert owner_idx.get("index") is True
    assert list(owner_idx.get("columns", [])) == [owner_column, "created_at"]
    assert verdict_idx.get("index") is True
    assert list(verdict_idx.get("columns", [])) == ["verdict"]


# --- OpenAPI contract (US29 / ISO-6.1) -----------------------------------------


@pytest.mark.django_db
def test_openapi_schema_documents_the_history_filters():
    """The generated schema is the contract with the frontend (DoD)."""
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator().get_schema(request=None, public=True)
    list_operation = schema["paths"]["/api/scans/"]["get"]
    parameters = {param["name"]: param for param in list_operation["parameters"]}

    assert {
        "q",
        "verdict",
        "status",
        "created_after",
        "created_before",
        "ordering",
    } <= set(parameters)
    assert parameters["verdict"]["schema"]["enum"] == [
        "legitimate",
        "phishing",
        "uncertain",
    ]
    assert set(parameters["ordering"]["schema"]["enum"]) == set(ORDERING_VALUES)
    assert set(ORDERING_VALUES) == set(ORDERING_WHITELIST) | {
        f"-{name}" for name in ORDERING_WHITELIST
    }
