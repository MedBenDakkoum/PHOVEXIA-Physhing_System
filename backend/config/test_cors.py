"""
Step 8c tests - CORS configuration (ISO-6.3 compatibility, dev project).

django-cors-headers is configured from settings.CORS_ALLOWED_ORIGINS
(comma-separated in .env, empty = same-origin only) with
CORS_ALLOW_CREDENTIALS = False (JWT in the Authorization header, never
cookies). CorsMiddleware sits BEFORE CommonMiddleware.

Requirement tags: ISO-6.3, US-none (infrastructure).
"""
import pytest
from django.urls import reverse
from rest_framework import status as http_status

SCAN_LIST = "scan-list"

ALLOWED = "http://localhost:5173"
SECOND_ALLOWED = "http://localhost:3000"
DISALLOWED = "http://evil.example"


@pytest.fixture
def cors_settings(settings):
    settings.CORS_ALLOWED_ORIGINS = [ALLOWED, SECOND_ALLOWED]
    settings.CORS_ALLOW_CREDENTIALS = False
    return settings


@pytest.mark.django_db
def test_allowed_origin_gets_the_cors_header(api_client, cors_settings):
    resp = api_client.get(reverse(SCAN_LIST), HTTP_ORIGIN=ALLOWED)
    # 401 (anonymous) is fine: CORS headers must be present on every response.
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED
    assert resp["Access-Control-Allow-Origin"] == ALLOWED
    # Credentials stay refused: no Access-Control-Allow-Credentials header.
    assert "Access-Control-Allow-Credentials" not in resp


@pytest.mark.django_db
def test_second_allowed_origin_also_gets_the_header(api_client, cors_settings):
    resp = api_client.get(reverse(SCAN_LIST), HTTP_ORIGIN=SECOND_ALLOWED)
    assert resp["Access-Control-Allow-Origin"] == SECOND_ALLOWED


@pytest.mark.django_db
def test_disallowed_origin_gets_no_cors_header(api_client, cors_settings):
    resp = api_client.get(reverse(SCAN_LIST), HTTP_ORIGIN=DISALLOWED)
    assert resp.status_code == http_status.HTTP_401_UNAUTHORIZED
    assert "Access-Control-Allow-Origin" not in resp


@pytest.mark.django_db
def test_default_empty_origin_list_allows_no_cross_origin(api_client, settings):
    """The code default (no env var) is empty: same-origin only."""
    settings.CORS_ALLOWED_ORIGINS = []
    resp = api_client.get(reverse(SCAN_LIST), HTTP_ORIGIN=ALLOWED)
    assert "Access-Control-Allow-Origin" not in resp


@pytest.mark.django_db
def test_preflight_with_authorization_header_is_accepted(api_client, cors_settings):
    """Browser preflight for a JWT POST: OPTIONS must be answered with the
    right Allow-* headers, before CommonMiddleware (middleware order)."""
    resp = api_client.options(
        reverse(SCAN_LIST),
        HTTP_ORIGIN=ALLOWED,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        HTTP_ACCESS_CONTROL_REQUEST_HEADERS="authorization,content-type",
    )
    assert resp.status_code in (http_status.HTTP_200_OK, http_status.HTTP_204_NO_CONTENT)
    assert resp["Access-Control-Allow-Origin"] == ALLOWED
    assert "POST" in resp["Access-Control-Allow-Methods"]
    allowed_headers = resp["Access-Control-Allow-Headers"].lower()
    assert "authorization" in allowed_headers


@pytest.mark.django_db
def test_preflight_from_a_disallowed_origin_is_refused(api_client, cors_settings):
    resp = api_client.options(
        reverse(SCAN_LIST),
        HTTP_ORIGIN=DISALLOWED,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        HTTP_ACCESS_CONTROL_REQUEST_HEADERS="authorization",
    )
    assert "Access-Control-Allow-Origin" not in resp
