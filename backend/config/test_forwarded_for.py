"""Throttle identity behind nginx - feature "full Docker stack" (ISO-6.6).

Why this matters: nginx sits in front of gunicorn (docker-compose.yml) and
the full profile sets NUM_PROXIES=1. rest_framework.throttling.BaseThrottle.
get_ident() then reads X-Forwarded-For instead of the socket peer (which is
the nginx container address), so the header MUST be written by nginx only.
deploy/nginx.conf therefore overwrites it with $remote_addr and never
appends the client's own value.
"""

from __future__ import annotations

import pytest
from django.conf import settings as django_settings
from django.test import RequestFactory, override_settings
from rest_framework import throttling
from rest_framework.test import APIClient

FORWARDED = "203.0.113.7"  # what nginx puts in the header (its peer address)
NGINX_ADDRESS = "172.18.0.5"  # what Django sees as REMOTE_ADDR (the proxy)

LOGIN_BODY = {"email": "nobody@example.com", "password": "WrongPass!234"}


def _request(**headers):
    request = RequestFactory().get("/", **headers)
    request.META["REMOTE_ADDR"] = NGINX_ADDRESS
    return request


def test_with_one_proxy_the_key_is_the_address_nginx_wrote():
    """NUM_PROXIES=1 -> the single forwarded address wins over the proxy IP."""
    with override_settings(
        REST_FRAMEWORK={**django_settings.REST_FRAMEWORK, "NUM_PROXIES": 1}
    ):
        ident = throttling.BaseThrottle().get_ident(
            _request(HTTP_X_FORWARDED_FOR=FORWARDED)
        )
    assert ident == FORWARDED
    assert ident != NGINX_ADDRESS  # otherwise every user would share one key


def test_without_a_proxy_a_forwarded_header_is_ignored():
    """NUM_PROXIES=0 (dev default) -> REMOTE_ADDR only, header never trusted."""
    with override_settings(
        REST_FRAMEWORK={**django_settings.REST_FRAMEWORK, "NUM_PROXIES": 0}
    ):
        ident = throttling.BaseThrottle().get_ident(
            _request(HTTP_X_FORWARDED_FOR="198.51.100.99")
        )
    assert ident == NGINX_ADDRESS


@pytest.mark.django_db
def test_login_limit_still_fires_behind_the_proxy_for_every_forged_header():
    """Live contract of the nginx check: 11 requests, distinct forged
    X-Forwarded-For on each one, one shared key (the address nginx writes)
    => the 11th is 429. A forged header never buys a fresh budget."""
    client = APIClient()
    with override_settings(
        REST_FRAMEWORK={**django_settings.REST_FRAMEWORK, "NUM_PROXIES": 1}
    ):
        codes = []
        for index in range(11):
            response = client.post(
                "/api/auth/login/",
                LOGIN_BODY,
                format="json",
                HTTP_X_FORWARDED_FOR=FORWARDED,
            )
            codes.append(response.status_code)
    assert all(code != 429 for code in codes[:10])
    assert codes[10] == 429
