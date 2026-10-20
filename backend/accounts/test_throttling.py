"""
Step 8d tests - DRF throttling on the auth endpoints.

Rates (settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"], overridable from .env):
login 10/min/IP, register 10/hour/IP, refresh 60/min/IP,
change-password 5/hour/user. NUM_PROXIES = 0 => the throttle key is
REMOTE_ADDR, so a forged X-Forwarded-For can never bypass a limit.

Requirement tags: ISO-6.3 (security / rate limiting), US-none (infrastructure).
"""
import logging
import re
import time
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from rest_framework import status as http_status
from rest_framework.throttling import SimpleRateThrottle

from audit.models import AuditLog
from config.settings import (
    _caches_config,
    _non_negative_int_env,
    _redis_cache_url,
    _throttle_rate_env,
)

User = get_user_model()
pytestmark = pytest.mark.django_db

PASSWORD = "StrongPass!234"
NEW_PASSWORD = "AnotherStrong!567"
LOGIN_URL = "login"
REGISTER_URL = "register"
REFRESH_URL = "token_refresh"
CHANGE_PASSWORD_URL = "change_password"


def _login(client, email, password, **extra):
    return client.post(
        reverse(LOGIN_URL), {"email": email, "password": password}, format="json", **extra
    )


def _normalize_wait(text):
    """Hide the variable 'N seconds' so two 429 bodies can be compared."""
    return re.sub(r"\d+", "#", text)


def test_settings_expose_the_step_8d_throttle_configuration(settings):
    rates = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
    assert rates["login"] == "10/min"
    assert rates["register"] == "10/hour"
    assert rates["refresh"] == "60/min"
    assert rates["change_password"] == "5/hour"
    assert settings.REST_FRAMEWORK["NUM_PROXIES"] == 0


def test_login_is_throttled_after_ten_requests_with_retry_after(api_client, make_user):
    user = make_user()
    for _ in range(10):
        assert _login(api_client, user.email, PASSWORD).status_code == http_status.HTTP_200_OK

    audits_before = AuditLog.objects.count()
    response = _login(api_client, user.email, PASSWORD)

    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert response.has_header("Retry-After")
    assert response.json()["detail"].startswith("Request was throttled")
    # The throttled attempt is refused BEFORE the view runs: no audit entry.
    assert AuditLog.objects.count() == audits_before


def test_login_throttle_never_reveals_whether_the_email_exists(api_client, make_user):
    make_user(email="known@example.com")
    known_payload = {"email": "known@example.com", "password": PASSWORD}
    for _ in range(10):
        assert (
            api_client.post(reverse(LOGIN_URL), known_payload, format="json").status_code
            == http_status.HTTP_200_OK
        )

    unknown = api_client.post(
        reverse(LOGIN_URL),
        {"email": "nobody@example.com", "password": "x"},
        format="json",
    )
    known = api_client.post(reverse(LOGIN_URL), known_payload, format="json")

    assert unknown.status_code == known.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    unknown_body, known_body = unknown.json(), known.json()
    assert set(unknown_body) == set(known_body) == {"detail"}
    assert "example.com" not in str(unknown_body)
    assert "example.com" not in str(known_body)
    assert _normalize_wait(unknown_body["detail"]) == _normalize_wait(known_body["detail"])


def test_a_forged_x_forwarded_for_never_bypasses_the_login_limit(api_client, make_user):
    """NUM_PROXIES=0: the key is REMOTE_ADDR, the X-Forwarded-For is ignored."""
    user = make_user()
    for i in range(10):
        response = _login(
            api_client,
            user.email,
            PASSWORD,
            REMOTE_ADDR="198.51.100.10",
            HTTP_X_FORWARDED_FOR=f"203.0.113.{i}",
        )
        assert response.status_code == http_status.HTTP_200_OK

    response = _login(
        api_client,
        user.email,
        PASSWORD,
        REMOTE_ADDR="198.51.100.10",
        HTTP_X_FORWARDED_FOR="203.0.113.200",
    )
    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS


def test_the_login_limit_is_per_ip_and_another_ip_is_not_blocked(api_client, make_user):
    user = make_user()
    for _ in range(10):
        response = _login(api_client, user.email, PASSWORD, REMOTE_ADDR="203.0.113.5")
        assert response.status_code == http_status.HTTP_200_OK

    blocked = _login(api_client, user.email, PASSWORD, REMOTE_ADDR="203.0.113.5")
    other_ip = _login(api_client, user.email, PASSWORD, REMOTE_ADDR="203.0.113.6")

    assert blocked.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert other_ip.status_code == http_status.HTTP_200_OK


def test_the_login_window_resets_after_the_period(api_client, make_user):
    user = make_user()
    for _ in range(10):
        assert _login(api_client, user.email, PASSWORD).status_code == http_status.HTTP_200_OK
    assert (
        _login(api_client, user.email, PASSWORD).status_code
        == http_status.HTTP_429_TOO_MANY_REQUESTS
    )

    # SimpleRateThrottle.timer = time.time(): jump past the 60 s window.
    with patch.object(SimpleRateThrottle, "timer", lambda self: time.time() + 61):
        response = _login(api_client, user.email, PASSWORD)

    assert response.status_code == http_status.HTTP_200_OK


def test_register_is_throttled_after_ten_per_hour(api_client):
    for i in range(10):
        response = api_client.post(
            reverse(REGISTER_URL),
            {"email": f"user{i}@example.com", "password": PASSWORD},
            format="json",
        )
        assert response.status_code == http_status.HTTP_201_CREATED

    response = api_client.post(
        reverse(REGISTER_URL),
        {"email": "user10@example.com", "password": PASSWORD},
        format="json",
    )

    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert response.has_header("Retry-After")
    assert not User.objects.filter(email="user10@example.com").exists()


def test_refresh_is_throttled_after_sixty_requests(api_client):
    payload = {"refresh": "not-a-valid-token"}
    for _ in range(60):
        response = api_client.post(reverse(REFRESH_URL), payload, format="json")
        assert response.status_code != http_status.HTTP_429_TOO_MANY_REQUESTS

    response = api_client.post(reverse(REFRESH_URL), payload, format="json")

    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert response.has_header("Retry-After")


def test_change_password_limit_is_per_user_not_per_ip(api_client, make_user):
    alice = make_user(email="alice@example.com")
    bob = make_user(email="bob@example.com")

    api_client.force_authenticate(alice)
    for _ in range(5):
        response = api_client.post(
            reverse(CHANGE_PASSWORD_URL),
            {"old_password": "wrong", "new_password": NEW_PASSWORD},
            format="json",
        )
        # Wrong current password: refused by the serializer, but counted.
        assert response.status_code == http_status.HTTP_400_BAD_REQUEST

    response = api_client.post(
        reverse(CHANGE_PASSWORD_URL),
        {"old_password": "wrong", "new_password": NEW_PASSWORD},
        format="json",
    )

    assert response.status_code == http_status.HTTP_429_TOO_MANY_REQUESTS
    assert response.has_header("Retry-After")
    alice.refresh_from_db()
    assert alice.check_password(PASSWORD)  # the throttled attempt changed nothing

    # Same IP, other user: bob still has his own 5/hour budget.
    api_client.force_authenticate(bob)
    response = api_client.post(
        reverse(CHANGE_PASSWORD_URL),
        {"old_password": PASSWORD, "new_password": NEW_PASSWORD},
        format="json",
    )
    assert response.status_code == http_status.HTTP_204_NO_CONTENT
    bob.refresh_from_db()
    assert bob.check_password(NEW_PASSWORD)


@pytest.mark.parametrize(
    "bad",
    ["fast", "10", "0/min", "-3/hour", "10/", "ten/min", "10/x"],
    ids=["no_slash", "no_period", "zero", "negative", "empty_period", "no_count", "bad_period"],
)
def test_an_invalid_throttle_rate_is_rejected_at_startup(monkeypatch, bad):
    monkeypatch.setenv("THROTTLE_LOGIN", bad)
    with pytest.raises(ImproperlyConfigured, match="THROTTLE_LOGIN"):
        _throttle_rate_env("THROTTLE_LOGIN", "10/min")


def test_an_empty_or_unset_throttle_rate_keeps_the_default(monkeypatch):
    monkeypatch.delenv("THROTTLE_LOGIN", raising=False)
    assert _throttle_rate_env("THROTTLE_LOGIN", "10/min") == "10/min"
    monkeypatch.setenv("THROTTLE_LOGIN", "   ")
    assert _throttle_rate_env("THROTTLE_LOGIN", "10/min") == "10/min"
    monkeypatch.setenv("THROTTLE_LOGIN", " 30/min ")
    assert _throttle_rate_env("THROTTLE_LOGIN", "10/min") == "30/min"


def test_the_cache_never_points_at_the_celery_redis_database(monkeypatch):
    """cache.clear() = FLUSHDB: the cache must live on DB 1, Celery on DB 0."""
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    assert _redis_cache_url() == "redis://localhost:6379/1"
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    assert _redis_cache_url() == "redis://localhost:6379/1"
    monkeypatch.setenv("REDIS_URL", "redis://user:secret@localhost:6379/2")
    assert _redis_cache_url() == "redis://user:secret@localhost:6379/1"
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert _redis_cache_url() == ""


def test_num_proxies_is_read_and_validated_from_the_env(monkeypatch):
    monkeypatch.delenv("NUM_PROXIES", raising=False)
    assert _non_negative_int_env("NUM_PROXIES", 0) == 0
    monkeypatch.setenv("NUM_PROXIES", "   ")
    assert _non_negative_int_env("NUM_PROXIES", 0) == 0
    monkeypatch.setenv("NUM_PROXIES", "2")
    assert _non_negative_int_env("NUM_PROXIES", 0) == 2
    monkeypatch.setenv("NUM_PROXIES", "two")
    assert _non_negative_int_env("NUM_PROXIES", 0) == 0  # invalid -> default + warning
    monkeypatch.setenv("NUM_PROXIES", "-1")
    assert _non_negative_int_env("NUM_PROXIES", 0) == 0  # negative -> default + warning


def test_cache_falls_back_to_locmem_without_redis_url(monkeypatch, caplog):
    monkeypatch.delenv("REDIS_URL", raising=False)
    with caplog.at_level(logging.WARNING, logger="config.settings"):
        config = _caches_config()
    assert config["default"]["BACKEND"].endswith("locmem.LocMemCache")
    assert any("LocMemCache" in record.getMessage() for record in caplog.records)


def test_cache_falls_back_to_locmem_when_the_redis_probe_fails(monkeypatch, caplog):
    # 127.0.0.1:1 is never published by docker compose: the probe times out.
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    with caplog.at_level(logging.WARNING, logger="config.settings"):
        config = _caches_config()
    assert config["default"]["BACKEND"].endswith("locmem.LocMemCache")
    assert any("unreachable" in record.getMessage() for record in caplog.records)
