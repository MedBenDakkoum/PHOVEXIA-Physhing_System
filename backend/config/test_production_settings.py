"""Production settings - feature "production settings" (ISO-6.6, ISO-6.8).

Every rule is asserted on the pure helpers of `config.production` (env
mapping in, value out), plus one subprocess check that the REAL Django
settings module follows the same rule.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from django.core.exceptions import ImproperlyConfigured

from config import production as prod

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_development_mode_when_debug_is_true():
    assert prod.is_production({"DEBUG": "True"}) is False


def test_production_mode_is_on_for_django_env_even_with_debug_true():
    # DJANGO_ENV=production wins over the DEBUG key of the .env file.
    assert prod.is_production({"DJANGO_ENV": "production", "DEBUG": "True"}) is True


def test_production_mode_is_on_when_debug_is_not_explicitly_true():
    assert prod.is_production({}) is True
    assert prod.is_production({"DEBUG": "False"}) is True


def test_secret_key_is_required_with_a_clear_message_and_no_default():
    with pytest.raises(ImproperlyConfigured) as excinfo:
        prod.require_env({}, "SECRET_KEY", hint="the Django signing key.")
    message = str(excinfo.value)
    assert "SECRET_KEY is required" in message
    assert "No default value" in message


def test_allowed_hosts_are_required_in_production_and_parsed():
    with pytest.raises(ImproperlyConfigured):
        prod.parse_hosts({}, required=True)
    assert prod.parse_hosts({}, required=False) == []
    assert prod.parse_hosts(
        {"ALLOWED_HOSTS": " a.example , , b.example "}, required=True
    ) == ["a.example", "b.example"]


def test_security_flags_default_to_off_for_plain_http_and_are_read_from_env():
    # Default = the local plain-HTTP stack keeps working.
    default = prod.build_security_settings({})
    assert default["SECURE_SSL_REDIRECT"] is False
    assert default["SECURE_HSTS_SECONDS"] == 0
    assert default["SECURE_HSTS_INCLUDE_SUBDOMAINS"] is False
    assert default["SESSION_COOKIE_SECURE"] is False
    assert default["CSRF_COOKIE_SECURE"] is False
    assert default["SECURE_PROXY_SSL_HEADER"] is None
    assert default["CSRF_TRUSTED_ORIGINS"] == []

    # The HTTPS deployment switches every one of them on from the env.
    https = prod.build_security_settings(
        {
            "SECURE_SSL_REDIRECT": "True",
            "SECURE_HSTS_SECONDS": "31536000",
            "SECURE_HSTS_INCLUDE_SUBDOMAINS": "True",
            "SECURE_HSTS_PRELOAD": "True",
            "SESSION_COOKIE_SECURE": "True",
            "CSRF_COOKIE_SECURE": "True",
            "CSRF_TRUSTED_ORIGINS": "https://phishing.example.org",
        }
    )
    assert https["SECURE_SSL_REDIRECT"] is True
    assert https["SECURE_HSTS_SECONDS"] == 31536000
    assert https["SECURE_HSTS_PRELOAD"] is True
    assert https["SESSION_COOKIE_SECURE"] is True
    assert https["CSRF_COOKIE_SECURE"] is True
    assert https["CSRF_TRUSTED_ORIGINS"] == ["https://phishing.example.org"]


def test_proxy_ssl_header_is_declared_only_when_the_env_says_so():
    off = prod.build_security_settings({})
    assert off["SECURE_PROXY_SSL_HEADER"] is None
    on = prod.build_security_settings({"USE_X_FORWARDED_PROTO": "True"})
    assert on["SECURE_PROXY_SSL_HEADER"] == ("HTTP_X_FORWARDED_PROTO", "https")


def test_a_malformed_security_value_fails_at_startup():
    with pytest.raises(ImproperlyConfigured):
        prod.build_security_settings({"SECURE_SSL_REDIRECT": "maybe"})
    with pytest.raises(ImproperlyConfigured):
        prod.int_env({"SECURE_HSTS_SECONDS": "1y"}, "SECURE_HSTS_SECONDS", 0)
    with pytest.raises(ImproperlyConfigured):
        prod.choice_env(
            {"LOG_LEVEL": "chatty"}, "LOG_LEVEL", frozenset({"INFO", "WARNING"}), "INFO"
        )


def test_logging_goes_to_stdout_at_the_env_level_without_bodies_or_tokens():
    conf = prod.build_logging_settings({"LOG_LEVEL": "DEBUG"})
    handler = conf["handlers"]["stdout"]
    assert handler["class"] == "logging.StreamHandler"
    assert handler["stream"] == "ext://sys.stdout"
    assert handler["level"] == "DEBUG"
    assert conf["loggers"]["django"]["level"] == "DEBUG"
    assert conf["disable_existing_loggers"] is False
    fmt = conf["formatters"]["standard"]["format"]
    for forbidden in ("body", "password", "token", "headers", "%(request"):
        assert forbidden not in fmt


def test_redacted_urls_never_contain_the_password():
    assert (
        prod.redact_credentials("redis://:s3cr3t@redis:6379/1")
        == "redis://:***@redis:6379/1"
    )
    assert (
        prod.redact_credentials("redis://user:s3cr3t@redis:6379/1")
        == "redis://user:***@redis:6379/1"
    )
    assert prod.redact_credentials("redis://redis:6379/1") == "redis://redis:6379/1"
    assert "s3cr3t" not in prod.redact_credentials("redis://:s3cr3t@redis:6379/1")


def test_real_settings_module_forces_debug_off_when_django_env_is_production():
    """The rule above is applied by config/settings.py, not only by its helper."""
    env = {**os.environ, "DJANGO_ENV": "production"}
    code = (
        "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings');"
        "import django; django.setup();"
        "from django.conf import settings;"
        "print('DEBUG=%s' % settings.DEBUG);"
        "print('PRODUCTION_MODE=%s' % settings.PRODUCTION_MODE);"
        "print('PROXY_HEADER=%s' % (settings.SECURE_PROXY_SSL_HEADER,))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "DEBUG=False" in result.stdout
    assert "PRODUCTION_MODE=True" in result.stdout
    # .env has USE_X_FORWARDED_PROTO=False, so no header is trusted.
    assert "PROXY_HEADER=None" in result.stdout
