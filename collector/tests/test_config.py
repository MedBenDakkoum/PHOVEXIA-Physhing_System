"""Startup gate: test-only allowances are refused in production (spec v1 5.7)."""
from __future__ import annotations

import pytest
from app.config import ConfigurationError, Settings


def test_production_startup_refuses_the_test_allowlist():
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "COLLECTOR_API_KEY": "k",
                "COLLECTOR_ENV": "production",
                "COLLECTOR_ALLOW_PRIVATE_HOSTS": "testserver",
            }
        )


def test_missing_api_key_refuses_to_boot():
    with pytest.raises(ConfigurationError):
        Settings.from_env({"COLLECTOR_ENV": "production"})


def test_test_mode_accepts_a_hostname_allowlist():
    settings = Settings.from_env(
        {
            "COLLECTOR_API_KEY": "k",
            "COLLECTOR_ENV": "test",
            "COLLECTOR_ALLOW_PRIVATE_HOSTS": "TestServer, other",
        }
    )
    assert settings.allow_private_hosts == frozenset({"testserver", "other"})


def test_load_grace_defaults_to_five_and_is_validated():
    default = Settings.from_env({"COLLECTOR_API_KEY": "k"})
    assert default.load_grace_s == 5.0
    assert default.timeout_s == 20.0

    accepted = Settings.from_env(
        {"COLLECTOR_API_KEY": "k", "COLLECTOR_LOAD_GRACE_S": "2.5"}
    )
    assert accepted.load_grace_s == 2.5

    for raw in ("0", "-1", "abc", "nan", "inf"):
        with pytest.raises(ConfigurationError):
            Settings.from_env(
                {"COLLECTOR_API_KEY": "k", "COLLECTOR_LOAD_GRACE_S": raw}
            )
