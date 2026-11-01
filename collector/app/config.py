"""Collector settings loaded from the environment (spec v1 section 5.7)."""
from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

ENV_PRODUCTION = "production"
ENV_TEST = "test"
_VALID_ENVS = frozenset({ENV_PRODUCTION, ENV_TEST})


class ConfigurationError(Exception):
    """Raised when the collector environment cannot boot."""


def _read_int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}")
    return value


def _read_float(env: Mapping[str, str], name: str, default: float, minimum: float) -> float:
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}")
    return value


def _read_grace(env: Mapping[str, str], name: str, default: float) -> float:
    """Strictly positive finite seconds; 0 would mean an infinite Playwright wait."""
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ConfigurationError(f"{name} must be a strictly positive number")
    return value


@dataclass(frozen=True)
class Settings:
    """Validated environment; construction is the startup gate (fail fast)."""

    api_key: str
    env: str = ENV_PRODUCTION
    allow_private_hosts: frozenset[str] = field(default_factory=frozenset)
    timeout_s: float = 20.0
    load_grace_s: float = 5.0
    max_concurrency: int = 2
    browser_recycle_every: int = 50
    max_total_bytes: int = 25_000_000
    proxy_port: int = 3129

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Read and validate the environment; raise ConfigurationError on any flaw."""
        env = dict(os.environ if environ is None else environ)
        api_key = str(env.get("COLLECTOR_API_KEY") or "").strip()
        if not api_key:
            raise ConfigurationError("COLLECTOR_API_KEY is required and must not be empty")
        mode = str(env.get("COLLECTOR_ENV") or ENV_PRODUCTION).strip().lower()
        if mode not in _VALID_ENVS:
            raise ConfigurationError("COLLECTOR_ENV must be 'production' or 'test'")
        allow = frozenset(
            host.strip().lower()
            for host in str(env.get("COLLECTOR_ALLOW_PRIVATE_HOSTS") or "").split(",")
            if host.strip()
        )
        if allow and mode == ENV_PRODUCTION:
            raise ConfigurationError(
                "COLLECTOR_ALLOW_PRIVATE_HOSTS must be empty when COLLECTOR_ENV=production"
            )
        return cls(
            api_key=api_key,
            env=mode,
            allow_private_hosts=allow,
            timeout_s=_read_float(env, "COLLECTOR_TIMEOUT_S", 20.0, minimum=0.1),
            load_grace_s=_read_grace(env, "COLLECTOR_LOAD_GRACE_S", 5.0),
            max_concurrency=_read_int(env, "COLLECTOR_MAX_CONCURRENCY", 2),
            browser_recycle_every=_read_int(env, "COLLECTOR_BROWSER_RECYCLE_EVERY", 50),
            max_total_bytes=_read_int(env, "COLLECTOR_MAX_TOTAL_BYTES", 25_000_000),
            proxy_port=_read_int(env, "COLLECTOR_PROXY_PORT", 3129),
        )
