"""Environment-driven production settings (feature: production settings).

Read rules (ISO-6.6 security, ISO-6.8 portability):

- ``is_production(env)`` is true when ``DJANGO_ENV=production`` OR ``DEBUG``
  is not explicitly ``True``. In that path ``SECRET_KEY`` and
  ``ALLOWED_HOSTS`` are REQUIRED: a clear ``ImproperlyConfigured`` at startup,
  never a default or hard-coded key (and ``DJANGO_ENV=production`` forces
  ``DEBUG=False`` whatever ``DEBUG`` says).
- Every ``SECURE_*`` flag comes from the environment and defaults to **off**,
  so a plain-HTTP local stack (``http://127.0.0.1:8080``) keeps working. The
  HTTPS values to switch on are documented in ``backend/deploy/README.md``.
  A malformed security value FAILS at startup instead of silently defaulting
  (same policy as the throttle rates: a wrong flag must not look active).
- ``build_logging_settings`` logs to stdout (Docker collects it), level from
  ``LOG_LEVEL``, and never formats request bodies, credentials or tokens.
- ``redact_credentials`` hides the password of a URL before it reaches a log.

Every function takes a plain mapping (``os.environ``) so it is unit-testable
without reloading Django settings.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from django.core.exceptions import ImproperlyConfigured

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})
_LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"})


def is_production(env: Mapping[str, str]) -> bool:
    """True for the production path: DJANGO_ENV=production or DEBUG not True."""
    django_env = (env.get("DJANGO_ENV") or "").strip().lower()
    if django_env == "production":
        return True
    return (env.get("DEBUG") or "False").strip() != "True"


def require_env(env: Mapping[str, str], name: str, *, hint: str) -> str:
    """Return a REQUIRED env var or raise ImproperlyConfigured with a hint."""
    value = (env.get(name) or "").strip()
    if not value:
        raise ImproperlyConfigured(
            f"{name} is required in this environment: {hint} "
            f"Set it in backend/.env (never committed) or in the container "
            f"environment. No default value is provided on purpose."
        )
    return value


def parse_hosts(env: Mapping[str, str], *, required: bool) -> list[str]:
    """ALLOWED_HOSTS from a comma-separated env var (trimmed, no blanks)."""
    raw = env.get("ALLOWED_HOSTS") or ""
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    if required and not hosts:
        raise ImproperlyConfigured(
            "ALLOWED_HOSTS is required when DEBUG is off / "
            "DJANGO_ENV=production: comma-separated host names the API answers "
            "to (example: 127.0.0.1,example.org). Django refuses every Host "
            "header otherwise, so an empty list would 400 every request."
        )
    return hosts


def parse_list(env: Mapping[str, str], name: str) -> list[str]:
    """Comma-separated env var -> trimmed non-empty list (e.g. CSRF origins)."""
    raw = env.get(name) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def bool_env(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    """Boolean env var; an unknown value fails at startup (never silent)."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ImproperlyConfigured(
        f"Invalid {name}={raw!r}: expected one of "
        f"{sorted(_TRUE_VALUES | _FALSE_VALUES - {''})} "
        f"(example: True or False)."
    )


def int_env(
    env: Mapping[str, str], name: str, default: int, *, minimum: int = 0
) -> int:
    """Integer env var; invalid or out of range fails at startup."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"Invalid {name}={raw!r}: expected an integer >= {minimum}."
        ) from exc
    if value < minimum:
        raise ImproperlyConfigured(
            f"Invalid {name}={value}: expected an integer >= {minimum}."
        )
    return value


def choice_env(
    env: Mapping[str, str], name: str, allowed: frozenset[str], default: str
) -> str:
    """Uppercased choice from the env; an unknown value fails at startup."""
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().upper()
    if value not in allowed:
        raise ImproperlyConfigured(
            f"Invalid {name}={raw!r}: expected one of {sorted(allowed)}."
        )
    return value


def redact_credentials(url: str) -> str:
    """Hide ``user:password@`` of a URL so it can be written to a log."""
    if "://" not in url or "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    credentials, separator, tail = rest.rpartition("@")
    if not separator:
        return url
    if ":" in credentials:
        user = credentials.split(":", 1)[0]
        return f"{scheme}://{user}:***@{tail}"
    return f"{scheme}://***@{tail}"


def build_security_settings(env: Mapping[str, str]) -> dict[str, Any]:
    """SECURE_* / CSRF settings, all read from env, all OFF by default."""
    use_forwarded_proto = bool_env(env, "USE_X_FORWARDED_PROTO", False)
    return {
        "SECURE_SSL_REDIRECT": bool_env(env, "SECURE_SSL_REDIRECT", False),
        "SECURE_HSTS_SECONDS": int_env(env, "SECURE_HSTS_SECONDS", 0),
        "SECURE_HSTS_INCLUDE_SUBDOMAINS": bool_env(
            env, "SECURE_HSTS_INCLUDE_SUBDOMAINS", False
        ),
        "SECURE_HSTS_PRELOAD": bool_env(env, "SECURE_HSTS_PRELOAD", False),
        "SESSION_COOKIE_SECURE": bool_env(env, "SESSION_COOKIE_SECURE", False),
        "CSRF_COOKIE_SECURE": bool_env(env, "CSRF_COOKIE_SECURE", False),
        # nosniff is a default of Django >= 4; re-stated so it is visible and
        # env-tunable, and matched by nginx (deploy/nginx.conf).
        "SECURE_CONTENT_TYPE_NOSNIFF": bool_env(
            env, "SECURE_CONTENT_TYPE_NOSNIFF", True
        ),
        "SECURE_REFERRER_POLICY": (
            (env.get("SECURE_REFERRER_POLICY") or "").strip()
            or "same-origin"
        ),
        # Same value as nginx: a double header can never contradict itself.
        "X_FRAME_OPTIONS": "DENY",
        "CSRF_TRUSTED_ORIGINS": parse_list(env, "CSRF_TRUSTED_ORIGINS"),
        # Only declared when the env says the proxy sets X-Forwarded-Proto;
        # otherwise Django would trust a header any client can send.
        "SECURE_PROXY_SSL_HEADER": (
            ("HTTP_X_FORWARDED_PROTO", "https") if use_forwarded_proto else None
        ),
    }


def build_logging_settings(env: Mapping[str, str]) -> dict[str, Any]:
    """LOGGING -> stdout, level from LOG_LEVEL, no bodies/credentials/tokens.

    The format only carries time, level, logger, module and message: Django
    never puts request bodies, headers or tokens in a log record, and our
    services log identifiers (ids, lengths, exception classes) only.
    """
    level = choice_env(env, "LOG_LEVEL", _LOG_LEVELS, "INFO")
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s %(levelname)s %(name)s %(module)s %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "stdout": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "standard",
                "level": level,
            },
        },
        "root": {"handlers": ["stdout"], "level": level},
        "loggers": {
            "django": {
                "handlers": ["stdout"],
                "level": level,
                "propagate": False,
            },
            "django.request": {
                "handlers": ["stdout"],
                "level": "WARNING",
                "propagate": False,
            },
            "django.server": {
                "handlers": ["stdout"],
                "level": "INFO",
                "propagate": False,
            },
        },
    }
