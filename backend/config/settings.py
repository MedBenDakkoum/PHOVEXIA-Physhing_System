import logging
import os
from pathlib import Path

from celery.schedules import crontab
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

from config.production import (
    build_logging_settings,
    build_security_settings,
    is_production,
    parse_hosts,
    redact_credentials,
    require_env,
)

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment-driven production settings (config/production.py).
#
# PRODUCTION_MODE = DJANGO_ENV=production OR DEBUG is not explicitly "True".
# In that path SECRET_KEY and ALLOWED_HOSTS are REQUIRED (clear startup
# error, no default key) and DEBUG is forced to False. Local development
# (.env with DEBUG=True) keeps the previous behaviour.
# ---------------------------------------------------------------------------
DJANGO_ENV = (os.getenv("DJANGO_ENV") or "development").strip().lower()
PRODUCTION_MODE = is_production(os.environ)

DEBUG = (not PRODUCTION_MODE) and os.getenv("DEBUG", "False") == "True"

SECRET_KEY = require_env(
    os.environ,
    "SECRET_KEY",
    hint="the Django signing key (long, random, private).",
)
ALLOWED_HOSTS = parse_hosts(os.environ, required=PRODUCTION_MODE)

# CORS (Step 8c) - browser origins allowed to call the API cross-origin.
# Comma-separated in .env; the DEFAULT is empty = no cross-origin request is
# allowed (same-origin only), which is the safe default.
# CORS_ALLOW_CREDENTIALS stays False on purpose: the API authenticates with a
# JWT in the Authorization header, never with cookies, so browsers do not need
# (and must not send) credentials cross-origin.
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
CORS_ALLOW_CREDENTIALS = False


def _positive_int_env(name: str, default: int) -> int:
    """Read an int env var; fall back to `default` with a warning if invalid.

    Invalid means: not an integer, or < 1 (BR-01: a quota of 0 or negative
    would lock every user out of scanning). An unset/empty var keeps the
    default silently (no warning).
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning(
            "Invalid %s=%r: not an integer; falling back to %d.", name, raw, default
        )
        return default
    if value < 1:
        logger.warning(
            "Invalid %s=%r: must be >= 1; falling back to %d.", name, raw, default
        )
        return default
    return value




def _float_env(name: str, default: float) -> float:
    """Read a float env var; fall back to `default` with a warning if invalid.

    Cross-field and range validation (lower < upper, both in [0, 1]) is done
    by scans.services.inference._thresholds() which raises ImproperlyConfigured.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError:
        logger.warning(
            "Invalid %s=%r: not a float; falling back to %s.", name, raw, default
        )
        return default
    return value


def _non_negative_int_env(name: str, default: int) -> int:
    """Read an int env var >= 0; fall back to `default` with a warning if invalid.

    Used for NUM_PROXIES (Step 8d): 0 = the throttle key is REMOTE_ADDR only,
    a client-supplied X-Forwarded-For is never trusted.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning(
            "Invalid %s=%r: not an integer; falling back to %d.", name, raw, default
        )
        return default
    if value < 0:
        logger.warning(
            "Invalid %s=%r: must be >= 0; falling back to %d.", name, raw, default
        )
        return default
    return value


def _throttle_rate_env(name: str, default: str) -> str:
    """Read a DRF throttle rate env var; raise ImproperlyConfigured if invalid.

    Accepted format = the one DRF's SimpleRateThrottle.parse_rate() parses:
    "<count>/<period>" where the first letter of the period is one of
    s, m, h, d (examples: "10/min", "10/hour"). An invalid rate FAILS AT
    STARTUP on purpose: silently falling back to the default would let an
    operator believe a limit is active when it is not. count must be >= 1
    ("0/..." would lock every client out). Unset/empty keeps `default`.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    rate = raw.strip()
    try:
        num, period = rate.split("/")
        count = int(num)
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"Invalid {name}={rate!r}: expected '<count>/<period>' with the "
            f"period starting with one of s, m, h, d (example: '10/min')."
        ) from exc
    if not period or period[0] not in "smhd":
        raise ImproperlyConfigured(
            f"Invalid {name}={rate!r}: the period must start with one of "
            f"s, m, h, d (example: '10/min')."
        )
    if count < 1:
        raise ImproperlyConfigured(
            f"Invalid {name}={rate!r}: the count must be >= 1."
        )
    return rate


def _redis_cache_url() -> str:
    """Cache URL derived from REDIS_URL, pointing at Redis DB 1 ("" = no Redis).

    DB 1 on purpose: DB 0 is the Celery broker and Django's cache.clear()
    issues FLUSHDB on this database, which would wipe the Celery keys
    (AGENTS.md lesson learned).
    """
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        return ""
    base, sep, query = redis_url.partition("?")
    base = base.rstrip("/")
    suffix = f"?{query}" if sep else ""
    tail = base.rsplit("/", 1)[-1]
    if tail.isdigit():
        return f"{base.rsplit('/', 1)[0]}/1{suffix}"
    return f"{base}/1{suffix}"


def _caches_config() -> dict:
    """Step 8d: DRF throttle counters must be shared by every process.

    Redis is the real counter store (REDIS_URL in .env, DB 1). If it is not
    configured or not reachable, fall back to LocMemCache WITH a warning:
    LocMem is per process and cannot protect a multi-process deployment.
    Any failure (no redis package, bad URL, timeout) must NOT crash startup.
    """
    url = _redis_cache_url()
    if not url:
        logger.warning(
            "REDIS_URL is not set; using LocMemCache for the throttle counters "
            "(per process only, NOT a protection for production)."
        )
    else:
        try:
            # Lazy import: only needed for the startup probe.
            import redis

            redis.Redis.from_url(
                url, socket_connect_timeout=1, socket_timeout=1
            ).ping()
        except Exception as exc:  # noqa: BLE001 - startup must never crash on the probe
            logger.warning(
                "Redis cache %s unreachable (%s); falling back to LocMemCache "
                "(per process only, NOT a protection for production).",
                # REDIS_URL embeds the password (full Docker profile): the
                # logged URL must never carry credentials.
                redact_credentials(url),
                exc,
            )
        else:
            return {
                "default": {
                    "BACKEND": "django.core.cache.backends.redis.RedisCache",
                    "LOCATION": url,
                }
            }
    return {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "phishing-throttle",
        }
    }


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'django_filters',
    'drf_spectacular',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'accounts',
    'audit',
    'scans',
    # Step 10: human review workflow (Report / AnalystNote / Notification).
    # After 'scans' (string FK references: no load-order constraint).
    'reviews',
    # Step 11: blocklist and protected brands (US38-US41, US55).
    'blocklist',
    # Step 12: admin control panel (US45, US48, US49, US52-US54 / BR-11).
    'controlpanel',
    # Step 13 (US5, US56, US57): templated email delivery (service + Celery
    # task + templates). No models, no URLs.
    'emails',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # Step 8c: CorsMiddleware as high as possible, and in all cases BEFORE
    # CommonMiddleware (django-cors-headers requirement): preflight OPTIONS
    # must be answered before any middleware that can generate responses.
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.1/ref/settings/#databases
# DB_ENGINE=sqlite (default) or postgres (when DB_ENGINE=postgres is set)

DB_ENGINE = os.getenv("DB_ENGINE", "sqlite")

if DB_ENGINE == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME", "phishing_db"),
            "USER": os.getenv("DB_USER", "postgres"),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", "localhost"),
            "PORT": os.getenv("DB_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# BR-01 / US-14: max scans per user per calendar day (in TIME_ZONE above).
# Same limit for every role (end user, analyst, admin) - deliberate decision.
# Step 12 (US52): fallback while the DetectionSettings table is empty.
SCAN_DAILY_QUOTA = _positive_int_env("SCAN_DAILY_QUOTA", 20)

# Step 9 / US11 / BR-02: anonymous quick checks per IP per hour. Enforced by
# an atomic counter in the cache (scans.services.quick_check), not by DRF.
# Step 12 (US52): fallback while the DetectionSettings table is empty.
QUICK_CHECK_HOURLY_LIMIT = _positive_int_env("QUICK_CHECK_HOURLY_LIMIT", 5)

# Step 15 (retention / ISO-6.5 privacy): anonymous FAST scans (quick checks,
# owner NULL) older than this many days are deleted by the daily beat task
# scans.purge_expired_data. Their audit entries keep the domain only, never
# the URL (record(metadata={"domain": ...}) in scans/views.py).
QUICK_CHECK_RETENTION_DAYS = _positive_int_env("QUICK_CHECK_RETENTION_DAYS", 7)

# Detection thresholds (verdict = phishing if score >= upper, legitimate if
# score <= lower, uncertain in between -> analyst queue). Validated by
# scans.services.inference.__thresholds(): floats in [0, 1] and lower < upper.
# Step 12 (US52): these are the FALLBACK values used while the
# DetectionSettings table is empty; once an admin PATCHes /api/admin/settings/
# the DB row wins (controlpanel.services.settings.get_detection_settings).
DETECTION_PHISHING_THRESHOLD = _float_env("DETECTION_PHISHING_THRESHOLD", 0.70)
DETECTION_UNCERTAIN_LOWER = _float_env("DETECTION_UNCERTAIN_LOWER", 0.40)

# Step 12 (US53) / Step 15 (ISO-6.5 reliability): a scan still ANALYZING after
# this many minutes is (a) reported as "stuck" by GET /api/admin/health/ and
# (b) moved to FAILED with error_message "timeout" by the beat task
# scans.reap_stuck_scans. One knob, one concept: the Step 12 name
# ANALYZING_STUCK_MINUTES was renamed SCAN_STUCK_MINUTES in Step 15.
SCAN_STUCK_MINUTES = _positive_int_env("SCAN_STUCK_MINUTES", 10)

# Step 12 (US48): directory where model files live (file_path is validated
# against path traversal inside this directory).
MODELS_DIR = Path(os.getenv("MODELS_DIR", BASE_DIR / "models"))

# ---------------------------------------------------------------------------
# Internal clients to the collector and inference services (US26 / US20).
# All values come from the environment; empty URLs mean "not configured" and
# the real-bundle path fails closed (infrastructure failure -> FAILED) rather
# than silently calling a wrong endpoint. The MOCK path never uses them.
# ---------------------------------------------------------------------------
COLLECTOR_URL = os.getenv("COLLECTOR_URL", "")
COLLECTOR_API_KEY = os.getenv("COLLECTOR_API_KEY", "")
COLLECTOR_TIMEOUT = _float_env("COLLECTOR_TIMEOUT", 30.0)
INFERENCE_URL = os.getenv("INFERENCE_URL", "")
INFERENCE_API_KEY = os.getenv("INFERENCE_API_KEY", "")
INFERENCE_TIMEOUT = _float_env("INFERENCE_TIMEOUT", 30.0)

# Media root for user-facing artefacts (screenshots). Inside the container the
# full profile mounts a named volume here (worker read-write, web read-only).
MEDIA_ROOT = Path(os.getenv("MEDIA_ROOT", BASE_DIR / "media"))
# How long a screenshot (and its scan's file) is kept before the beat job
# deletes it (privacy / ISO-6.5 retention, same spirit as quick checks).
SCREENSHOT_RETENTION_DAYS = _positive_int_env("SCREENSHOT_RETENTION_DAYS", 30)


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.1/howto/static-files/

STATIC_URL = 'static/'
# Feature: production settings. Where `manage.py collectstatic` writes; nginx
# serves this directory (deploy/nginx.conf) from the shared static_volume.
# Overridable for the container path /app/staticfiles.
STATIC_ROOT = Path(os.getenv("STATIC_ROOT", BASE_DIR / "staticfiles"))


# Email
# https://docs.djangoproject.com/en/6.1/topics/email/#topic-email-configuration
# Step 13 (US5, US56, US57): every value comes from .env (keys keep the
# classic EMAIL_* names); the default backend prints to the console so a
# fresh install works without SMTP. Django 6.1 configures mail through
# MAILERS instead of the flat EMAIL_HOST/... globals, so the env values are
# read straight into the MAILERS dict below.

DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL", "noreply@phishing-detector.local"
)

_mailer_backend = os.getenv(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)

# Backend kwargs are accepted by the SMTP backend only: Django 6.1 raises
# InvalidMailer for any option a backend does not understand (the console
# backend rejects host/port/...), so they are attached conditionally.
if _mailer_backend.endswith("smtp.EmailBackend"):
    _mailer_options = {
        "host": os.getenv("EMAIL_HOST", ""),
        "port": _positive_int_env("EMAIL_PORT", 587),
        "username": os.getenv("EMAIL_HOST_USER", ""),
        "password": os.getenv("EMAIL_HOST_PASSWORD", ""),
        "use_tls": os.getenv("EMAIL_USE_TLS", "True") == "True",
    }
else:
    _mailer_options = {}

MAILERS = {
    "default": {
        "BACKEND": _mailer_backend,
        "OPTIONS": _mailer_options,
    },
}

# Frontend base URL used in the password-reset link (no trailing slash).
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
# Step 13 / US5: validity of a reset token, in seconds (Django reads this
# setting in PasswordResetTokenGenerator.check_token).
PASSWORD_RESET_TIMEOUT = _positive_int_env("PASSWORD_RESET_TIMEOUT", 3600)

from datetime import timedelta

AUTH_USER_MODEL = "accounts.User"

# Step 8d: cache = counter store of the DRF throttles (see _caches_config).
CACHES = _caches_config()

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # Step 12 (US54): Api-Key BEFORE JWT. It returns None for any other
        # scheme, and raises 401 when an Api-Key hits an endpoint outside the
        # allowlist (POST /api/scans/, GET /api/scans/{uuid}/).
        "controlpanel.authentication.ApiKeyAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "30/min",
        "user": "120/min",
        # Step 8d: auth endpoints (ScopedRateThrottle in accounts/views.py),
        # rates overridable from .env, invalid values fail at startup.
        "login": _throttle_rate_env("THROTTLE_LOGIN", "10/min"),
        "register": _throttle_rate_env("THROTTLE_REGISTER", "10/hour"),
        "refresh": _throttle_rate_env("THROTTLE_REFRESH", "60/min"),
        "change_password": _throttle_rate_env("THROTTLE_CHANGE_PASSWORD", "5/hour"),
        # Step 9: GET /api/quick-check/{uuid}/ (ScopedRateThrottle per IP).
        "quick_check_detail": _throttle_rate_env(
            "THROTTLE_QUICK_CHECK_DETAIL", "60/min"
        ),
    # Step 12 (US54): per-API-key throttle (controlpanel.throttling).
    "api_key": _throttle_rate_env("THROTTLE_API_KEY", "60/min"),
    # Step 13 (US5): password reset - per IP on both endpoints.
    # The per-EMAIL limit (3/hour) is a cache counter in accounts.services.
    "password_reset": _throttle_rate_env("THROTTLE_PASSWORD_RESET", "5/hour"),
    "password_reset_confirm": _throttle_rate_env(
        "THROTTLE_PASSWORD_RESET_CONFIRM", "10/hour"
    ),
},
    # Step 8d: 0 proxies => the throttle key is REMOTE_ADDR; a client-supplied
    # X-Forwarded-For is NEVER trusted (set N behind N reverse proxies).
    "NUM_PROXIES": _non_negative_int_env("NUM_PROXIES", 0),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Phishing Multimodal API",
    "VERSION": "0.1.0",
    # Step 10: Report.Status (open/resolved) and Scan.Status are both exposed
    # through a field named "status". Without explicit names for BOTH, the
    # enum post-processor emits a "non-optimally resolvable collision"
    # warning and invents unstable enum names (Warnings must stay at 0).
    # Step 12: same story for two fields named "kind"
    # (ModelVersion.Kind vs Notification.Kind).
    "ENUM_NAME_OVERRIDES": {
        "ScanStatusEnum": "scans.models.Scan.Status",
        "ScanVerdictEnum": "scans.models.VERDICT_CHOICES",
        "ReportStatusEnum": "reviews.models.Report.Status",
        "ModelVersionKindEnum": "controlpanel.models.ModelVersion.Kind",
        "NotificationKindEnum": "reviews.models.Notification.Kind",
    },
}

# Celery (Step 6) - broker = Redis (REDIS_URL in .env)
# JSON only: accept_content refuses pickle, so a crafted/old message can never
# execute code in the worker. Time limits: soft 90 s (task may clean up),
# hard 120 s (worker is killed).
CELERY_BROKER_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
# One run_scan attempt is bounded by COLLECTOR_TIMEOUT (30 s) plus
# INFERENCE_TIMEOUT (30 s) plus screenshot work (~30 s worst case). Retries
# are separate tasks with a countdown, so these limits only bound ONE attempt:
# 90 s soft leaves enough margin before the 120 s hard kill.
CELERY_TASK_SOFT_TIME_LIMIT = 90
CELERY_TASK_TIME_LIMIT = 120
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS = False

# Step 15 (ISO-6.5 reliability): the periodic jobs are DECLARED IN CODE, the
# thresholds they use come from the environment (SCAN_STUCK_MINUTES,
# QUICK_CHECK_RETENTION_DAYS). `celery -A config beat` (compose profile
# `full`) reads this mapping; nothing else schedules these two tasks.
CELERY_BEAT_SCHEDULE = {
    # Scans stuck in ANALYZING (worker died) or in SUBMITTED (task never
    # started) are moved to FAILED, one row lock at a time (skip_locked).
    "scans-reap-stuck-scans": {
        "task": "scans.reap_stuck_scans",
        "schedule": crontab(minute="*/5"),
    },
    # Privacy (US-retention): anonymous FAST scans + expired JWT tokens.
    "scans-purge-expired-data": {
        "task": "scans.purge_expired_data",
        "schedule": crontab(hour=3, minute=0),
    },
}

# ---------------------------------------------------------------------------
# Feature: production settings (ISO-6.6 security).
#
# All values come from the environment (backend/.env in dev, the compose
# `environment` block in the full profile) and default to OFF so a plain-HTTP
# local stack keeps working:
#   - HTTPS values: SECURE_SSL_REDIRECT, SECURE_HSTS_*,
#     SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE -> deploy/README.md
#   - SECURE_PROXY_SSL_HEADER is declared ONLY when USE_X_FORWARDED_PROTO is
#     truthy, otherwise Django would trust an X-Forwarded-Proto header that
#     any client can send by itself.
# A malformed flag fails at startup (config.production.bool_env), it never
# silently falls back to a "safe-looking" default.
# ---------------------------------------------------------------------------
_SECURITY = build_security_settings(os.environ)
SECURE_SSL_REDIRECT = _SECURITY["SECURE_SSL_REDIRECT"]
SECURE_HSTS_SECONDS = _SECURITY["SECURE_HSTS_SECONDS"]
SECURE_HSTS_INCLUDE_SUBDOMAINS = _SECURITY["SECURE_HSTS_INCLUDE_SUBDOMAINS"]
SECURE_HSTS_PRELOAD = _SECURITY["SECURE_HSTS_PRELOAD"]
SESSION_COOKIE_SECURE = _SECURITY["SESSION_COOKIE_SECURE"]
CSRF_COOKIE_SECURE = _SECURITY["CSRF_COOKIE_SECURE"]
SECURE_CONTENT_TYPE_NOSNIFF = _SECURITY["SECURE_CONTENT_TYPE_NOSNIFF"]
SECURE_REFERRER_POLICY = _SECURITY["SECURE_REFERRER_POLICY"]
X_FRAME_OPTIONS = _SECURITY["X_FRAME_OPTIONS"]
CSRF_TRUSTED_ORIGINS = _SECURITY["CSRF_TRUSTED_ORIGINS"]
SECURE_PROXY_SSL_HEADER = _SECURITY["SECURE_PROXY_SSL_HEADER"]

# Feature: production settings (ISO-6.5 / ISO-6.6): everything goes to stdout
# so `docker compose logs` is the single place to read, level from LOG_LEVEL,
# format without request bodies, credentials or tokens.
LOGGING = build_logging_settings(os.environ)
