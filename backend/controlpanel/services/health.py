"""US53 - system health checks.

Every check returns {"ok": bool, "message": short str, "value": json-able}
and NEVER raises: a failing check is reported as ok=False with a short safe
message (exception class name only - no secret, no stack trace, no URL).
The overall status is "ok" when every check is ok, else "degraded".
"""
from __future__ import annotations

import os
from datetime import timedelta

from django.conf import settings
from django.db import connection
from django.utils import timezone

from scans.models import Scan

from .model_versions import get_active_model_version_label

_BROKER_QUEUE = "celery"  # default Celery queue name on the broker DB
_MESSAGE_MAX = 120


def check_database() -> dict:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    return {"ok": True, "message": "ok", "value": None}


def _redis_client(url: str):
    import redis

    return redis.Redis.from_url(
        url, socket_connect_timeout=1, socket_timeout=1
    )


def _broker_url() -> str:
    return (settings.CELERY_BROKER_URL or "").strip()


def check_redis() -> dict:
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return {"ok": False, "message": "not configured", "value": None}
    try:
        _redis_client(url).ping()
    except Exception as exc:  # noqa: BLE001 - a failing check must not raise
        return {"ok": False, "message": _err(exc), "value": None}
    return {"ok": True, "message": "ok", "value": None}


def check_celery() -> dict:
    """inspect().ping() with a 1 s timeout; "unreachable" instead of failing."""
    from celery import current_app

    try:
        replies = current_app.control.ping(timeout=1)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": f"unreachable ({type(exc).__name__})"[:_MESSAGE_MAX],
            "value": None,
        }
    workers = len(replies or [])
    if workers == 0:
        return {"ok": False, "message": "unreachable (no worker)", "value": 0}
    return {"ok": True, "message": f"{workers} worker(s)", "value": workers}


def check_queue_length() -> dict:
    url = _broker_url()
    if not url:
        return {"ok": False, "message": "not configured", "value": None}
    try:
        length = _redis_client(url).llen(_BROKER_QUEUE)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": _err(exc), "value": None}
    return {"ok": True, "message": f"{length} message(s)", "value": int(length)}


def check_stuck_scans() -> dict:
    """Scans still ANALYZING after settings.ANALYZING_STUCK_MINUTES."""
    cutoff = timezone.now() - timedelta(minutes=settings.ANALYZING_STUCK_MINUTES)
    count = Scan.objects.filter(
        status=Scan.Status.ANALYZING, updated_at__lt=cutoff
    ).count()
    return {
        "ok": True,
        "message": f"{count} stuck for > {settings.ANALYZING_STUCK_MINUTES} min",
        "value": count,
    }


def check_last_finished_scan() -> dict:
    last = (
        Scan.objects.filter(finished_at__isnull=False)
        .order_by("-finished_at")
        .values_list("finished_at", flat=True)
        .first()
    )
    value = last.isoformat() if last else None
    return {"ok": True, "message": "ok" if last else "none yet", "value": value}


def check_active_model_version() -> dict:
    label = get_active_model_version_label()
    return {
        "ok": bool(label),
        "message": label or "no active version",
        "value": label or None,
    }


def build_health() -> dict:
    """Run every check independently; the view must never fail."""
    checks = {}
    for name, func in (
        ("database", check_database),
        ("redis", check_redis),
        ("celery", check_celery),
        ("queue_length", check_queue_length),
        ("stuck_scans", check_stuck_scans),
        ("last_finished_scan", check_last_finished_scan),
        ("active_model_version", check_active_model_version),
    ):
        try:
            checks[name] = func()
        except Exception as exc:  # noqa: BLE001 - defensive: never fail the request
            checks[name] = {"ok": False, "message": _err(exc), "value": None}
    status = "ok" if all(item["ok"] for item in checks.values()) else "degraded"
    return {
        "status": status,
        "checked_at": timezone.now().isoformat(),
        "checks": checks,
    }


def _err(exc: BaseException) -> str:
    """Short safe message: exception class only, never str(exc) (could leak
    a URL/credential), never a stack trace."""
    return f"error ({type(exc).__name__})"[:_MESSAGE_MAX]
