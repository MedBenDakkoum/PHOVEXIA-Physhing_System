"""US45 - admin dashboard: aggregations only, constant query count, 60 s cache.

Period resolution:
- `period` = 7d | 30d | 90d (default 30d) = rolling window [now - N days, now];
- or explicit `from` / `to` DATES in settings.TIME_ZONE (inclusive calendar
  days, matching the scan history filter convention).

Median scan duration is computed IN PYTHON on at most 10_000 finished scans
of the period, because SQLite has no median aggregate. Every other figure is
a GROUP BY / count (never one query per row).
"""
from __future__ import annotations

from datetime import datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.utils.dateparse import parse_date

from scans.models import Scan

CACHE_TTL = 60  # seconds (spec)
PERIOD_CHOICES = ("7d", "30d", "90d")
DEFAULT_PERIOD = "30d"
MEDIAN_SAMPLE_LIMIT = 10_000
_TOP_DOMAINS = 10


class DashboardPeriodError(ValueError):
    """Invalid period/from/to query parameters (HTTP 400)."""


def parse_period(query_params) -> tuple[datetime, datetime, str]:
    """Return (start, end, cache_label) for the requested period."""
    period = (query_params.get("period") or "").strip()
    date_from = (query_params.get("from") or "").strip()
    date_to = (query_params.get("to") or "").strip()

    if date_from or date_to:
        if period:
            raise DashboardPeriodError(
                "Paramètre inconnu : utilisez `period` OU `from`/`to`, pas les deux."
            )
        if not (date_from and date_to):
            raise DashboardPeriodError("`from` et `to` doivent être fournis ensemble.")
        start_date = parse_date(date_from)
        end_date = parse_date(date_to)
        if start_date is None or end_date is None:
            raise DashboardPeriodError(
                "Dates invalides : format attendu YYYY-MM-DD."
            )
        if start_date > end_date:
            raise DashboardPeriodError("`from` doit être antérieur ou égal à `to`.")
        tz = timezone.get_current_timezone()
        start = timezone.make_aware(datetime.combine(start_date, time.min), tz)
        end = timezone.make_aware(
            datetime.combine(end_date + timedelta(days=1), time.min), tz
        )
        return start, end, f"{date_from}:{date_to}"

    if not period:
        period = DEFAULT_PERIOD
    if period not in PERIOD_CHOICES:
        raise DashboardPeriodError(
            f"Période invalide : attendu {' ou '.join(PERIOD_CHOICES)}."
        )
    days = int(period[:-1])
    now = timezone.now()
    return now - timedelta(days=days), now, period


def build_dashboard(start: datetime, end: datetime) -> dict:
    """Aggregate the figures for [start, end). Constant number of queries."""
    base = Scan.objects.filter(created_at__gte=start, created_at__lt=end)

    # 1) one GROUP BY per requested breakdown (3 queries).
    total = base.count()
    by_verdict = _group(base, "verdict")
    by_status = _group(base, "status")
    by_source = _group(base, "detection_source")

    # 2) anonymous quick checks of the period (1 query).
    quick_checks = base.filter(owner__isnull=True).count()

    # 3) scans per calendar day in the project time zone (1 query).
    tz = timezone.get_current_timezone()
    per_day_qs = (
        base.annotate(day=TruncDate("created_at", tzinfo=tz))
        .values("day")
        .annotate(count=Count("pk"))
        .order_by("day")
    )
    scans_per_day = [
        {"date": row["day"].isoformat(), "count": row["count"]} for row in per_day_qs
    ]

    # 4) top phishing domains (1 query).
    top_domains = list(
        base.filter(verdict="phishing")
        .exclude(domain="")
        .values("domain")
        .annotate(count=Count("pk"))
        .order_by("-count", "domain")[:_TOP_DOMAINS]
    )
    top_phishing_domains = [
        {"domain": row["domain"], "count": row["count"]} for row in top_domains
    ]

    # 5) median duration in Python on at most 10_000 finished scans (1 query).
    durations = [
        (finished - created).total_seconds()
        for created, finished in base.filter(finished_at__isnull=False)
        .order_by("-finished_at")
        .values_list("created_at", "finished_at")[:MEDIAN_SAMPLE_LIMIT]
        if created is not None and finished is not None
    ]
    durations.sort()
    median = _median(durations)

    # 6) users by role (global snapshot, 1 query).
    User = get_user_model()
    users_by_role = {
        row["role"]: row["count"]
        for row in User.objects.values("role").annotate(count=Count("pk"))
    }

    confirmed = by_status.get("confirmed", 0)
    false_positives = by_status.get("false_positive", 0)
    fp_denominator = confirmed + false_positives

    return {
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "totals": {
            "scans": total,
            "users": sum(users_by_role.values()),
        },
        "quick_checks": quick_checks,
        "scans_by_verdict": by_verdict,
        "scans_by_status": by_status,
        "scans_by_detection_source": by_source,
        "phishing_rate": _ratio(by_verdict.get("phishing", 0), total),
        "false_positive_rate": _ratio(false_positives, fp_denominator),
        "pending_reviews": by_status.get("under_review", 0),
        "median_scan_duration_seconds": median,
        "scans_per_day": scans_per_day,
        "top_phishing_domains": top_phishing_domains,
        "users_by_role": users_by_role,
        "median_sample_size": len(durations),
    }


def get_dashboard(query_params) -> dict:
    """Cached dashboard for the requested period (60 s, key = the period)."""
    start, end, label = parse_period(query_params)
    cache_key = f"controlpanel:dashboard:{label}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return cached
    payload = build_dashboard(start, end)
    payload["period"]["label"] = label
    cache.set(cache_key, payload, CACHE_TTL)
    return payload


def _group(queryset, field: str) -> dict:
    rows = queryset.values(field).annotate(count=Count("pk"))
    return {
        (row[field] or "none"): row["count"] for row in rows
    }


def _ratio(numerator: int, denominator: int):
    if denominator <= 0:
        return None
    return numerator / denominator


def _median(sorted_values: list[float]):
    if not sorted_values:
        return None
    middle = len(sorted_values) // 2
    if len(sorted_values) % 2:
        return sorted_values[middle]
    return (sorted_values[middle - 1] + sorted_values[middle]) / 2
