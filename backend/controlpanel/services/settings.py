"""US52 - detection settings: singleton row + 30 s cache + env fallback.

Contract:
- get_detection_settings() reads the singleton row (pk = 1). When the table
  is EMPTY it returns the Django settings values (env-driven), so a fresh
  install behaves exactly like before US52.
- The DB values are cached for 30 s; update_detection_settings() clears the
  cache on every PATCH, so an admin change is visible immediately.
- The EMPTY-TABLE fallback is deliberately NOT cached: it is a plain settings
  read, and caching it would freeze env-driven values that operators (and
  tests) change at runtime.
- Validation: 0 < uncertain_lower < phishing_threshold <= 1, and quotas are
  integers within [1, MAX]. Done here (single source of truth) so both the
  API and any future caller obey the same rule.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from django.conf import settings as django_settings
from django.core.cache import cache
from django.db import transaction

from audit.models import AuditLog
from audit.services import record

from ..models import DetectionSettings

CACHE_KEY = "controlpanel:detection-settings"
CACHE_TTL = 30  # seconds (spec: short cache, cleared on every PATCH)

# Sane maxima (spec): quotas are >= 1 and <= a sane maximum, so a typo can
# never disable scanning or open an unbounded flood of anonymous checks.
MAX_DAILY_SCAN_QUOTA = 10_000
MAX_QUICK_CHECK_HOURLY_LIMIT = 1_000

SINGLETON_PK = 1


@dataclass(frozen=True)
class SettingsValues:
    """Effective detection settings (row values or the settings fallback)."""

    phishing_threshold: float
    uncertain_lower: float
    daily_scan_quota: int
    quick_check_hourly_limit: int

    def as_dict(self) -> dict:
        return asdict(self)


class SettingsValidationError(ValueError):
    """Invalid settings payload; `errors` is a DRF-style {field: [msgs]}."""

    def __init__(self, errors: dict):
        self.errors = errors
        super().__init__(f"Invalid detection settings: {errors}")


def validate_settings_values(values: dict) -> None:
    """Raise SettingsValidationError unless every value is in range.

    Cross-field rule: 0 < uncertain_lower < phishing_threshold <= 1.
    Quotas: integers in [1, MAX]. Callers pass MERGED values (current +
    patch), so a partial PATCH is validated as a whole.
    """
    errors: dict[str, list[str]] = {}
    try:
        threshold = float(values["phishing_threshold"])
        lower = float(values["uncertain_lower"])
    except (TypeError, ValueError):
        threshold = lower = None
    if threshold is None or lower is None or not (0.0 < lower < threshold <= 1.0):
        errors["uncertain_lower"] = [
            "Doit respecter : 0 < uncertain_lower < phishing_threshold <= 1."
        ]
        errors["phishing_threshold"] = [
            "Doit respecter : 0 < uncertain_lower < phishing_threshold <= 1."
        ]
    _check_quota(values, "daily_scan_quota", MAX_DAILY_SCAN_QUOTA, errors)
    _check_quota(
        values, "quick_check_hourly_limit", MAX_QUICK_CHECK_HOURLY_LIMIT, errors
    )
    if errors:
        raise SettingsValidationError(errors)


def _check_quota(values: dict, name: str, maximum: int, errors: dict) -> None:
    value = values.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        errors[name] = ["Doit être un entier."]
        return
    if not 1 <= value <= maximum:
        errors[name] = [f"Doit être compris entre 1 et {maximum}."]


def _fallback() -> SettingsValues:
    """Django settings / env values (the pre-US52 behaviour). Raw values on
    purpose: scans.services.inference converts and validates the thresholds
    itself, exactly as before."""
    return SettingsValues(
        phishing_threshold=django_settings.DETECTION_PHISHING_THRESHOLD,
        uncertain_lower=django_settings.DETECTION_UNCERTAIN_LOWER,
        daily_scan_quota=int(django_settings.SCAN_DAILY_QUOTA),
        quick_check_hourly_limit=int(django_settings.QUICK_CHECK_HOURLY_LIMIT),
    )


def get_detection_settings() -> SettingsValues:
    """Effective settings: cached row (30 s), else live settings fallback."""
    cached = cache.get(CACHE_KEY)
    if isinstance(cached, dict):
        return SettingsValues(**cached)
    row = DetectionSettings.objects.filter(pk=SINGLETON_PK).first()
    if row is None:
        # Empty table: never cached (see module docstring).
        return _fallback()
    values = SettingsValues(
        phishing_threshold=row.phishing_threshold,
        uncertain_lower=row.uncertain_lower,
        daily_scan_quota=row.daily_scan_quota,
        quick_check_hourly_limit=row.quick_check_hourly_limit,
    )
    cache.set(CACHE_KEY, values.as_dict(), CACHE_TTL)
    return values


def get_settings_row() -> DetectionSettings | None:
    """The singleton row (metadata for the API), or None before the first PATCH."""
    return DetectionSettings.objects.filter(pk=SINGLETON_PK).select_related(
        "updated_by"
    ).first()


def clear_detection_settings_cache() -> None:
    cache.delete(CACHE_KEY)


def update_detection_settings(
    *, values: dict, user, request=None
) -> SettingsValues:
    """Validate, write the singleton, clear the cache, audit (US52).

    `values` must be the COMPLETE settings dict (current + patch merged):
    the cross-field rule cannot be checked on a partial payload.
    """
    validate_settings_values(values)
    new_values = SettingsValues(
        phishing_threshold=float(values["phishing_threshold"]),
        uncertain_lower=float(values["uncertain_lower"]),
        daily_scan_quota=int(values["daily_scan_quota"]),
        quick_check_hourly_limit=int(values["quick_check_hourly_limit"]),
    )
    with transaction.atomic():
        old_values = get_detection_settings()
        row, _created = DetectionSettings.objects.select_for_update().get_or_create(
            pk=SINGLETON_PK
        )
        row.phishing_threshold = new_values.phishing_threshold
        row.uncertain_lower = new_values.uncertain_lower
        row.daily_scan_quota = new_values.daily_scan_quota
        row.quick_check_hourly_limit = new_values.quick_check_hourly_limit
        row.updated_by = user
        row.save()
        record(
            AuditLog.Action.SETTINGS_CHANGED,
            request=request,
            user=user,
            target=row,
            metadata={"old": old_values.as_dict(), "new": new_values.as_dict()},
        )
    clear_detection_settings_cache()
    return new_values
