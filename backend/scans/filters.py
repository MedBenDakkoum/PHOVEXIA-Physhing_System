"""Step 8b - history filters on GET /api/scans/ (US29 / ISO-6.1).

Query parameters (all optional, combined with AND):

    q               substring of url or domain, case-insensitive, literal
                    (no SQL wildcard: %, _, ' and " are matched as characters)
    verdict         one of the Scan verdict choices (phishing/legitimate/uncertain)
    status          one of the Scan status choices
    created_after   ISO 8601 datetime, OR a bare date YYYY-MM-DD; keeps
                    created_at >= value (inclusive)
    created_before  ISO 8601 datetime, OR a bare date YYYY-MM-DD; keeps
                    created_at <= value (inclusive)

Gap check (19 Oct 2026): a bare date (YYYY-MM-DD) means the WHOLE calendar day
in settings.TIME_ZONE, so both bound days are inclusive:
    created_after=2026-10-10   ->  created_at >= 2026-10-10 00:00:00 (local)
    created_before=2026-10-10  ->  created_at <= 2026-10-10 23:59:59.999999 (local)
A full ISO 8601 datetime keeps the exact instant (behaviour unchanged).

The view adds `ordering` (whitelist, see views.ScanListCreateView) on top of
this FilterSet.

Guarantees:
- The filters are applied on the queryset of the view, which is already scoped
  to `owner=request.user`, so no filter can ever widen the result to another
  user's scans (US29, ISO-6.6).
- An invalid value (malformed date, unknown verdict or status) answers 400
  before any SQL runs: django-filter's backend raises (`raise_exception`).
- Verdict/status choices are read from the model fields, so a new choice added
  later in models.py is automatically accepted here (no duplicated list).
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from typing import ClassVar

import django_filters as df
from django.db.models import Q
from django.utils import timezone

from .models import Scan

_VERDICT_CHOICES = tuple(Scan._meta.get_field("verdict").choices)
_STATUS_CHOICES = tuple(Scan._meta.get_field("status").choices)

_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class _DayBound(datetime):
    """A datetime that remembers the client sent a bare date (YYYY-MM-DD)."""

    is_day_bound = True


def _local_midnight(value: str) -> _DayBound:
    """Local midnight of the bare date `value`, in settings.TIME_ZONE."""
    parsed = date.fromisoformat(value)
    return _DayBound(
        parsed.year,
        parsed.month,
        parsed.day,
        tzinfo=timezone.get_default_timezone(),
    )


class DayBoundIsoDateTimeField(df.fields.IsoDateTimeField):
    """Full ISO 8601 datetime, or a bare date YYYY-MM-DD = a local calendar day.

    A bare date becomes the local midnight of that day in settings.TIME_ZONE
    and is tagged `is_day_bound=True` so `created_before` can widen it to the
    end of the day (both bound days inclusive).
    """

    def to_python(self, value):
        if isinstance(value, str) and _DATE_ONLY_RE.match(value.strip()):
            return _local_midnight(value.strip())
        return super().to_python(value)


class DayInclusiveIsoDateTimeFilter(df.IsoDateTimeFilter):
    """IsoDateTimeFilter accepting a bare date (see the field above)."""

    field_class = DayBoundIsoDateTimeField


class EndOfDayIsoDateTimeFilter(DayInclusiveIsoDateTimeFilter):
    """`<=` filter: a bare date is widened to 23:59:59.999999 local time.

    So `created_before=2026-10-10` keeps the whole of 10 October in
    settings.TIME_ZONE (both bound days are inclusive). A full ISO datetime
    is compared to the exact instant, unchanged.
    """

    def filter(self, queryset, value):
        if value is not None and getattr(value, "is_day_bound", False):
            value = value + timedelta(days=1) - timedelta(microseconds=1)
        return super().filter(queryset, value)


class ScanFilter(df.FilterSet):
    """US29 - search and filter my scan history."""

    q = df.CharFilter(method="filter_q")
    verdict = df.ChoiceFilter(choices=_VERDICT_CHOICES)
    status = df.ChoiceFilter(choices=_STATUS_CHOICES)
    created_after = DayInclusiveIsoDateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    created_before = EndOfDayIsoDateTimeFilter(
        field_name="created_at", lookup_expr="lte"
    )

    class Meta:
        model = Scan
        fields: ClassVar[list[str]] = []

    def filter_q(self, queryset, name, value):
        """Substring match on url OR domain (icontains, case-insensitive).

        icontains escapes the value, so %, _, ' and " are matched literally
        (no SQL wildcard, no injection) - proven by the gap-check tests.

        The bound form strips the value and django-filter's Filter.filter
        discards empty values before calling a method filter, so `value` is
        never blank here (a blank q is simply ignored by the base class).
        """
        term = value.strip()
        return queryset.filter(Q(url__icontains=term) | Q(domain__icontains=term))
