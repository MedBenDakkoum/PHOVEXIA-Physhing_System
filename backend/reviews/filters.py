"""Step 10 - review queue filters (US33).

Same day-bound date semantics as the scan history (Step 8b): a bare
`YYYY-MM-DD` covers the whole local calendar day, both bounds inclusive.
The `source` filter separates the scans that entered the queue automatically
(uncertain verdict) from the ones a user reported (US31).
"""
from __future__ import annotations

from typing import ClassVar

import django_filters as df

from scans.filters import DayInclusiveIsoDateTimeFilter, EndOfDayIsoDateTimeFilter
from scans.models import Scan

_VERDICT_CHOICES = tuple(Scan._meta.get_field("verdict").choices)


class ReviewQueueFilter(df.FilterSet):
    """GET /api/review/queue/ query parameters (all optional, combined with AND)."""

    source = df.ChoiceFilter(
        choices=(("uncertain", "Uncertain"), ("reported", "Reported")),
        method="filter_source",
    )
    verdict = df.ChoiceFilter(choices=_VERDICT_CHOICES)
    created_after = DayInclusiveIsoDateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    created_before = EndOfDayIsoDateTimeFilter(
        field_name="created_at", lookup_expr="lte"
    )

    class Meta:
        model = Scan
        fields: ClassVar[list[str]] = []

    def filter_source(self, queryset, name, value):
        if value == "reported":
            return queryset.filter(reported=True)
        return queryset.filter(reported=False)
