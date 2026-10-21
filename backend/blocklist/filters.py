"""Blocklist list filters (US38 / ISO-6.1).

Same day-bound date semantics as the scan history (Step 8b): a bare
`YYYY-MM-DD` covers the whole local calendar day, both bounds inclusive.
Choices are read from the model so a new choice cannot leave the API behind.
"""
from __future__ import annotations

from typing import ClassVar

import django_filters as df
from django.db.models import Q

from scans.filters import DayInclusiveIsoDateTimeFilter, EndOfDayIsoDateTimeFilter

from .models import BlocklistEntry

_REASON_CHOICES = tuple(BlocklistEntry._meta.get_field("reason").choices)


class BlocklistFilter(df.FilterSet):
    """GET /api/blocklist/ query parameters (all optional, combined with AND)."""

    q = df.CharFilter(method="filter_q")
    reason = df.ChoiceFilter(choices=_REASON_CHOICES)
    added_by = df.CharFilter(method="filter_added_by")
    created_after = DayInclusiveIsoDateTimeFilter(
        field_name="created_at", lookup_expr="gte"
    )
    created_before = EndOfDayIsoDateTimeFilter(
        field_name="created_at", lookup_expr="lte"
    )

    class Meta:
        model = BlocklistEntry
        fields: ClassVar[list[str]] = []

    def filter_q(self, queryset, name, value):
        """Substring match on domain OR note (icontains, literal)."""
        term = value.strip()
        return queryset.filter(Q(domain__icontains=term) | Q(note__icontains=term))

    def filter_added_by(self, queryset, name, value):
        """Filter on the email of the analyst who added the entry."""
        term = value.strip()
        return queryset.filter(added_by__email__icontains=term)
