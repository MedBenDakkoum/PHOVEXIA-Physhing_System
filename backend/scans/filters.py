"""Step 8b - history filters on GET /api/scans/ (US29 / ISO-6.1).

Query parameters (all optional, combined with AND):

    q               substring of url or domain, case-insensitive
    verdict         one of the Scan verdict choices (phishing/legitimate/uncertain)
    status          one of the Scan status choices
    created_after   ISO 8601 datetime, keeps created_at >= value (inclusive)
    created_before  ISO 8601 datetime, keeps created_at <= value (inclusive)

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

from typing import ClassVar

import django_filters as df
from django.db.models import Q

from .models import Scan

_VERDICT_CHOICES = tuple(Scan._meta.get_field("verdict").choices)
_STATUS_CHOICES = tuple(Scan._meta.get_field("status").choices)


class ScanFilter(df.FilterSet):
    """US29 - search and filter my scan history."""

    q = df.CharFilter(method="filter_q")
    verdict = df.ChoiceFilter(choices=_VERDICT_CHOICES)
    status = df.ChoiceFilter(choices=_STATUS_CHOICES)
    created_after = df.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    created_before = df.IsoDateTimeFilter(field_name="created_at", lookup_expr="lte")

    class Meta:
        model = Scan
        fields: ClassVar[list[str]] = []

    def filter_q(self, queryset, name, value):
        """Substring match on url OR domain (icontains, case-insensitive).

        The bound form strips the value and django-filter's Filter.filter
        discards empty values before calling a method filter, so `value` is
        never blank here (a blank q is simply ignored by the base class).
        """
        term = value.strip()
        return queryset.filter(Q(url__icontains=term) | Q(domain__icontains=term))
