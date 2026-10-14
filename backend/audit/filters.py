from typing import ClassVar

import django_filters as df

from .models import AuditLog


class AuditLogFilter(df.FilterSet):
    user = df.NumberFilter(field_name="user_id")
    user_email = df.CharFilter(field_name="user_email", lookup_expr="icontains")
    action = df.ChoiceFilter(choices=AuditLog.Action.choices)
    date_from = df.DateFilter(field_name="created_at", lookup_expr="date__gte")
    date_to = df.DateFilter(field_name="created_at", lookup_expr="date__lte")

    class Meta:
        model = AuditLog
        fields: ClassVar[list[str]] = []