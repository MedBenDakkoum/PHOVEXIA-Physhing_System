from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination

from accounts.permissions import IsAdminRole

from .filters import AuditLogFilter
from .models import AuditLog
from .serializers import AuditLogSerializer


class AuditPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Journal d'audit : lecture seule, paginé, filtrable, réservé à l'administrateur."""
    queryset = AuditLog.objects.select_related("user")
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminRole]
    pagination_class = AuditPagination
    filter_backends = [DjangoFilterBackend]
    filterset_class = AuditLogFilter