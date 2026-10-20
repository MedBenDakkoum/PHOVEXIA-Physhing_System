from django.urls import path

from .views import (
    NotificationListView,
    NotificationReadView,
    ReportCreateView,
    ReviewDecisionView,
    ReviewDetailView,
    ReviewNoteView,
    ReviewQueueView,
    ReviewRescanView,
)

urlpatterns = [
    # US31 / BR-05: the report endpoint hangs under the scan it belongs to and
    # is scoped to the owner inside the view (a foreign scan = 404).
    path(
        "scans/<uuid:public_id>/report/",
        ReportCreateView.as_view(),
        name="scan-report",
    ),
    # Before <uuid:public_id>/ (same reason as scans/quota/): the literal
    # "queue" must never be parsed as a scan UUID.
    path("review/queue/", ReviewQueueView.as_view(), name="review-queue"),
    path(
        "review/<uuid:public_id>/",
        ReviewDetailView.as_view(),
        name="review-detail",
    ),
    path(
        "review/<uuid:public_id>/decision/",
        ReviewDecisionView.as_view(),
        name="review-decision",
    ),
    path(
        "review/<uuid:public_id>/notes/",
        ReviewNoteView.as_view(),
        name="review-note",
    ),
    path(
        "review/<uuid:public_id>/rescan/",
        ReviewRescanView.as_view(),
        name="review-rescan",
    ),
    # US57: own notifications, public UUID for the read endpoint.
    path("notifications/", NotificationListView.as_view(), name="notification-list"),
    path(
        "notifications/<uuid:public_id>/read/",
        NotificationReadView.as_view(),
        name="notification-read",
    ),
]
