"""Step 10 - review workflow serializers (US31, US33-US36, US57).

Every endpoint declares an explicit serializer (OpenAPI contract). Ids are
public UUIDs only: `Report` and `AnalystNote` are addressed through their
scan, and `Notification` exposes its own `public_id`.
"""
from __future__ import annotations

from typing import ClassVar

from rest_framework import serializers

from scans.models import Scan

from .models import AnalystNote, Notification, Report
from .services import DECISION_CONFIRM_PHISHING, DECISION_FALSE_POSITIVE


class ReportCreateSerializer(serializers.Serializer):
    """POST /api/scans/{uuid}/report/ body (US31)."""

    claimed_label = serializers.ChoiceField(choices=Report.ClaimedLabel.choices)
    comment = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class ReportSerializer(serializers.ModelSerializer):
    """Read-only projection of a report (never exposes the integer pk)."""

    scan = serializers.UUIDField(source="scan.public_id", read_only=True)
    reporter_email = serializers.EmailField(
        source="reporter.email", read_only=True, default=None
    )

    class Meta:
        model = Report
        fields: ClassVar[list[str]] = [
            "scan",
            "reporter_email",
            "claimed_label",
            "comment",
            "status",
            "created_at",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class NoteCreateSerializer(serializers.Serializer):
    """POST /api/review/{uuid}/notes/ body (US35)."""

    text = serializers.CharField(required=True, allow_blank=False, max_length=2000)


class NoteSerializer(serializers.ModelSerializer):
    """Read-only projection of an internal note (analyst-only endpoints)."""

    author_email = serializers.EmailField(source="author.email", read_only=True)

    class Meta:
        model = AnalystNote
        fields: ClassVar[list[str]] = ["author_email", "text", "created_at"]
        read_only_fields: ClassVar[list[str]] = list(fields)


class DecisionSerializer(serializers.Serializer):
    """POST /api/review/{uuid}/decision/ body (US34)."""

    decision = serializers.ChoiceField(
        choices=[
            (DECISION_CONFIRM_PHISHING, "Confirmer le phishing"),
            (DECISION_FALSE_POSITIVE, "Faux positif"),
        ]
    )
    comment = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class ReviewQueueItemSerializer(serializers.ModelSerializer):
    """One row of GET /api/review/queue/ (US33).

    `reported` and `claimed_label` come from the subqueries annotated by
    reviews.services.annotate_report_flags (no query per row).
    """

    id = serializers.UUIDField(source="public_id", read_only=True)
    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    reported = serializers.BooleanField(read_only=True)
    claimed_label = serializers.CharField(read_only=True, allow_null=True)

    class Meta:
        model = Scan
        fields: ClassVar[list[str]] = [
            "id",
            "url",
            "domain",
            "mode",
            "status",
            "verdict",
            "score",
            "created_at",
            "finished_at",
            "owner_email",
            "reported",
            "claimed_label",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class ReviewDetailSerializer(ReviewQueueItemSerializer):
    """GET /api/review/{uuid}/ : the scan + its report, notes and decision.

    Analyst-only: the reporter email, the note authors and the reviewing
    analyst are visible here, and ONLY here (the owner-facing scan detail
    never contains them).
    """

    report = serializers.SerializerMethodField()
    notes = NoteSerializer(many=True, read_only=True)
    reviewed_by_email = serializers.EmailField(
        source="reviewed_by.email", read_only=True, default=None
    )
    review_comment = serializers.CharField(read_only=True, allow_blank=True)
    rescan_of = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta(ReviewQueueItemSerializer.Meta):
        fields: ClassVar[list[str]] = list(ReviewQueueItemSerializer.Meta.fields) + [
            "reviewed_by_email",
            "reviewed_at",
            "review_comment",
            "rescan_of",
            "report",
            "notes",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)

    def get_report(self, obj) -> dict | None:
        # reports is prefetched by the view: no extra query per row.
        reports = getattr(obj, "reports", None)
        if reports is None:
            return None
        report = reports.first()
        return ReportSerializer(report).data if report is not None else None


class NotificationSerializer(serializers.ModelSerializer):
    """GET /api/notifications/ item (US57). Id is the public UUID."""

    id = serializers.UUIDField(source="public_id", read_only=True)
    scan = serializers.UUIDField(source="scan.public_id", read_only=True, allow_null=True)

    class Meta:
        model = Notification
        fields: ClassVar[list[str]] = [
            "id",
            "kind",
            "scan",
            "message",
            "read_at",
            "created_at",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class RescanCreatedSerializer(serializers.Serializer):
    """202 body of POST /api/review/{uuid}/rescan/ (US36)."""

    id = serializers.UUIDField()
    status = serializers.CharField(max_length=20)
