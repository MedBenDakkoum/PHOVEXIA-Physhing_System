"""Step 10 - human review workflow models (US31, US33-US36, US57 / BR-05).

Report       a scan owner flags a wrong verdict (US31). ONE report per scan
             forever (BR-05): enforced by a database UniqueConstraint on
             `scan`, plus a row lock in reviews.services.report_scan.
AnalystNote  internal note written by an analyst on a scan (US35). NEVER
             exposed to the scan owner (analyst-only endpoints).
Notification message for the reporter when a decision lands on his report
             (US57). Own-only, `read_at` nullable = unread.

Every public identifier exposed by the API is a UUID (Step 8a rule):
Notification carries its own `public_id`, the two other models are only ever
addressed through their scan's public UUID.
"""
import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models
from django.db.models import F


class Report(models.Model):
    """US31 - the owner claims the verdict of his scan is wrong."""

    class ClaimedLabel(models.TextChoices):
        SAFE = "safe", "Légitime"
        PHISHING = "phishing", "Phishing"

    class Status(models.TextChoices):
        OPEN = "open", "Ouvert"
        RESOLVED = "resolved", "Traité"

    scan = models.ForeignKey(
        "scans.Scan", on_delete=models.CASCADE, related_name="reports"
    )
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reports"
    )
    claimed_label = models.CharField(max_length=10, choices=ClaimedLabel.choices)
    comment = models.CharField(max_length=1000, blank=True)
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.OPEN
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]
        constraints: ClassVar[list[models.Constraint]] = [
            # BR-05: a scan can be reported only once.
            models.UniqueConstraint(fields=["scan"], name="report_one_per_scan"),
        ]

    def __str__(self):
        return f"Report({self.claimed_label}) on Scan {self.scan_id}"


class AnalystNote(models.Model):
    """US35 - internal note, analyst-only visibility."""

    scan = models.ForeignKey(
        "scans.Scan", on_delete=models.CASCADE, related_name="notes"
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="analyst_notes"
    )
    text = models.CharField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["created_at", "id"]

    def __str__(self):
        return f"Note on Scan {self.scan_id} by {self.author_id}"


class Notification(models.Model):
    """US57 - "your report has been decided", unread until read_at is set."""

    class Kind(models.TextChoices):
        REPORT_DECISION = "report_decision", "Décision sur un signalement"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications"
    )
    kind = models.CharField(max_length=30, choices=Kind.choices)
    scan = models.ForeignKey(
        "scans.Scan",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="notifications",
    )
    message = models.CharField(max_length=255)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Unread first, then newest. `nulls_first=True` is REQUIRED for
        # portability: PostgreSQL sorts NULLs LAST in ASC by default while
        # SQLite sorts them first, so the bare (read_at, -created_at) pair
        # gave the opposite order on the two engines (verified by the test
        # suite run on both).
        ordering: ClassVar[list] = [F("read_at").asc(nulls_first=True), "-created_at"]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "read_at"], name="notif_user_unread_idx"),
        ]

    def __str__(self):
        return f"Notification({self.kind}) for user {self.user_id}"
