import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models


class Scan(models.Model):
    """Phishing scan model - BR-01 quota, BR-04 status workflow, BR-07 URL validation."""
    
    # Mode: FAST (URL+HTML only) or FULL (all four modalities)
    class Mode(models.TextChoices):
        FAST = "fast"
        FULL = "full"

    # Step 11 (US41): where the verdict came from. BLOCKLIST = the domain was
    # already actively blocked, so no model ran and no task was queued.
    class DetectionSource(models.TextChoices):
        MODEL = "model", "Model"
        BLOCKLIST = "blocklist", "Blocklist"

    # Statuses: Submitted -> Analyzing -> Detected/Failed -> Under Review/False Positive -> Confirmed/Blocked
    class Status(models.TextChoices):
        SUBMITTED = "submitted"
        ANALYZING = "analyzing"
        DETECTED = "detected"
        UNDER_REVIEW = "under_review"
        CONFIRMED = "confirmed"
        FALSE_POSITIVE = "false_positive"
        BLOCKED = "blocked"
        FAILED = "failed"
    
    # Class-level manager for default queries
    objects = models.Manager()
    
    # Fields
    id = models.BigAutoField(primary_key=True)
    # Public identifier exposed by the API: a UUID is not enumerable, unlike
    # the sequential integer primary key which stays internal (US30 / ISO-6.6).
    public_id = models.UUIDField(
        "Public ID", default=uuid.uuid4, unique=True, editable=False
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name="scans",
    )
    url = models.URLField("URL", max_length=2048)
    domain = models.CharField("Domain", max_length=254, blank=True)
    mode = models.CharField("Mode", max_length=10, choices=Mode.choices, default=Mode.FAST)
    status = models.CharField(
        "Status", max_length=20, choices=Status.choices, default=Status.SUBMITTED
    )
    verdict = models.CharField(
        "Verdict", max_length=20, choices=[
            ("phishing", "Phishing"),
            ("legitimate", "Legitimate"),
            ("uncertain", "Uncertain"),
        ], null=True, blank=True
    )
    score = models.FloatField("Score", null=True, blank=True)
    detection_source = models.CharField(
        "Detection source",
        max_length=10,
        choices=DetectionSource.choices,
        default=DetectionSource.MODEL,
    )
    error_message = models.TextField("Error message", null=True, blank=True)
    # Step 10 (US34 / BR-04): human review outcome. Owner-facing data never
    # includes the analyst identity, only the decision itself (ISO-6.6).
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_scans",
    )
    reviewed_at = models.DateTimeField("Reviewed at", null=True, blank=True)
    review_comment = models.CharField(
        "Review comment", max_length=1000, blank=True, default=""
    )
    # Step 10 (US36): a rescan is a NEW scan linked to the original one.
    rescan_of = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rescans",
    )
    created_at = models.DateTimeField("Created at", auto_now_add=True)
    updated_at = models.DateTimeField("Updated at", auto_now=True)
    finished_at = models.DateTimeField("Finished at", null=True, blank=True)
    
    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["-created_at", "-id"]),
            # Step 8b (US29): history = owner scope + newest first, and the
            # verdict filter. The date range reuses the -created_at index.
            # The `q` filter uses icontains on url/domain, which no btree
            # index can serve (documented in docs/HANDOFF.md).
            models.Index(
                fields=["owner", "-created_at"],
                name="scans_scan_owner_created_idx",
            ),
            models.Index(fields=["verdict"], name="scans_scan_verdict_idx"),
        ]
    
    def __str__(self):
        return f"Scan {self.public_id} - {self.domain or self.url}"