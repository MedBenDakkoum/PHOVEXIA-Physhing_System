from typing import ClassVar

from django.conf import settings
from django.db import models


class Scan(models.Model):
    """Phishing scan model - BR-01 quota, BR-04 status workflow, BR-07 URL validation."""
    
    # Mode: FAST (URL+HTML only) or FULL (all four modalities)
    class Mode(models.TextChoices):
        FAST = "fast"
        FULL = "full"
    
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
    error_message = models.TextField("Error message", null=True, blank=True)
    created_at = models.DateTimeField("Created at", auto_now_add=True)
    updated_at = models.DateTimeField("Updated at", auto_now=True)
    finished_at = models.DateTimeField("Finished at", null=True, blank=True)
    
    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["-created_at", "-id"]),
        ]
    
    def __str__(self):
        return f"Scan {self.id} - {self.domain or self.url}"