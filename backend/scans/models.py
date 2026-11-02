import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models

# Shared by `verdict` and `model_verdict` (US19). Declared once so OpenAPI gets
# ONE stable enum name instead of an ambiguous collision.
VERDICT_CHOICES = (
    ("phishing", "Phishing"),
    ("legitimate", "Legitimate"),
    ("uncertain", "Uncertain"),
)


class Scan(models.Model):
    """Phishing scan model - BR-01 quota, BR-04 status workflow, BR-07 URL validation."""
    
    # Mode: FAST (URL+HTML only) or FULL (all four modalities)
    class Mode(models.TextChoices):
        FAST = "fast"
        FULL = "full"

    # Step 11 (US41): where the verdict came from. BLOCKLIST = the domain was
    # already actively blocked, so no model ran and no task was queued.
    # BRAND_POLICY = a transparent non-DL brand rule adjusted the final verdict
    # (the raw model output is kept in model_verdict/model_score).
    class DetectionSource(models.TextChoices):
        MODEL = "model", "Model"
        BLOCKLIST = "blocklist", "Blocklist"
        BRAND_POLICY = "brand_policy", "Brand policy"
        # Demo environment (docs/DEMO_RUNBOOK.md): the verdict was produced by
        # load_demo_samples from the stored golden-sample inputs (Phish360
        # test split). The page was NEVER visited: no collector ran.
        DATASET_SAMPLE = "dataset_sample", "Dataset sample"

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
        "Verdict", max_length=20, choices=VERDICT_CHOICES, null=True, blank=True
    )
    score = models.FloatField("Score", null=True, blank=True)
    # Brand policy (US19): the model output is NEVER erased. `model_verdict`
    # and `model_score` keep the raw prediction while `verdict`/`score` hold
    # the FINAL decision (possibly adjusted by a transparent brand rule).
    # `policy_flags` is a JSON list of machine-readable flags, `policy_note` a
    # short French explanation for the UI. Empty when no rule applied.
    model_verdict = models.CharField(
        "Model verdict",
        max_length=20,
        choices=VERDICT_CHOICES,
        null=True,
        blank=True,
    )
    model_score = models.FloatField("Model score", null=True, blank=True)
    policy_flags = models.JSONField("Policy flags", default=list, blank=True)
    policy_note = models.TextField("Policy note", blank=True, default="")
    detection_source = models.CharField(
        "Detection source",
        max_length=20,
        choices=DetectionSource.choices,
        default=DetectionSource.MODEL,
    )
    # Step 12 (US48): label of the ModelVersion that produced the verdict
    # (filled at prediction time from the active version). Empty for
    # blocklist verdicts (no model ran) and for scans not yet predicted.
    model_version = models.CharField("Model version", max_length=50, blank=True, default="")
    # US17/US20: version of the verified model bundle that ran (from inference
    # /health), distinct from the ModelVersion label. Empty for MOCK/blocklist.
    model_bundle_version = models.CharField(
        "Model bundle version", max_length=100, blank=True, default=""
    )
    error_message = models.TextField("Error message", null=True, blank=True)
    # US17: the URL the collector actually reached (after redirects), the
    # captured signals and the per-modality probabilities. Raw HTML and text
    # are deliberately NOT stored.
    final_url = models.URLField("Final URL", max_length=2048, blank=True, default="")
    signals = models.JSONField("Captured signals", default=dict, blank=True)
    probabilities = models.JSONField(
        "Per-modality probabilities", default=dict, blank=True
    )
    partial = models.BooleanField("Partial result", default=False)
    reason_code = models.CharField("Reason code", max_length=64, blank=True, default="")
    # ISO-6.5: number of the current/last attempt (0 = first run). Retries are
    # scheduled by the task with a countdown; this counter makes a duplicate
    # delivery of attempt N a no-op instead of a parallel run.
    retry_count = models.PositiveSmallIntegerField("Retry count", default=0)
    # US20: relative path under MEDIA_ROOT (screenshots/<public_id>.png), or
    # empty when none was captured or it failed validation.
    screenshot_path = models.CharField(
        "Screenshot path", max_length=500, blank=True, default=""
    )
    collected_at = models.DateTimeField("Collected at", null=True, blank=True)
    # Demo (docs/DEMO_RUNBOOK.md): id of the golden sample that produced this
    # row ("" for every real scan). Makes load_demo_samples idempotent and is
    # never exposed as an identifier to clients.
    demo_sample_id = models.CharField(
        "Demo sample ID", max_length=64, blank=True, default="", db_index=True
    )
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