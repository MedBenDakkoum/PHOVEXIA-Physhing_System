"""Admin control panel models (US45, US48, US49, US52, US54 / BR-11).

- DetectionSettings: SINGLETON (the service always reads/writes pk=1). When
  no row exists yet, get_detection_settings() falls back to the Django
  settings values, so a fresh install behaves exactly like before.
- ModelVersion: one row per registered version. BR-11 = a conditional
  UniqueConstraint keeps at most ONE active version.
- ApiKey: only the SHA-256 hash of the secret is stored; the secret itself
  is shown once at creation and never persisted (US54).
"""
from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models


class DetectionSettings(models.Model):
    """Singleton detection thresholds + quotas (US52).

    Row pk is always 1 (enforced by controlpanel.services.settings). The
    model does not enforce the ranges itself: validation lives in the
    serializer/service so the API can return precise 400 messages, and the
    defaults mirror config/settings.py.
    """

    phishing_threshold = models.FloatField("Phishing threshold", default=0.70)
    uncertain_lower = models.FloatField("Uncertain lower bound", default=0.40)
    daily_scan_quota = models.PositiveIntegerField("Daily scan quota", default=20)
    quick_check_hourly_limit = models.PositiveIntegerField(
        "Quick checks per hour per IP", default=5
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="detection_settings_updates",
    )
    updated_at = models.DateTimeField("Updated at", auto_now=True)

    class Meta:
        verbose_name = "Detection settings"

    def __str__(self) -> str:
        return (
            f"Detection settings (threshold={self.phishing_threshold}, "
            f"quota={self.daily_scan_quota})"
        )


class ModelVersion(models.Model):
    """A registered model version (US48 / US49 / BR-11)."""

    class Kind(models.TextChoices):
        MOCK = "MOCK", "Mock"
        ONNX = "ONNX", "ONNX"
        # US20 / US26: the verified torch bundle served by the inference
        # service (registered via sync_model_version, activated by an admin).
        TORCH_BUNDLE = "TORCH_BUNDLE", "Torch bundle"

    public_id = models.UUIDField(
        "Public ID", default=uuid.uuid4, unique=True, editable=False
    )
    name = models.CharField("Name", max_length=100)
    version = models.CharField("Version", max_length=50)
    kind = models.CharField("Kind", max_length=20, choices=Kind.choices)
    # Relative to settings.MODELS_DIR; validated against path traversal at
    # registration (and re-checked at activation).
    file_path = models.CharField("File path", max_length=500, blank=True, default="")
    # SHA-256 of the file, computed when the file exists, verified at activation.
    sha256 = models.CharField("SHA-256", max_length=64, blank=True, default="")
    # precision, recall, f1, false_positive_rate, latency_ms, test_set_size, dataset
    metrics = models.JSONField("Metrics", default=dict, blank=True)
    notes = models.TextField("Notes", blank=True, default="")
    is_active = models.BooleanField("Active", default=False, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="model_versions_created",
    )
    created_at = models.DateTimeField("Created at", auto_now_add=True)
    activated_at = models.DateTimeField("Activated at", null=True, blank=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]
        constraints: ClassVar[list[models.UniqueConstraint]] = [
            # BR-11: at most ONE active version at any time.
            models.UniqueConstraint(
                fields=["is_active"],
                condition=models.Q(is_active=True),
                name="modelversion_one_active",
            ),
            # A (name, version) pair identifies a version.
            models.UniqueConstraint(
                fields=["name", "version"],
                name="modelversion_name_version_unique",
            ),
        ]

    def __str__(self) -> str:
        state = "active" if self.is_active else "inactive"
        return f"{self.name} {self.version} ({self.kind}, {state})"


class ApiKey(models.Model):
    """An API key for machine clients (US54).

    The secret (token_urlsafe(32)) is stored ONLY as its SHA-256 hash plus
    the first 8 characters (prefix) used to narrow the lookup before a
    constant-time compare.
    """

    class Scope(models.TextChoices):
        SCAN_CREATE = "scan:create", "Create scans"
        SCAN_READ = "scan:read", "Read scans"

    public_id = models.UUIDField(
        "Public ID", default=uuid.uuid4, unique=True, editable=False
    )
    name = models.CharField("Name", max_length=100)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    key_prefix = models.CharField("Key prefix", max_length=8)
    key_hash = models.CharField("Key hash", max_length=64, unique=True)
    scopes = models.JSONField("Scopes", default=list, blank=True)
    is_active = models.BooleanField("Active", default=True, db_index=True)
    expires_at = models.DateTimeField("Expires at", null=True, blank=True)
    last_used_at = models.DateTimeField("Last used at", null=True, blank=True)
    created_at = models.DateTimeField("Created at", auto_now_add=True)
    revoked_at = models.DateTimeField("Revoked at", null=True, blank=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]

    def __str__(self) -> str:
        state = "active" if self.is_active and self.revoked_at is None else "revoked"
        return f"{self.name} ({self.key_prefix}..., {state})"
