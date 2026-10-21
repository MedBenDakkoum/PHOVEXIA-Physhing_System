"""Blocklist and protected brands models (US38-US41, US55 / BR-03, BR-12).

`BlocklistEntry` is soft-deleted: the row keeps its history (who removed it,
when and why) while `is_active` drives every check. BR-03 is enforced by a
conditional UniqueConstraint so only ONE active entry can exist per domain,
while removed entries stay in the table for audit purposes.
"""
from __future__ import annotations

import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models


class BlocklistEntry(models.Model):
    """One blocked domain (US38 / US39 / US41)."""

    class Reason(models.TextChoices):
        CONFIRMED_PHISHING = "confirmed_phishing", "Confirmed phishing"
        CAMPAIGN = "campaign", "Campaign"
        MANUAL = "manual", "Manual"

    public_id = models.UUIDField(
        "Public ID", default=uuid.uuid4, unique=True, editable=False
    )
    domain = models.CharField("Domain", max_length=254)
    reason = models.CharField(
        "Reason", max_length=20, choices=Reason.choices, default=Reason.MANUAL
    )
    note = models.TextField("Note", blank=True, default="")
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="blocklist_entries_added",
    )
    source_scan = models.ForeignKey(
        "scans.Scan",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="blocklist_entries",
    )
    created_at = models.DateTimeField("Created at", auto_now_add=True, db_index=True)
    # Soft delete (US39 / BR-12): the row is kept, only deactivated.
    is_active = models.BooleanField("Active", default=True, db_index=True)
    removed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="blocklist_entries_removed",
    )
    removed_at = models.DateTimeField("Removed at", null=True, blank=True)
    removal_reason = models.CharField("Removal reason", max_length=1000, blank=True, default="")

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at"]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["domain"], name="blocklist_domain_idx"),
        ]
        constraints: ClassVar[list[models.UniqueConstraint]] = [
            # BR-03: a domain can appear only once among the ACTIVE entries.
            models.UniqueConstraint(
                fields=["domain"],
                condition=models.Q(is_active=True),
                name="blocklist_one_active_per_domain",
            ),
        ]

    def __str__(self) -> str:
        state = "active" if self.is_active else "removed"
        return f"{self.domain} ({self.reason}, {state})"


class ProtectedBrand(models.Model):
    """A protected brand for the lookalike check (US19 / US55)."""

    public_id = models.UUIDField(
        "Public ID", default=uuid.uuid4, unique=True, editable=False
    )
    name = models.CharField("Name", max_length=100)
    domain = models.CharField("Domain", max_length=254, unique=True)
    is_active = models.BooleanField("Active", default=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="protected_brands_created",
    )
    created_at = models.DateTimeField("Created at", auto_now_add=True)

    class Meta:
        ordering: ClassVar[list[str]] = ["name"]

    def __str__(self) -> str:
        return f"{self.name} <{self.domain}>"
