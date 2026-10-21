"""Blocklist and protected-brands serializers (US38-US40, US55).

Every view declares an explicit serializer (OpenAPI contract). Ids are public
UUIDs only: the sequential integer pk never leaves the server (ISO-6.6).
"""
from __future__ import annotations

from typing import ClassVar

from rest_framework import serializers

from .models import BlocklistEntry, ProtectedBrand


class BlocklistEntrySerializer(serializers.ModelSerializer):
    """Read-only projection of one blocklist entry (id = public UUID)."""

    id = serializers.UUIDField(source="public_id", read_only=True)
    added_by_email = serializers.EmailField(
        source="added_by.email", read_only=True, default=None
    )
    removed_by_email = serializers.EmailField(
        source="removed_by.email", read_only=True, default=None
    )
    source_scan = serializers.UUIDField(
        source="source_scan.public_id", read_only=True, allow_null=True, default=None
    )

    class Meta:
        model = BlocklistEntry
        fields: ClassVar[list[str]] = [
            "id",
            "domain",
            "reason",
            "note",
            "added_by_email",
            "source_scan",
            "created_at",
            "is_active",
            "removed_by_email",
            "removed_at",
            "removal_reason",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class BlocklistCreateSerializer(serializers.Serializer):
    """POST /api/blocklist/ body: domain + reason (+ optional note / source_scan)."""

    domain = serializers.CharField(required=True, allow_blank=False, max_length=254)
    reason = serializers.ChoiceField(choices=BlocklistEntry.Reason.choices)
    note = serializers.CharField(required=False, allow_blank=True, max_length=1000)
    source_scan = serializers.UUIDField(required=False, allow_null=True, default=None)


class BlocklistRemoveSerializer(serializers.Serializer):
    """DELETE /api/blocklist/{uuid}/ body (BR-12: reason is REQUIRED)."""

    reason = serializers.CharField(required=True, allow_blank=False, max_length=1000)


class ProtectedBrandSerializer(serializers.ModelSerializer):
    """Read-only projection of a protected brand (id = public UUID)."""

    id = serializers.UUIDField(source="public_id", read_only=True)
    created_by_email = serializers.EmailField(
        source="created_by.email", read_only=True, default=None
    )

    class Meta:
        model = ProtectedBrand
        fields: ClassVar[list[str]] = [
            "id",
            "name",
            "domain",
            "is_active",
            "created_by_email",
            "created_at",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class ProtectedBrandCreateSerializer(serializers.Serializer):
    """POST /api/brands/ body: name + domain (+ optional is_active)."""

    name = serializers.CharField(required=True, allow_blank=False, max_length=100)
    domain = serializers.CharField(required=True, allow_blank=False, max_length=254)
    is_active = serializers.BooleanField(required=False, default=True)


class ProtectedBrandPatchSerializer(serializers.Serializer):
    """PATCH /api/brands/{uuid}/ body: every field optional."""

    name = serializers.CharField(required=False, allow_blank=False, max_length=100)
    domain = serializers.CharField(required=False, allow_blank=False, max_length=254)
    is_active = serializers.BooleanField(required=False)


class BlocklistErrorSerializer(serializers.Serializer):
    """400/409 body: machine-readable `code` + human `detail` (schema only)."""

    code = serializers.CharField()
    detail = serializers.CharField()
