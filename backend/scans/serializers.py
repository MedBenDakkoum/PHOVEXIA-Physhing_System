"""Step 7 serializers for the scan API (US12, US14, US16).

Every endpoint declares an explicit serializer so it appears in the OpenAPI
schema (drf-spectacular).

`ScanCreateSerializer` declares ONLY `url`: DRF ignores any other key sent by
the client (mode, status, verdict, score, owner, ...), and the view then sets
them on the server side. The client can therefore never choose them.
"""
from __future__ import annotations

from typing import ClassVar

from rest_framework import serializers

from .models import Scan


class ScanCreateSerializer(serializers.Serializer):
    """POST /api/scans/ body: {"url": "..."} and nothing else."""

    url = serializers.CharField(required=True, allow_blank=True, allow_null=False)


class ScanSerializer(serializers.ModelSerializer):
    """Read-only projection of a scan (list and detail).

    Step 8a: `id` is the public UUID (`public_id`), never the sequential
    integer primary key, which stays internal (ISO-6.6 anti-enumeration).
    """

    id = serializers.UUIDField(source="public_id", read_only=True)

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
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class QuotaSerializer(serializers.Serializer):
    """Quota snapshot (US14): remaining scans for today."""

    limit = serializers.IntegerField()
    used = serializers.IntegerField()
    remaining = serializers.IntegerField()
    reset_at = serializers.DateTimeField()


class ScanCreatedSerializer(serializers.Serializer):
    """202 body of POST /api/scans/: the created scan + the quota after it.

    Step 8a: `id` is the public UUID, matching the detail URL /api/scans/<uuid>/.
    """

    id = serializers.UUIDField()
    url = serializers.CharField(max_length=2048)
    status = serializers.CharField(max_length=20)
    created_at = serializers.DateTimeField()
    quota = QuotaSerializer()


class QuotaExceededSerializer(serializers.Serializer):
    """429 body of POST /api/scans/ (BR-01) + the Retry-After header."""

    detail = serializers.CharField()
    limit = serializers.IntegerField()
    used = serializers.IntegerField()
    reset_at = serializers.DateTimeField()


class ScanErrorSerializer(serializers.Serializer):
    """400 body: machine-readable `code` (RejectionCode) + human `detail`.

    Schema-only: the view builds this dictionary by hand, the serializer is
    never instantiated (the optional `errors` payload is a free-form dict).
    """

    code = serializers.CharField()
    detail = serializers.CharField()
    errors = serializers.DictField(required=False)
