"""Admin control panel serializers (US45, US48, US49, US52, US53, US54).

Every view declares an explicit serializer (OpenAPI contract). Ids are public
UUIDs only: the sequential integer pk never leaves the server (ISO-6.6).
The API key secret appears ONLY in the creation response, once (US54).
"""
from __future__ import annotations

from typing import ClassVar

from rest_framework import serializers

from .models import ApiKey, ModelVersion
from .services.settings import MAX_DAILY_SCAN_QUOTA, MAX_QUICK_CHECK_HOURLY_LIMIT


class AdminErrorSerializer(serializers.Serializer):
    """400/404/409 body: machine-readable `code` + human `detail` (schema only)."""

    code = serializers.CharField()
    detail = serializers.CharField()
    errors = serializers.DictField(required=False)


class DetectionSettingsSerializer(serializers.Serializer):
    """GET /api/admin/settings/ response (values come from the service)."""

    phishing_threshold = serializers.FloatField()
    uncertain_lower = serializers.FloatField()
    daily_scan_quota = serializers.IntegerField()
    quick_check_hourly_limit = serializers.IntegerField()
    updated_at = serializers.DateTimeField(allow_null=True)
    updated_by_email = serializers.EmailField(allow_null=True)


class DetectionSettingsUpdateSerializer(serializers.Serializer):
    """PATCH /api/admin/settings/ body: every field optional (partial).

    Range/cross-field rules (0 < lower < threshold <= 1, quotas >= 1) are
    applied on the MERGED values by services.settings.validate_settings_values.
    """

    phishing_threshold = serializers.FloatField(required=False, min_value=0.0, max_value=1.0)
    uncertain_lower = serializers.FloatField(required=False, min_value=0.0, max_value=1.0)
    daily_scan_quota = serializers.IntegerField(
        required=False, min_value=1, max_value=MAX_DAILY_SCAN_QUOTA
    )
    quick_check_hourly_limit = serializers.IntegerField(
        required=False, min_value=1, max_value=MAX_QUICK_CHECK_HOURLY_LIMIT
    )


class ModelVersionSerializer(serializers.ModelSerializer):
    """Read-only projection of a model version (id = public UUID)."""

    id = serializers.UUIDField(source="public_id", read_only=True)
    created_by_email = serializers.EmailField(
        source="created_by.email", read_only=True, allow_null=True, default=None
    )

    class Meta:
        model = ModelVersion
        fields: ClassVar[list[str]] = [
            "id",
            "name",
            "version",
            "kind",
            "file_path",
            "sha256",
            "metrics",
            "notes",
            "is_active",
            "created_by_email",
            "created_at",
            "activated_at",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


_NUMERIC_METRICS = (
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "latency_ms",
    "test_set_size",
)


class ModelVersionCreateSerializer(serializers.Serializer):
    """POST /api/admin/models/ body (metadata only, no file upload)."""

    name = serializers.CharField(required=True, allow_blank=False, max_length=100)
    version = serializers.CharField(required=True, allow_blank=False, max_length=50)
    kind = serializers.ChoiceField(choices=ModelVersion.Kind.choices)
    file_path = serializers.CharField(
        required=False, allow_blank=True, max_length=500, default=""
    )
    metrics = serializers.DictField(required=False, default=dict)
    notes = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate_metrics(self, value: dict) -> dict:
        for key, item in value.items():
            if key in _NUMERIC_METRICS:
                if isinstance(item, bool) or not isinstance(item, (int, float)):
                    raise serializers.ValidationError(
                        f"« {key} » doit être un nombre."
                    )
            elif key == "dataset":
                if not isinstance(item, str):
                    raise serializers.ValidationError(
                        "« dataset » doit être une chaîne."
                    )
            elif item is not None and isinstance(item, (dict, list)):
                raise serializers.ValidationError(
                    f"« {key} » doit être une valeur simple."
                )
        return value


class ModelCompareSerializer(serializers.Serializer):
    """GET /api/admin/models/compare/ response: side-by-side metrics + deltas."""

    baseline_id = serializers.UUIDField()
    models = serializers.ListField(child=serializers.DictField())
    metrics = serializers.ListField(child=serializers.DictField())


class DashboardSerializer(serializers.Serializer):
    """GET /api/admin/dashboard/ response (US45). Nested breakdowns are
    JSON dicts keyed by status/verdict/domain, so they stay schema-light."""

    period = serializers.DictField()
    totals = serializers.DictField()
    quick_checks = serializers.IntegerField()
    scans_by_verdict = serializers.DictField()
    scans_by_status = serializers.DictField()
    scans_by_detection_source = serializers.DictField()
    phishing_rate = serializers.FloatField(allow_null=True)
    false_positive_rate = serializers.FloatField(allow_null=True)
    pending_reviews = serializers.IntegerField()
    median_scan_duration_seconds = serializers.FloatField(allow_null=True)
    scans_per_day = serializers.ListField(child=serializers.DictField())
    top_phishing_domains = serializers.ListField(child=serializers.DictField())
    users_by_role = serializers.DictField()
    median_sample_size = serializers.IntegerField()


class HealthCheckSerializer(serializers.Serializer):
    """One health check: ok + short message + optional machine value."""

    ok = serializers.BooleanField()
    message = serializers.CharField()
    value = serializers.JSONField(allow_null=True)


class AdminHealthSerializer(serializers.Serializer):
    """GET /api/admin/health/ response (never fails: every check is reported)."""

    # CharField on purpose (not a ChoiceField): "ok"/"degraded" must not
    # collide with the Scan/Report `status` enums in the OpenAPI schema.
    status = serializers.CharField()
    checked_at = serializers.CharField()
    checks = serializers.DictField(child=HealthCheckSerializer())


class PublicHealthSerializer(serializers.Serializer):
    """GET /api/health/ response: public, minimal, no details (US53)."""

    status = serializers.CharField()


class ApiKeySerializer(serializers.ModelSerializer):
    """Read-only projection - NEVER contains the secret or the hash (US54)."""

    id = serializers.UUIDField(source="public_id", read_only=True)
    owner_email = serializers.EmailField(source="owner.email", read_only=True)

    class Meta:
        model = ApiKey
        fields: ClassVar[list[str]] = [
            "id",
            "name",
            "owner_email",
            "key_prefix",
            "scopes",
            "is_active",
            "expires_at",
            "last_used_at",
            "created_at",
            "revoked_at",
        ]
        read_only_fields: ClassVar[list[str]] = list(fields)


class ApiKeyCreateSerializer(serializers.Serializer):
    """POST /api/admin/api-keys/ body."""

    name = serializers.CharField(required=True, allow_blank=False, max_length=100)
    scopes = serializers.MultipleChoiceField(
        choices=ApiKey.Scope.choices, required=True, allow_empty=False
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)


class ApiKeyCreatedSerializer(ApiKeySerializer):
    """Creation response: the standard fields PLUS the secret, shown ONCE.

    Must be fed the MODEL INSTANCE (not a dict): `id` and `owner_email` use
    custom `source` paths that a plain dict does not satisfy. The secret only
    exists here, passed through the context by the view.
    """

    secret = serializers.SerializerMethodField()

    class Meta(ApiKeySerializer.Meta):
        fields: ClassVar[list[str]] = [*ApiKeySerializer.Meta.fields, "secret"]

    def get_secret(self, obj) -> str:
        return self.context.get("secret", "")
