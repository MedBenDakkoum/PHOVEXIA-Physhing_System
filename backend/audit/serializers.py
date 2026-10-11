from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    action_label = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id", "created_at", "user", "user_email", "action", "action_label",
                  "target_type", "target_id", "target_repr", "ip_address", "metadata"]
        read_only_fields = fields