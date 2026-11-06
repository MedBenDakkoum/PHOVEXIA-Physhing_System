"""Send one harmless integration event (manual verification with n8n).

Usage (from backend/):
    python manage.py send_test_event test.event
    python manage.py send_test_event scan.confirmed

The event carries no real scan and no personal data. When
N8N_WEBHOOK_BASE_URL is empty the feature is disabled and nothing is sent.
"""
from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from integrations.events import EVENT_PATHS
from integrations.services import emit_event, is_enabled

TEST_PAYLOAD = {
    "message": "Harmless test event emitted by manage.py send_test_event",
    "origin": "management_command",
}


class Command(BaseCommand):
    help = (
        "Emit a harmless integration event (test.event, scan.confirmed or "
        "scan.needs_review) to the configured n8n webhook."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "type",
            choices=sorted(EVENT_PATHS),
            help="Event type to emit.",
        )

    def handle(self, *args, **options):
        event_type = options["type"]
        if not is_enabled():
            self.stdout.write(
                self.style.WARNING(
                    "N8N_WEBHOOK_BASE_URL is empty: feature disabled, nothing sent."
                )
            )
            return
        if not settings.N8N_WEBHOOK_SECRET:
            raise CommandError(
                "N8N_WEBHOOK_SECRET is required when N8N_WEBHOOK_BASE_URL is set."
            )
        event_id = emit_event(event_type, dict(TEST_PAYLOAD))
        self.stdout.write(
            self.style.SUCCESS(f"event queued id={event_id} type={event_type}")
        )
