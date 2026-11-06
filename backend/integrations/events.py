"""Event types understood by the n8n integration (fixed, never user supplied).

Each event type maps to a FIXED path appended to the configured base URL:
``{N8N_WEBHOOK_BASE_URL}/webhook/<path>``. The host always comes from
configuration; no request field, scan field or payload key can change it.
"""
from __future__ import annotations

SCAN_CONFIRMED = "scan.confirmed"
SCAN_NEEDS_REVIEW = "scan.needs_review"
TEST_EVENT = "test.event"

EVENT_PATHS: dict[str, str] = {
    SCAN_CONFIRMED: "scan-confirmed",
    SCAN_NEEDS_REVIEW: "scan-needs-review",
    TEST_EVENT: "test-event",
}
