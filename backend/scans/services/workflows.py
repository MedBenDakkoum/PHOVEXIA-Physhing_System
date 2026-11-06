from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from django.contrib.auth import get_user_model
from django.utils import timezone

from audit.services import log_status_change

from ..models import Scan

User = get_user_model()


@dataclass(frozen=True)
class Transition:
    """Immutable transition rule: from_status -> allowed_to_statuses.

    `audit_label` is the label written in the audit entry for every
    destination; `audit_labels` overrides it for specific destinations
    (one `from` status can have several moves with different meanings).
    """
    from_status: str
    allowed_to: tuple[str, ...]
    audit_label: str
    audit_labels: Mapping[str, str] = field(default_factory=dict)

    def label_for(self, to_status: str) -> str:
        return self.audit_labels.get(to_status, self.audit_label)


# Fixed transition graph per BR-04: Submitted→Analyzing|Failed; Analyzing→Detected|Failed;
# Detected→Under Review; Under Review→Confirmed|False Positive; Confirmed→Blocked; Failed→Submitted
#
# Step 15 (ISO-6.5): Submitted→Failed was ADDED to the graph. A scan whose
# task never started (queue timeout) cannot stay SUBMITTED forever, and the
# reaper must write that move through change_status like every other one, so
# the graph has to allow it (audit label "queue_timeout").
TRANSITIONS: tuple[Transition, ...] = (
    Transition(
        from_status=Scan.Status.SUBMITTED,
        allowed_to=(Scan.Status.ANALYZING, Scan.Status.FAILED),
        audit_label="scan_started",
        audit_labels={Scan.Status.FAILED: "queue_timeout"},
    ),
    Transition(from_status=Scan.Status.ANALYZING, allowed_to=(Scan.Status.DETECTED, Scan.Status.FAILED), audit_label="analysis_complete"),
    Transition(from_status=Scan.Status.DETECTED, allowed_to=(Scan.Status.UNDER_REVIEW,), audit_label="detected_under_review"),
    Transition(from_status=Scan.Status.UNDER_REVIEW, allowed_to=(Scan.Status.CONFIRMED, Scan.Status.FALSE_POSITIVE), audit_label="review_decided"),
    Transition(from_status=Scan.Status.CONFIRMED, allowed_to=(Scan.Status.BLOCKED,), audit_label="confirmed_blocked"),
    Transition(from_status=Scan.Status.FAILED, allowed_to=(Scan.Status.SUBMITTED,), audit_label="rescan_queued"),
)


def _find_transition(scan: Scan, new_status: str) -> Transition | None:
    """Find the transition rule that applies to the current scan status."""
    for t in TRANSITIONS:
        if t.from_status == scan.status and new_status in t.allowed_to:
            return t
    return None


class InvalidTransition(Exception):
    """Raised when an attempt is made to transition a scan to an invalid status."""


def change_status(scan: Scan, new_status: str, actor: User | None) -> Scan:
    """
    Change the scan status following BR-04 transition rules.

    actor is the user who triggered the change, or None for the SYSTEM
    (Celery worker runs a scan with no human connected - AuditLog.user is
    nullable by design).
    Raises InvalidTransition if the transition is not allowed.
    Writes an audit entry on successful transition.
    """
    transition = _find_transition(scan, new_status)
    if transition is None:
        allowed = ", ".join(
            target
            for t in TRANSITIONS
            if t.from_status == scan.status
            for target in t.allowed_to
        )
        raise InvalidTransition(
            f"Invalid status transition: {scan.status} → {new_status}. "
            f"Allowed: {allowed}"
        )

    # Update the scan status and timestamp (keep old status for the audit entry)
    old_status = scan.status
    scan.status = new_status
    if new_status in (
        Scan.Status.DETECTED,
        Scan.Status.FAILED,
        Scan.Status.CONFIRMED,
        Scan.Status.FALSE_POSITIVE,
        Scan.Status.BLOCKED,
    ):
        scan.finished_at = timezone.now()
    scan.updated_at = timezone.now()
    scan.save(update_fields=["status", "updated_at", "finished_at"])

    # Write audit entry
    log_status_change(scan, transition.label_for(new_status), actor, old_status, new_status)

    # Outbound n8n event: an UNCERTAIN, COMPLETE scan entering the analyst
    # queue (a partial scan stays DETECTED and never reaches this status).
    # Reported scans are emitted by reviews.services.report_scan, so the
    # reason is accurate and there is no duplicate.
    if (
        new_status == Scan.Status.UNDER_REVIEW
        and not scan.partial
        and scan.verdict == "uncertain"
    ):
        from integrations.services import emit_scan_needs_review

        emit_scan_needs_review(scan, reason="uncertain")

    return scan