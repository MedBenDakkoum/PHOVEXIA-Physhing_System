"""Step 10 - human review business logic (US31, US33-US36, US57 / BR-04, BR-05).

Rules enforced here (the views stay thin):
- Every status change goes through the BR-04 transition graph
  (scans.services.workflows.change_status): an invalid transition raises
  InvalidTransition and is never half-applied.
- Every mutation runs in ONE transaction.atomic() block; the scan row is
  locked with select_for_update() so two concurrent reports / decisions
  cannot both win.
- Audit entries always target the Scan (its public UUID is what the audit
  log stores since Step 8a) and carry the human actor plus the request IP
  when the view can provide it. Never the URL, never a note/report body.
"""
from __future__ import annotations

from django.db import IntegrityError, transaction
from django.db.models import Exists, OuterRef, Subquery
from django.utils import timezone

from audit.models import AuditLog
from audit.services import record
from scans.models import Scan
from scans.services.quota import QuotaExceeded, check_quota
from scans.services.url_validation import InvalidURL, validate_url
from scans.services.workflows import change_status
from scans.tasks import enqueue_scan

from .models import AnalystNote, Notification, Report

REPORTABLE_STATUSES = (Scan.Status.DETECTED, Scan.Status.UNDER_REVIEW)

DECISION_CONFIRM_PHISHING = "confirm_phishing"
DECISION_FALSE_POSITIVE = "false_positive"
DECISION_TARGET = {
    DECISION_CONFIRM_PHISHING: Scan.Status.CONFIRMED,
    DECISION_FALSE_POSITIVE: Scan.Status.FALSE_POSITIVE,
}


class AlreadyReported(Exception):
    """BR-05: this scan already has a report."""


class NotReportable(Exception):
    """The scan is not in a status that accepts a report."""


class NotDecidable(Exception):
    """A decision is only possible from UNDER_REVIEW (BR-04)."""


def annotate_report_flags(queryset):
    """Add the report columns every row needs, in two correlated subqueries.

    `has_report` / `report_status`  -> owner-facing scan list and detail
    `reported` / `claimed_label`    -> analyst review queue
    Never one query per row (no N+1).
    """
    reports = Report.objects.filter(scan=OuterRef("pk")).order_by("-created_at")
    return queryset.annotate(
        has_report=Exists(reports),
        reported=Exists(reports),
        report_status=Subquery(reports.values("status")[:1]),
        claimed_label=Subquery(reports.values("claimed_label")[:1]),
    )


def report_scan(
    *,
    scan: Scan,
    reporter,
    claimed_label: str,
    comment: str = "",
    request=None,
) -> Report:
    """US31 / BR-05 - the owner flags a wrong verdict.

    A DETECTED scan moves to UNDER_REVIEW through the BR-04 graph (the
    analyst then decides); a scan already UNDER_REVIEW (uncertain verdict)
    keeps its status. The scan row is locked, so two concurrent reports for
    the same scan cannot both succeed (409 for the loser, and the
    UniqueConstraint is the database backstop).
    """
    with transaction.atomic():
        locked = Scan.objects.select_for_update().get(pk=scan.pk)
        if Report.objects.filter(scan=locked).exists():
            raise AlreadyReported(str(locked.public_id))
        if locked.status not in REPORTABLE_STATUSES:
            raise NotReportable(locked.status)
        if locked.status == Scan.Status.DETECTED:
            change_status(locked, Scan.Status.UNDER_REVIEW, actor=reporter)
        try:
            report = Report.objects.create(
                scan=locked,
                reporter=reporter,
                claimed_label=claimed_label,
                comment=comment,
            )
        except IntegrityError as exc:  # backstop if the lock was bypassed
            raise AlreadyReported(str(locked.public_id)) from exc
        record(
            AuditLog.Action.REPORT_CREATED,
            request=request,
            user=reporter,
            target=locked,
            metadata={"claimed_label": claimed_label},
        )
    return report


def submit_decision(
    *, scan: Scan, analyst, decision: str, comment: str = "", request=None
) -> Scan:
    """US34 - confirm the phishing or declare a false positive (BR-04).

    Only from UNDER_REVIEW. Sets reviewed_by / reviewed_at / review_comment,
    resolves the open report if any and notifies its reporter (US57).
    """
    target_status = DECISION_TARGET[decision]
    with transaction.atomic():
        # No select_related(): owner is nullable and PostgreSQL refuses
        # FOR UPDATE on the nullable side of an outer join (verified on both
        # engines). The decision never needs the owner.
        locked = Scan.objects.select_for_update().get(pk=scan.pk)
        if locked.status != Scan.Status.UNDER_REVIEW:
            raise NotDecidable(locked.status)
        change_status(locked, target_status, actor=analyst)
        locked.reviewed_by = analyst
        locked.reviewed_at = timezone.now()
        locked.review_comment = comment
        locked.save(
            update_fields=["reviewed_by", "reviewed_at", "review_comment", "updated_at"]
        )
        report = (
            Report.objects.select_for_update()
            .filter(scan=locked, status=Report.Status.OPEN)
            .first()
        )
        reporter = None
        if report is not None:
            report.status = Report.Status.RESOLVED
            report.save(update_fields=["status"])
            reporter = report.reporter
        record(
            AuditLog.Action.SCAN_DECIDED,
            request=request,
            user=analyst,
            target=locked,
            metadata={
                "decision": decision,
                "to_status": target_status,
                "had_report": report is not None,
            },
        )
        if reporter is not None:
            Notification.objects.create(
                user=reporter,
                kind=Notification.Kind.REPORT_DECISION,
                scan=locked,
                message=_decision_message(locked, decision),
            )
    return locked


def _decision_message(scan: Scan, decision: str) -> str:
    if decision == DECISION_CONFIRM_PHISHING:
        outcome = "phishing confirmé par un analyste"
    else:
        outcome = "faux positif : le site est considéré comme légitime"
    return f"Votre signalement sur {scan.domain} a été traité : {outcome}."


def add_note(*, scan: Scan, author, text: str, request=None) -> AnalystNote:
    """US35 - an analyst leaves an internal note (never shown to the owner)."""
    with transaction.atomic():
        note = AnalystNote.objects.create(scan=scan, author=author, text=text)
        record(
            AuditLog.Action.NOTE_ADDED,
            request=request,
            user=author,
            target=scan,
            metadata={"note_length": len(text)},
        )
    return note


def rescan_scan(*, scan: Scan, analyst, request=None) -> Scan:
    """US36 - re-run the same URL as a NEW scan owned by the analyst.

    The URL is re-validated with the BR-07 rules (it may have been harmless
    when first seen and private now, or the validator may have improved), the
    new scan is counted in the ANALYST's daily quota (BR-01) and linked to
    the original through `rescan_of`.
    """
    with transaction.atomic():
        validated = validate_url(scan.url)
        check_quota(analyst)
        new_scan = Scan.objects.create(
            owner=analyst,
            url=validated.url,
            domain=validated.host,
            mode=Scan.Mode.FULL,
            status=Scan.Status.SUBMITTED,
            rescan_of=scan,
        )
        record(
            AuditLog.Action.SCAN_RESCANNED,
            request=request,
            user=analyst,
            target=new_scan,
            metadata={"rescan_of": str(scan.public_id)},
        )
        enqueue_scan(new_scan)
    return new_scan


__all__ = [
    "DECISION_CONFIRM_PHISHING",
    "DECISION_FALSE_POSITIVE",
    "AlreadyReported",
    "InvalidURL",
    "NotDecidable",
    "NotReportable",
    "QuotaExceeded",
    "add_note",
    "annotate_report_flags",
    "report_scan",
    "rescan_scan",
    "submit_decision",
]
