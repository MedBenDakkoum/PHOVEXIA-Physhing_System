"""
Workflow tests for scans/services/workflows.py — BR-04 (scan status transition graph).

The oracle below (EXPECTED_GRAPH, EXPECTED_AUDIT_LABEL) is written from
docs/PROJECT_CONTEXT.md section 6, NOT imported from the code, so a bad edit
of TRANSITIONS cannot make these tests pass.
"""
import pytest

from audit.models import AuditLog
from scans.models import Scan
from scans.services.workflows import InvalidTransition, change_status

pytestmark = pytest.mark.django_db

ALL_STATUSES = tuple(status.value for status in Scan.Status)

# BR-04 oracle: from_status -> allowed to_statuses
EXPECTED_GRAPH = {
    "submitted": ("analyzing",),
    "analyzing": ("detected", "failed"),
    "detected": ("under_review",),
    "under_review": ("confirmed", "false_positive"),
    "confirmed": ("blocked",),
    "failed": ("submitted",),
    "false_positive": (),
    "blocked": (),
}

# BR-04 oracle: audit label expected for each allowed move
EXPECTED_AUDIT_LABEL = {
    ("submitted", "analyzing"): "scan_started",
    ("analyzing", "detected"): "analysis_complete",
    ("analyzing", "failed"): "analysis_complete",
    ("detected", "under_review"): "detected_under_review",
    ("under_review", "confirmed"): "review_decided",
    ("under_review", "false_positive"): "review_decided",
    ("confirmed", "blocked"): "confirmed_blocked",
    ("failed", "submitted"): "rescan_queued",
}

# Statuses where finished_at must be stamped
FINISHED_STATUSES = {"detected", "failed", "confirmed", "false_positive", "blocked"}

VALID_PAIRS = [(frm, to) for frm, targets in EXPECTED_GRAPH.items() for to in targets]
INVALID_PAIRS = [
    (frm, to)
    for frm in ALL_STATUSES
    for to in ALL_STATUSES
    if to not in EXPECTED_GRAPH[frm]
]


def make_scan(status, owner):
    return Scan.objects.create(
        owner=owner,
        url="https://example.com/login",
        domain="example.com",
        status=status,
    )


@pytest.mark.parametrize(
    "from_status,to_status",
    VALID_PAIRS,
    ids=[f"{frm}_to_{to}" for frm, to in VALID_PAIRS],
)
def test_valid_transition_applies_new_status(make_user, from_status, to_status):
    """BR-04: every allowed transition updates status and stamps finished_at."""
    actor = make_user()
    scan = make_scan(from_status, actor)

    result = change_status(scan, to_status, actor)

    scan.refresh_from_db()
    assert result.status == to_status
    assert scan.status == to_status
    if to_status in FINISHED_STATUSES:
        assert scan.finished_at is not None
    else:
        assert scan.finished_at is None


@pytest.mark.parametrize(
    "from_status,to_status",
    VALID_PAIRS,
    ids=[f"{frm}_to_{to}" for frm, to in VALID_PAIRS],
)
def test_valid_transition_writes_audit_entry(make_user, from_status, to_status):
    """BR-04 + US46: exactly one audit entry with the real from/to statuses."""
    actor = make_user()
    scan = make_scan(from_status, actor)
    before = AuditLog.objects.count()

    change_status(scan, to_status, actor)

    assert AuditLog.objects.count() == before + 1
    entry = AuditLog.objects.get(target_type="scan", target_id=str(scan.public_id))
    assert entry.action == AuditLog.Action.SCAN_STATUS_CHANGED
    assert entry.user_id == actor.pk
    assert entry.metadata["from_status"] == from_status
    assert entry.metadata["to_status"] == to_status
    assert entry.metadata["transition"] == EXPECTED_AUDIT_LABEL[(from_status, to_status)]


@pytest.mark.parametrize(
    "from_status,to_status",
    INVALID_PAIRS,
    ids=[f"{frm}_to_{to}" for frm, to in INVALID_PAIRS],
)
def test_invalid_transition_refused(make_user, from_status, to_status):
    """BR-04: forbidden move raises InvalidTransition, keeps status, writes no audit."""
    actor = make_user()
    scan = make_scan(from_status, actor)
    before = AuditLog.objects.count()

    with pytest.raises(InvalidTransition):
        change_status(scan, to_status, actor)

    scan.refresh_from_db()
    assert scan.status == from_status
    assert scan.finished_at is None
    assert AuditLog.objects.count() == before


def test_invalid_transition_message_lists_allowed_targets(make_user):
    """BR-04: the refusal message shows the current status and allowed targets."""
    actor = make_user()
    scan = make_scan("submitted", actor)

    with pytest.raises(InvalidTransition) as excinfo:
        change_status(scan, "blocked", actor)

    message = str(excinfo.value)
    assert "submitted" in message
    assert "analyzing" in message


def test_transition_graph_matches_oracle():
    """BR-04: the implemented graph is exactly the documented one."""
    from scans.services.workflows import TRANSITIONS

    implemented = {status: () for status in ALL_STATUSES}
    for t in TRANSITIONS:
        implemented[t.from_status] = tuple(t.allowed_to)
    assert implemented == EXPECTED_GRAPH
