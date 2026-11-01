"""Tests for the `fix_swapped_probabilities` data-repair command (US27).

The command must be a dry run by default, only touch scans created before
--before with a real model version and a non-empty probabilities object, and
never write anything without --apply.
"""
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from scans.models import Scan

SWAPPED = {
    "url": 0.97,
    "page_text": 0.98,
    "screenshot": 0.0039,
    "metadata": 0.09,
    "fusion": 0.71,
}


def make_scan(**overrides):
    values = {
        "url": "https://example.com/",
        "domain": "example.com",
        "status": Scan.Status.DETECTED,
        "model_version": "2026-10-25",
        "probabilities": dict(SWAPPED),
    }
    values.update(overrides)
    return Scan.objects.create(**values)


def run(*args):
    out = StringIO()
    call_command("fix_swapped_probabilities", *args, stdout=out)
    return out.getvalue()


@pytest.mark.django_db
def test_dry_run_is_the_default_and_writes_nothing():
    scan = make_scan()
    before = (timezone.now() + timedelta(hours=1)).isoformat()

    output = run("--before", before)

    scan.refresh_from_db()
    assert "DRY RUN" in output
    assert scan.probabilities == SWAPPED


@pytest.mark.django_db
def test_apply_swaps_url_and_screenshot_and_keeps_other_keys():
    scan = make_scan()
    before = (timezone.now() + timedelta(hours=1)).isoformat()

    output = run("--before", before, "--apply")

    scan.refresh_from_db()
    assert "APPLY: 1 scan(s) updated." in output
    assert scan.probabilities["url"] == pytest.approx(0.0039)
    assert scan.probabilities["screenshot"] == pytest.approx(0.97)
    assert scan.probabilities["page_text"] == pytest.approx(0.98)
    assert scan.probabilities["metadata"] == pytest.approx(0.09)
    assert scan.probabilities["fusion"] == pytest.approx(0.71)


@pytest.mark.django_db
def test_only_eligible_scans_are_updated():
    eligible = make_scan()
    mock = make_scan(model_version="mock-0")
    empty = make_scan(probabilities={})
    incomplete = make_scan(probabilities={"url": 0.5, "page_text": 0.2})
    later = make_scan()
    Scan.objects.filter(pk=later.pk).update(
        created_at=timezone.now() + timedelta(days=1)
    )
    before = (timezone.now() + timedelta(hours=1)).isoformat()

    run("--before", before, "--apply")

    for scan in (eligible, mock, empty, incomplete, later):
        scan.refresh_from_db()
    assert eligible.probabilities["url"] == pytest.approx(0.0039)
    assert mock.probabilities == SWAPPED
    assert empty.probabilities == {}
    assert incomplete.probabilities == {"url": 0.5, "page_text": 0.2}
    assert later.probabilities == SWAPPED


@pytest.mark.django_db
def test_invalid_datetime_is_refused():
    with pytest.raises(CommandError):
        run("--before", "not-a-date")
