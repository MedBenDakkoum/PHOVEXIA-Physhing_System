"""Repair scans stored with the url/screenshot probability labels swapped.

Before the by-name fix in ``scans.services.inference_client``, the friendly
keys were assigned by position: the mobilenet (screenshot) branch was stored
under ``url`` and the url_cnn branch under ``screenshot``. This command swaps
those two keys back, but ONLY for scans created before a caller-supplied ISO
datetime that have a real (non mock) model version and a non-empty
``probabilities`` JSON object.

Dry run by default. Nothing is written unless ``--apply`` is passed.
"""
from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from scans.models import Scan

MOCK_VERSION = "mock-0"


def _parse_before(value: str):
    parsed = parse_datetime(value)
    if parsed is None:
        raise CommandError(
            f"Invalid --before value {value!r}; expected an ISO datetime, "
            "e.g. 2026-10-31T12:00:00+01:00."
        )
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _swapped(probabilities: Any) -> dict[str, Any] | None:
    if not isinstance(probabilities, dict) or not probabilities:
        return None
    if "url" not in probabilities or "screenshot" not in probabilities:
        return None
    fixed = dict(probabilities)
    fixed["url"], fixed["screenshot"] = probabilities["screenshot"], probabilities["url"]
    return fixed


class Command(BaseCommand):
    help = (
        "Swap the url/screenshot keys of scans created before --before "
        "(real model_version, non-empty probabilities). Dry run by default."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--before",
            required=True,
            help="ISO datetime: only scans created strictly before it are considered.",
        )
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Actually write the corrected probabilities (default: dry run).",
        )

    def handle(self, *args, **options):
        before = _parse_before(options["before"])
        apply = bool(options["apply"])

        scans = (
            Scan.objects.filter(created_at__lt=before)
            .exclude(model_version__in=["", MOCK_VERSION])
            .order_by("id")
        )

        planned: list[tuple[Scan, dict[str, Any]]] = []
        for scan in scans.iterator(chunk_size=200):
            fixed = _swapped(scan.probabilities)
            if fixed is None:
                continue
            planned.append((scan, fixed))

        mode = "APPLY" if apply else "DRY RUN"
        self.stdout.write(
            f"{mode}: before={before.isoformat()} eligible={len(planned)}"
        )
        for scan, fixed in planned:
            self.stdout.write(
                "scan public_id={} model={} url {} -> {} | screenshot {} -> {}".format(
                    scan.public_id,
                    scan.model_version,
                    scan.probabilities.get("url"),
                    fixed.get("url"),
                    scan.probabilities.get("screenshot"),
                    fixed.get("screenshot"),
                )
            )

        if not apply:
            self.stdout.write(
                f"DRY RUN: {len(planned)} scan(s) would be updated; nothing written."
            )
            return

        updated = 0
        with transaction.atomic():
            for scan, fixed in planned:
                scan.probabilities = fixed
                scan.save(update_fields=["probabilities"])
                updated += 1

        self.stdout.write(f"APPLY: {updated} scan(s) updated.")
