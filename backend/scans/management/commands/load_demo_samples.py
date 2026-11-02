"""Load golden Phish360 samples as demo Scan rows (docs/DEMO_RUNBOOK.md).

Reads the git-ignored bundle (golden_samples.csv + <id>.png / <id>.txt),
mounted READ-ONLY at DEMO_SAMPLES_DIR by docker compose, and for each sample:

1. posts the STORED inputs (url, text, ssl, tld, subdomain, screenshot) to
   the inference service through the normal InferenceClient - the original
   URL is NEVER contacted: no collector, no HTTP GET, no browser (BR-07 is
   not even triggered because nothing is crawled);
2. compares every returned probability with golden_samples.csv (absolute
   tolerance 1e-4, same rule as the inference golden test) and prints each
   mismatch - nothing is invented, a mismatch never blocks the load;
3. reuses the NORMAL result mapping of the real pipeline: thresholds from
   DetectionSettings via _thresholds() + classify_score + the transparent
   brand policy, then _store_result (change_status SUBMITTED -> ANALYZING ->
   DETECTED, or -> UNDER_REVIEW for an uncertain verdict - BR-04);
4. stores the screenshot under MEDIA_ROOT/screenshots/<public_id>.png and
   stamps detection_source=dataset_sample (never counted against any quota,
   see scans/services/quota.py).

Idempotent: a sample already stored (demo_sample_id set) is skipped, so the
command can be re-run after `docker compose down -v` or an interrupted load.

Usage (from backend/, INFERENCE_URL must reach the service):
    python manage.py load_demo_samples --owner demo.user@example.org --count 20
"""
from __future__ import annotations

import base64
import csv
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from controlpanel.services import get_active_model_version_label

from ...models import Scan
from ...services.brand_policy import apply_brand_policy
from ...services.inference import _thresholds, classify_score
from ...services.inference_client import (
    _BASE_KEYS,
    _FRIENDLY_KEYS,
    InferenceClient,
    InferenceError,
)
from ...services.screenshots import prepare_screenshot
from ...services.workflows import change_status
from ...tasks import ScanOutcome, _store_result

User = get_user_model()

GOLDEN_CSV = "golden_samples.csv"
# Inference golden acceptance rule (contract section 5 / D8).
TOLERANCE = 1e-4

# golden_samples.csv column -> InferenceResponse friendly key. Built from the
# SAME zip the client uses, so the comparison always matches the raw base key
# the service returned, whatever the friendly label says.
_CSV_TO_FRIENDLY = dict(zip(_BASE_KEYS, _FRIENDLY_KEYS))
_EXPECTED_COLUMNS = {base: base for base in _BASE_KEYS}
_FUSION_COLUMN = "fusion_mlp_phishing_probability"


@dataclass
class LoadStats:
    created: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)

    @property
    def mismatch_count(self) -> int:
        return len(self.mismatches)


def resolve_samples_dir(explicit: str) -> Path:
    """--samples-dir > DEMO_SAMPLES_DIR > backend/ml_artifacts/golden."""
    candidate = (
        explicit
        or settings.DEMO_SAMPLES_DIR
        or str(Path(settings.BASE_DIR) / "ml_artifacts" / "golden")
    )
    path = Path(candidate)
    if not (path / GOLDEN_CSV).is_file():
        raise CommandError(
            f"golden bundle not found: {path / GOLDEN_CSV} "
            "(set DEMO_SAMPLES_DIR or pass --samples-dir)."
        )
    return path


def _read_rows(samples_dir: Path, count: int) -> list[dict[str, str]]:
    with (samples_dir / GOLDEN_CSV).open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise CommandError(f"{GOLDEN_CSV} contains no rows.")
    if count < 1:
        raise CommandError("--count must be >= 1.")
    return rows[:count]


def _parse_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _compare_to_golden(row: dict[str, str], inf, sample_id: str) -> list[str]:
    """Absolute 1e-4 comparison of every probability; returns the messages."""
    problems: list[str] = []
    for base_key, column in _EXPECTED_COLUMNS.items():
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        expected = float(raw)
        got = inf.base_probabilities.get(_CSV_TO_FRIENDLY[base_key])
        if got is None:
            problems.append(
                f"MISMATCH sample {sample_id} {column}: missing (got None, "
                f"expected {expected:.6f})"
            )
        elif abs(got - expected) > TOLERANCE:
            problems.append(
                f"MISMATCH sample {sample_id} {column}: expected "
                f"{expected:.6f}, got {got:.6f}, delta {abs(got - expected):.3e} "
                f"> {TOLERANCE:g}"
            )
    raw_fusion = (row.get(_FUSION_COLUMN) or "").strip()
    if raw_fusion and inf.phishing_probability is not None:
        expected = float(raw_fusion)
        if abs(inf.phishing_probability - expected) > TOLERANCE:
            problems.append(
                f"MISMATCH sample {sample_id} {_FUSION_COLUMN}: expected "
                f"{expected:.6f}, got {inf.phishing_probability:.6f}, delta "
                f"{abs(inf.phishing_probability - expected):.3e} > {TOLERANCE:g}"
            )
    return problems


def _signals_from_row(row: dict[str, str], url: str) -> dict[str, Any]:
    host = urlsplit(url).hostname or ""
    return {
        "ssl": _parse_int(row.get("SSL", "")),
        "tld": (row.get("TLD") or "").strip(),
        "subdomain": (row.get("Subdomain") or "").strip(),
        "domain": host,
    }


def _load_one(
    command: Command,
    owner: User,
    row: dict[str, str],
    samples_dir: Path,
    stats: LoadStats,
) -> None:
    sample_id = (row.get("sample_index") or "").strip()
    if not sample_id:
        raise CommandError("golden row without sample_index.")
    if Scan.objects.filter(demo_sample_id=sample_id).exists():
        stats.skipped.append(sample_id)
        return

    url = (row.get("URL") or "").strip()
    if not url:
        raise CommandError(f"golden row {sample_id} without URL.")
    domain = urlsplit(url).hostname or ""

    text_path = samples_dir / f"{sample_id}.txt"
    text = (
        text_path.read_text(encoding="utf-8")
        if text_path.is_file()
        else (row.get("html_text") or "")
    )
    png_path = samples_dir / f"{sample_id}.png"
    if png_path.is_file():
        png_bytes: bytes | None = png_path.read_bytes()
    else:
        png_bytes = None
        command.stdout.write(
            command.style.WARNING(
                f"sample {sample_id}: missing {png_path.name}, predicting "
                "without a screenshot."
            )
        )

    with transaction.atomic():
        scan = Scan.objects.create(
            owner=owner,
            url=url,
            domain=domain,
            mode=Scan.Mode.FULL,
            status=Scan.Status.SUBMITTED,
            detection_source=Scan.DetectionSource.DATASET_SAMPLE,
            demo_sample_id=sample_id,
        )
        change_status(scan, Scan.Status.ANALYZING, actor=None)

    try:
        inf = InferenceClient().predict(
            url=url,
            text=text,
            screenshot_png=png_bytes,
            ssl=_parse_int(row.get("SSL", "")),
            tld=(row.get("TLD") or "").strip() or None,
            subdomain=(row.get("Subdomain") or "").strip() or None,
        )
    except InferenceError as exc:
        scan.error_message = f"{type(exc).__name__}: {exc.detail or exc.reason}"[:200]
        scan.reason_code = exc.reason[:64]
        scan.save(update_fields=["error_message", "reason_code"])
        change_status(scan, Scan.Status.FAILED, actor=None)
        stats.failed.append(f"{sample_id} ({exc.reason})")
        command.stdout.write(
            command.style.WARNING(
                f"sample {sample_id}: FAILED ({exc.reason}) - inference service "
                "unreachable or protocol error."
            )
        )
        return

    stats.mismatches.extend(_compare_to_golden(row, inf, sample_id))

    screenshot_path, _ = prepare_screenshot(
        scan.public_id,
        base64.b64encode(png_bytes).decode("ascii") if png_bytes else None,
    )
    signals = _signals_from_row(row, url)
    model_label = get_active_model_version_label()

    if inf.status == "uncertain" or inf.partial or inf.phishing_probability is None:
        outcome = ScanOutcome(
            verdict="uncertain",
            score=None,
            partial=True,
            reason_code=inf.reason_code or "MODEL_UNCERTAIN",
            final_url=url,
            signals=signals,
            probabilities={**inf.base_probabilities, "fusion": None},
            model_bundle_version=inf.model_bundle_version,
            screenshot_path=screenshot_path,
            escalate_to_review=False,
            detection_source=Scan.DetectionSource.DATASET_SAMPLE,
        )
    else:
        lower, upper = _thresholds()
        verdict = classify_score(inf.phishing_probability, lower, upper)
        policy = apply_brand_policy(
            url=url,
            host=domain,
            model_verdict=verdict,
            model_score=inf.phishing_probability,
        )
        outcome = ScanOutcome(
            verdict=policy.verdict,
            score=policy.score,
            partial=False,
            reason_code="",
            final_url=url,
            signals=signals,
            probabilities={**inf.base_probabilities, "fusion": inf.phishing_probability},
            model_bundle_version=inf.model_bundle_version,
            screenshot_path=screenshot_path,
            escalate_to_review=(
                policy.escalate_to_review or policy.verdict == "uncertain"
            ),
            model_verdict=verdict,
            model_score=inf.phishing_probability,
            policy_flags=policy.flags,
            policy_note=policy.note,
            detection_source=Scan.DetectionSource.DATASET_SAMPLE,
        )

    with transaction.atomic():
        final_status = _store_result(
            scan.pk, outcome, model_version_label=model_label
        )
    stats.created.append(sample_id)
    command.stdout.write(
        f"sample {sample_id} -> scan {scan.public_id} "
        f"verdict={outcome.verdict} score={outcome.score} "
        f"status={final_status}"
    )


class Command(BaseCommand):
    help = (
        "Load golden Phish360 samples as DATASET_SAMPLE scans (inference only, "
        "the original URLs are never contacted; idempotent; demo_setup calls it)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--owner", required=True, help="Email of the user owning the scans."
        )
        parser.add_argument(
            "--count", type=int, default=20, help="How many samples to load (default 20)."
        )
        parser.add_argument(
            "--samples-dir",
            default="",
            help="Golden bundle folder (default: DEMO_SAMPLES_DIR, then ml_artifacts/golden).",
        )

    def handle(self, *args, **options):
        email = options["owner"].strip()
        owner = User.objects.filter(email__iexact=email).first()
        if owner is None:
            raise CommandError(f"owner not found: {email}")
        samples_dir = resolve_samples_dir(options["samples_dir"])
        # Prints the per-sample lines, the mismatches and the summary, then
        # returns the stats dict. NOT returned to BaseCommand.execute (it
        # stringifies a non-empty output): demo_setup calls this function
        # directly to reuse both the work and the printed proof.
        load_golden_samples(
            owner=owner,
            samples_dir=samples_dir,
            count=options["count"],
            command=self,
        )


def load_golden_samples(
    *, owner: User, samples_dir: Path, count: int, command: Command
) -> dict:
    """Shared entry point of the command: load `count` samples for `owner`.

    Prints through `command.stdout` / `command.style` so a caller (demo_setup)
    shows exactly the same output as the standalone command.
    """
    rows = _read_rows(samples_dir, count)

    stats = LoadStats()
    for row in rows:
        _load_one(command, owner, row, samples_dir, stats)

    verdicts = Counter(
        Scan.objects.filter(demo_sample_id__in=stats.created).values_list(
            "verdict", flat=True
        )
    )
    for message in stats.mismatches:
        command.stdout.write(command.style.WARNING(message))

    command.stdout.write(
        command.style.SUCCESS(
            f"load_demo_samples: {len(stats.created)} created, "
            f"{len(stats.skipped)} skipped, {len(stats.failed)} failed, "
            f"{stats.mismatch_count} mismatch(es) at {TOLERANCE:g} "
            f"tolerance (dir={samples_dir})."
        )
    )
    if verdicts:
        command.stdout.write(
            "verdicts of this run: "
            + ", ".join(f"{name}={qty}" for name, qty in sorted(verdicts.items()))
        )
    if stats.failed:
        command.stdout.write(
            command.style.WARNING(
                "failed samples: " + ", ".join(stats.failed)
                + " (inference service down or protocol error)."
            )
        )
    return {
        "created": len(stats.created),
        "skipped": len(stats.skipped),
        "failed": len(stats.failed),
        "mismatches": stats.mismatch_count,
        "mismatch_messages": stats.mismatches,
    }
