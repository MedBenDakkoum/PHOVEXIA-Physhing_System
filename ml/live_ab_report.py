#!/usr/bin/env python3
"""Read-only A/B analysis of the live Tranco evaluation CSV.

This script NEVER starts a scan and never calls the collector or the inference
service. It only reads rows that `ml/live_legit_eval.py` already wrote.

Reported for samples A and B:
- complete rate (complete / scanned) with a Wilson 95% interval;
- verdict shares among complete scans (phishing gets a Wilson 95% interval);
- median of the 4 base probabilities and of the fusion probability;
- share of complete scans whose domain matches a training brand, with a
  Wilson 95% interval;
- two-proportion test on the false-phishing share only when BOTH samples have
  at least 30 complete scans.

If the CSV is missing, the script prints the paths it checked and exits 2
without inventing any number.
"""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import Counter
from pathlib import Path

PROB_FIELDS = ("p_url", "p_page_text", "p_screenshot", "p_metadata", "p_fusion")
SCANNED_STATUSES = {"complete", "partial", "rejected", "failed"}
MIN_COMPLETE_FOR_TEST = 30
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = REPO_ROOT / "docs" / "live_eval_ab_20261029.csv"
FALLBACK_CSVS = (
    Path("C:/Users/user/AppData/Local/Temp/opencode/pishing_live_validation/docs")
    / "live_eval_ab_20261029.csv",
)


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def as_float(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def interval_text(successes: int, total: int) -> str:
    low, high = wilson_interval(successes, total)
    return f"{pct(low)}-{pct(high)}"


def two_proportion_test(
    first_successes: int,
    first_total: int,
    second_successes: int,
    second_total: int,
) -> tuple[float, float, float]:
    """Two-sided pooled two-proportion z-test. Returns (z, p, diff)."""
    first = first_successes / first_total
    second = second_successes / second_total
    pooled = (first_successes + second_successes) / (first_total + second_total)
    standard_error = math.sqrt(
        pooled * (1 - pooled) * (1 / first_total + 1 / second_total)
    )
    if standard_error == 0:
        return (0.0, 1.0, first - second)
    z_score = (first - second) / standard_error
    p_value = math.erfc(abs(z_score) / math.sqrt(2))
    return (z_score, p_value, first - second)


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    missing = {"sample", "status", "verdict", "brand_match", *PROB_FIELDS} - set(
        rows[0].keys() if rows else ()
    )
    if missing:
        raise SystemExit(f"{path}: missing columns: {', '.join(sorted(missing))}")
    return rows


def sample_stats(rows: list[dict[str, str]], sample: str) -> dict[str, object]:
    sample_rows = [row for row in rows if row.get("sample") == sample]
    scanned = [row for row in sample_rows if row.get("status") in SCANNED_STATUSES]
    complete = [row for row in scanned if row.get("status") == "complete"]
    verdicts = Counter(row.get("verdict") or "" for row in complete)
    medians = {}
    for field in PROB_FIELDS:
        values = [value for row in complete if (value := as_float(row[field])) is not None]
        medians[field] = statistics.median(values) if values else None
    brand_complete = sum(row.get("brand_match") == "yes" for row in complete)
    return {
        "rows": sample_rows,
        "scanned": len(scanned),
        "complete": len(complete),
        "verdicts": verdicts,
        "phishing": verdicts.get("phishing", 0),
        "brand_complete": brand_complete,
        "medians": medians,
    }


def render(rows: list[dict[str, str]], csv_path: Path) -> str:
    stats = {sample: sample_stats(rows, sample) for sample in ("A", "B")}
    lines = [
        "# Live Tranco A/B analysis",
        "",
        f"- Source CSV: `{csv_path}`",
        "- Complete scans counted only when `status=complete`.",
        "",
        "## Complete rate",
        "",
        "| Sample | Scanned | Complete | Complete rate | Wilson 95% |",
        "|---|---:|---:|---:|---:|",
    ]
    for sample, item in stats.items():
        scanned = int(item["scanned"])
        complete = int(item["complete"])
        rate = complete / scanned if scanned else 0.0
        lines.append(
            f"| {sample} | {scanned} | {complete} | {pct(rate)} | "
            f"{interval_text(complete, scanned)} |"
        )

    lines += [
        "",
        "## Verdict shares among complete scans",
        "",
        (
            "| Sample | Complete | Legitimate (95% CI) | Uncertain (95% CI) | "
            "Phishing (95% CI) |"
        ),        "|---|---:|---:|---:|---:|",
    ]
    for sample, item in stats.items():
        complete = int(item["complete"])
        verdicts = item["verdicts"]
        cells = []
        for verdict in ("legitimate", "uncertain", "phishing"):
            count = verdicts.get(verdict, 0)
            cells.append(f"{count} ({interval_text(count, complete)})")
        lines.append(
            f"| {sample} | {complete} | " + " | ".join(cells) + " |"
        )

    lines += [
        "",
        "## Median probabilities among complete scans",
        "",
        "| Sample | URL char-CNN | HTML (DistilBERT) | Screenshot | Metadata MLP | Fusion |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for sample, item in stats.items():
        medians = item["medians"]
        cells = [
            "n/a" if medians[field] is None else f"{medians[field]:.4f}"
            for field in PROB_FIELDS
        ]
        lines.append(f"| {sample} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Training-brand association",
        "",
        "| Sample | Complete with training-brand domain | Share | Wilson 95% |",
        "|---|---:|---:|---:|",
    ]
    for sample, item in stats.items():
        complete = int(item["complete"])
        brand = int(item["brand_complete"])
        share = brand / complete if complete else 0.0
        lines.append(
            f"| {sample} | {brand}/{complete} | {pct(share)} | "
            f"{interval_text(brand, complete)} |"
        )

    first, second = stats["A"], stats["B"]
    lines += ["", "## Two-proportion test (false-phishing share)", ""]
    if (
        int(first["complete"]) >= MIN_COMPLETE_FOR_TEST
        and int(second["complete"]) >= MIN_COMPLETE_FOR_TEST
    ):
        z_score, p_value, difference = two_proportion_test(
            int(first["phishing"]),
            int(first["complete"]),
            int(second["phishing"]),
            int(second["complete"]),
        )
        lines.append(
            f"A vs B: difference {difference * 100:+.1f} points, "
            f"z={z_score:.2f}, two-sided p={p_value:.4f}."
        )
    else:
        lines.append(
            f"Not run: both samples need at least {MIN_COMPLETE_FOR_TEST} "
            "complete scans."
        )
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        type=Path,
        default=DEFAULT_CSV,
        help=f"CSV written by ml/live_legit_eval.py (default: {DEFAULT_CSV})",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="optional Markdown output path; stdout when omitted",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    candidates = (args.csv, *FALLBACK_CSVS)
    existing = next((path for path in candidates if path.is_file()), None)
    if existing is None:
        print("BLOCKED: no live A/B CSV found; nothing was scanned.")
        for path in candidates:
            print(f"- checked: {path}")
        return 2
    report = render(load_rows(existing), existing)
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(report, encoding="utf-8")
        print(f"wrote {args.summary}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
