"""Live legitimate-domain evaluation against the Docker stack (domain-shift measurement).

This is NOT a certified score and NOT a replacement for the held-out test set.
It calls the real collector and inference services, exactly like the worker,
but does not create Scan rows and does not change any threshold or model.

Usage (inside the backend worker container):
    docker exec -w /app backend-worker-1 python /tmp/live_legit_eval.py \
        --domains /tmp/live_legit_domains.txt \
        --out /tmp/live_eval_YYYYMMDD.csv \
        --summary /tmp/live_eval_YYYYMMDD_summary.md
"""
from __future__ import annotations

import argparse
import base64
import csv
import os
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

DEFAULT_COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:8000")
DEFAULT_INFERENCE_URL = os.environ.get("INFERENCE_URL", "http://inference:8000")
COLLECTOR_KEY = os.environ.get("COLLECTOR_API_KEY", "")
INFERENCE_KEY = os.environ.get("INFERENCE_API_KEY", "")

BRANCHES = ("url", "page_text", "screenshot", "metadata")
BRANCH_LABELS = {
    "url": "url_charcnn",
    "page_text": "distilbert",
    "screenshot": "mobilenet",
    "metadata": "metadata",
}
INFERENCE_KEYS = {
    "url": "url_cnn_phishing_probability",
    "page_text": "distilbert_phishing_probability",
    "screenshot": "mobilenet_phishing_probability",
    "metadata": "metadata_phishing_probability",
}

CSV_FIELDS = [
    "rank",
    "domain",
    "url",
    "status",
    "partial",
    "reason_code",
    "collector_status",
    "collector_reason",
    "inference_status",
    "inference_reason",
    "http_status",
    "final_url",
    "p_url",
    "p_page_text",
    "p_screenshot",
    "p_metadata",
    "p_fusion",
    "verdict",
    "duration_ms",
    "error",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live legitimate-domain evaluation")
    parser.add_argument("--domains", required=True, help="file with one domain per line")
    parser.add_argument("--out", required=True, help="CSV output path")
    parser.add_argument("--summary", required=True, help="Markdown summary output path")
    parser.add_argument("--limit", type=int, default=None, help="evaluate only the first N domains")
    parser.add_argument("--min-interval", type=float, default=2.0, help="seconds between requests per host")
    parser.add_argument("--collector-url", default=DEFAULT_COLLECTOR_URL)
    parser.add_argument("--inference-url", default=DEFAULT_INFERENCE_URL)
    parser.add_argument("--collector-key", default=COLLECTOR_KEY)
    parser.add_argument("--inference-key", default=INFERENCE_KEY)
    parser.add_argument("--timeout", type=float, default=45.0, help="collector HTTP timeout")
    return parser.parse_args(argv)


def read_domains(path: str, limit: int | None) -> list[str]:
    domains: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line)
    return domains[:limit] if limit else domains


def load_thresholds() -> tuple[float, float, str]:
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        import django

        django.setup()
        from controlpanel.services.settings import get_detection_settings

        settings_value = get_detection_settings()
        return (
            float(settings_value.phishing_threshold),
            float(settings_value.uncertain_lower),
            "DetectionSettings",
        )
    except Exception:  # noqa: BLE001 - fall back when Django/DB is unavailable
        return (
            float(os.environ.get("DETECTION_PHISHING_THRESHOLD", "0.70")),
            float(os.environ.get("DETECTION_UNCERTAIN_LOWER", "0.40")),
            "environment/default",
        )


def verdict_from(score: float | None, phishing: float, uncertain_lower: float) -> str:
    if score is None:
        return "uncertain"
    if score >= phishing:
        return "phishing"
    if score <= uncertain_lower:
        return "legitimate"
    return "uncertain"


def wait_for_host(last_seen: dict[str, float], host: str, min_interval: float) -> None:
    now = time.monotonic()
    due = last_seen.get(host, 0.0) + min_interval
    if now < due:
        time.sleep(due - now)
    last_seen[host] = time.monotonic()


class CollectorRejected(Exception):
    def __init__(self, code: str, detail: str, status_code: int) -> None:
        self.code = code
        self.detail = detail
        self.status_code = status_code
        super().__init__(code)


def call_collector(
    session: requests.Session, base_url: str, api_key: str, url: str, timeout: float
) -> dict:
    response = session.post(
        f"{base_url.rstrip('/')}/collect",
        json={"url": url},
        headers={"X-API-Key": api_key},
        timeout=timeout,
        allow_redirects=False,
    )
    if response.status_code == 400:
        try:
            body = response.json()
        except ValueError:
            body = {}
        raise CollectorRejected(
            body.get("code") or "INVALID_URL",
            body.get("detail") or "URL rejected by validation",
            response.status_code,
        )
    if response.status_code != 200:
        raise RuntimeError(f"COLLECTOR_HTTP_{response.status_code}")
    return response.json()


def call_inference(
    session: requests.Session, base_url: str, api_key: str, capture: dict, timeout: float
) -> dict:
    data = {
        "url": capture.get("final_url") or "",
        "text": capture.get("text") or "",
        "ssl": str(int(capture.get("ssl") or 0)),
        "tld": capture.get("tld") or "",
        "subdomain": capture.get("subdomain") or "",
    }
    files = None
    screenshot = capture.get("screenshot_png_base64")
    if screenshot:
        files = {"screenshot": ("screenshot.png", base64.b64decode(screenshot), "image/png")}
    response = session.post(
        f"{base_url.rstrip('/')}/predict",
        data=data,
        files=files,
        headers={"X-API-Key": api_key},
        timeout=timeout,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise RuntimeError(f"INFERENCE_HTTP_{response.status_code}")
    return response.json()


def evaluate_domain(
    session: requests.Session,
    rank: int,
    domain: str,
    args: argparse.Namespace,
    phishing: float,
    uncertain_lower: float,
) -> dict:
    url = f"https://{domain}/"
    started = time.perf_counter()
    row = {field: "" for field in CSV_FIELDS}
    row.update(
        {
            "rank": rank,
            "domain": domain,
            "url": url,
            "partial": "false",
            "status": "failed",
        }
    )
    try:
        capture = call_collector(
            session, args.collector_url, args.collector_key, url, args.timeout
        )
        row["collector_status"] = capture.get("status") or ""
        row["collector_reason"] = capture.get("reason_code") or ""
        row["http_status"] = capture.get("http_status")
        row["final_url"] = capture.get("final_url") or ""
        if capture.get("status") != "complete":
            row["status"] = "partial"
            row["partial"] = "true"
            row["reason_code"] = capture.get("reason_code") or "COLLECTOR_PARTIAL"
            row["verdict"] = "uncertain"
            return row

        inference = call_inference(
            session, args.inference_url, args.inference_key, capture, args.timeout
        )
        row["inference_status"] = inference.get("status") or ""
        row["inference_reason"] = inference.get("reason_code") or ""
        base = inference.get("base_probabilities") or {}
        for branch in BRANCHES:
            row[f"p_{branch}"] = base.get(INFERENCE_KEYS[branch])
        if inference.get("status") == "uncertain" or inference.get("partial"):
            row["status"] = "partial"
            row["partial"] = "true"
            row["reason_code"] = inference.get("reason_code") or "MODEL_UNCERTAIN"
            row["verdict"] = "uncertain"
            return row

        fusion = inference.get("phishing_probability")
        row["p_fusion"] = fusion
        row["status"] = "complete"
        row["verdict"] = verdict_from(fusion, phishing, uncertain_lower)
        return row
    except CollectorRejected as exc:
        row["status"] = "rejected"
        row["partial"] = "true"
        row["collector_status"] = "rejected"
        row["collector_reason"] = exc.code
        row["reason_code"] = exc.code
        row["error"] = exc.detail
        row["verdict"] = ""
        return row
    except Exception as exc:  # noqa: BLE001 - one site must not abort the run
        row["status"] = "failed"
        row["partial"] = "true"
        row["error"] = f"{type(exc).__name__}: {exc}"
        row["verdict"] = ""
        return row
    finally:
        row["duration_ms"] = int((time.perf_counter() - started) * 1000)


def as_float(value: object) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def summarize(rows: list[dict], phishing: float, uncertain_lower: float, source: str, threshold_source: str) -> str:
    total = len(rows)
    complete = [row for row in rows if row["status"] == "complete"]
    partial = [row for row in rows if row["status"] == "partial"]
    rejected = [row for row in rows if row["status"] == "rejected"]
    failed = [row for row in rows if row["status"] == "failed"]
    reasons = Counter(
        row["reason_code"] or "UNKNOWN" for row in partial + rejected + failed
    )
    verdicts = Counter(row["verdict"] for row in complete)

    branch_high = Counter()
    branch_values: dict[str, list[float]] = {branch: [] for branch in BRANCHES}
    for row in complete:
        values = {branch: as_float(row[f"p_{branch}"]) for branch in BRANCHES}
        present = {branch: value for branch, value in values.items() if value is not None}
        if not present:
            continue
        best = max(present.values())
        for branch, value in present.items():
            if value == best:
                branch_high[branch] += 1
        for branch, value in present.items():
            branch_values[branch].append(value)

    lines = [
        "# Live legitimate-domain evaluation",
        "",
        f"- Source: {source}",
        f"- Run (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Decision thresholds: phishing >= {phishing:.2f}, legitimate <= {uncertain_lower:.2f} ({threshold_source})",
        "- Scope: home page only, HTTPS, Docker stack (collector + inference), no Scan rows, no tuning.",
        "- This is a domain-shift measurement, not a certified score.",
        "",
        "## Coverage",
        "",
        "| Metric | Count | Share |",
        "|---|---:|---:|",
        f"| Total | {total} | 100.0% |",
        f"| Complete | {len(complete)} | {len(complete) / total * 100 if total else 0:.1f}% |",
        f"| Partial | {len(partial)} | {len(partial) / total * 100 if total else 0:.1f}% |",
        f"| Rejected (not evaluable: DNS / BR-07) | {len(rejected)} | {len(rejected) / total * 100 if total else 0:.1f}% |",
        f"| Failed (infrastructure) | {len(failed)} | {len(failed) / total * 100 if total else 0:.1f}% |",
        "",
        "## Partial/rejected/failed reasons",
        "",
        "| Reason | Count |",
        "|---|---:|",
    ]
    for reason, count in reasons.most_common():
        lines.append(f"| {reason} | {count} |")
    if not reasons:
        lines.append("| none | 0 |")

    lines += [
        "",
        "## Verdicts among complete scans",
        "",
        "| Verdict | Count | Share |",
        "|---|---:|---:|",
    ]
    for verdict in ("legitimate", "uncertain", "phishing"):
        count = verdicts.get(verdict, 0)
        share = count / len(complete) * 100 if complete else 0.0
        lines.append(f"| {verdict} | {count} | {share:.1f}% |")

    lines += [
        "",
        "## Branch behaviour among complete scans",
        "",
        "| Branch | Most often highest | Median probability |",
        "|---|---:|---:|",
    ]
    for branch in BRANCHES:
        values = branch_values[branch]
        median = statistics.median(values) if values else None
        median_text = f"{median:.4f}" if median is not None else "n/a"
        lines.append(
            f"| {BRANCH_LABELS[branch]} | {branch_high.get(branch, 0)} | {median_text} |"
        )

    uncertain_share = verdicts.get("uncertain", 0) / len(complete) * 100 if complete else 0.0
    phishing_share = verdicts.get("phishing", 0) / len(complete) * 100 if complete else 0.0
    lines += [
        "",
        "## Comparison with the held-out test set",
        "",
        "| Metric | Live complete scans | Test-set reference |",
        "|---|---:|---:|",
        f"| Uncertain | {uncertain_share:.1f}% | 19.2% |",
        f"| Phishing (false positives, all inputs are legitimate) | {phishing_share:.1f}% | 5.5% at 0.5 |",
        "",
        "The reference values (19.2% uncertain, 5.5% false positives at 0.5) were provided by the user for the held-out test set.",
        "The decision rules differ (test set: argmax / 0.5; this run: DetectionSettings 0.70/0.40) and the data differ (live pages vs held-out split), so the comparison is indicative only.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    domains = read_domains(args.domains, args.limit)
    if not domains:
        print("No domains to evaluate.", file=sys.stderr)
        return 2
    if not args.collector_key or not args.inference_key:
        print("COLLECTOR_API_KEY and INFERENCE_API_KEY are required.", file=sys.stderr)
        return 2
    phishing, uncertain_lower, threshold_source = load_thresholds()
    source = "Tranco daily top-1M, https://tranco-list.eu/download/daily/top-1m.csv.zip, Last-Modified 2026-10-27T22:23:21Z, ETag 18e28325fea99168-945f8b, first 100 domains"

    session = requests.Session()
    last_seen: dict[str, float] = {}
    rows: list[dict] = []
    for index, domain in enumerate(domains, start=1):
        if index > 1:
            time.sleep(args.min_interval)
        wait_for_host(last_seen, domain.lower(), args.min_interval)
        row = evaluate_domain(session, index, domain, args, phishing, uncertain_lower)
        rows.append(row)
        print(
            f"{index:03d} {domain} status={row['status']} reason={row['reason_code']} "
            f"verdict={row['verdict']} fusion={row['p_fusion']}",
            flush=True,
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    summary = summarize(rows, phishing, uncertain_lower, source, threshold_source)
    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
