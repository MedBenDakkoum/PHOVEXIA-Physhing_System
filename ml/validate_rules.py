#!/usr/bin/env python3
"""Measure the collector feature rules against the Phish360 rules sample.

Rerunnable Part 1 of the collector work (docs/collector_spec_v1.md).

Modes
-----
default (parts A, B, C on the Parquet sample):

    python ml/validate_rules.py --sample backend/ml_artifacts/phish360_rules_sample.parquet \
        --tokenizer-dir <dir with distilbert-base-uncased files> \
        --evidence docs/evidence/collector_rules_v1_20261025.txt

sensitivity (golden samples against a running inference service):

    python ml/validate_rules.py --sensitivity --inference-url http://127.0.0.1:8000 \
        --api-key <INFERENCE_API_KEY> --golden-dir backend/ml_artifacts/golden \
        --evidence docs/evidence/collector_sensitivity_v1_20261025.txt

Inside the inference container (no published port, same-process service):

    cmd /c "docker exec -i backend-inference-1 python - --sensitivity ... < ml/validate_rules.py > out.txt"

Everything printed is also written to --evidence. No number is ever invented:
each figure below comes from a real run recorded in the evidence file.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

try:
    REPO_ROOT = Path(__file__).resolve().parents[1]
except (NameError, IndexError):
    REPO_ROOT = Path.cwd()
DEFAULT_SAMPLE = REPO_ROOT / "backend" / "ml_artifacts" / "phish360_rules_sample.parquet"
DEFAULT_GOLDEN_DIR = REPO_ROOT / "backend" / "ml_artifacts" / "golden"
DEFAULT_EVIDENCE = REPO_ROOT / "docs" / "evidence" / "collector_rules_v1_20261025.txt"
DEFAULT_SENSITIVITY_EVIDENCE = (
    REPO_ROOT / "docs" / "evidence" / "collector_sensitivity_v1_20261025.txt"
)
TOKENIZER_REVISION = "12040accade4e8a0f71eabdb258fecc2e7e948be"
TOKENIZER_BAR = 0.90
SSL_BAR = 0.97
MAX_TOKENS = 256

_lines: list[str] = []


def emit(text: str = "") -> None:
    print(text)
    _lines.append(text)


def flush_evidence(path: Path | None) -> None:
    if path is None or str(path) == "-":
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(_lines) + "\n", encoding="utf-8")
    emit(f"[evidence written to {path}]")


def norm(value) -> str:
    if value is None:
        return ""
    try:
        import pandas as pd

        if pd.isna(value):
            return ""
    except (ImportError, TypeError, ValueError):
        pass
    text = str(value).strip()
    if text.lower() in {"nan", "none", "<na>"}:
        return ""
    return text


def host_of(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def is_ip_host(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Part A - TLD / Domain / FLD / Subdomain
# ---------------------------------------------------------------------------

PROBE_CASES = [
    ("ipv4_literal", "http://217.16.9.28/path"),
    ("ipv6_literal", "http://[2001:db8::1]/path"),
    ("port_8080", "http://www.poliisi.fi:8080/x"),
    ("uppercase_host", "https://WWW.Example.COM/Path"),
    ("trailing_dot", "http://example.com./path"),
    ("idn_punycode", "http://xn--r8jz45g.com/"),
    ("idn_unicode", "http://\u4f8b\u3048\u30c6\u30b9\u30c8/"),
    ("no_scheme", "www.example.com/path"),
    ("deep_subdomain", "https://a.b.c.example.co.uk/x"),
    ("private_suffix", "https://identifiez-vous415.yolasite.com/"),
    ("localhost", "http://localhost:8000/"),
]


def load_libs():
    import tldextract
    from tld import get_tld as tld_get

    extractor = tldextract.TLDExtract(
        suffix_list_urls=(), include_psl_private_domains=True
    )
    return tld_get, extractor


def split_with_tld(get_tld, url: str) -> dict:
    try:
        result = get_tld(url.strip(), as_object=True, fail_silently=True)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        result = None
    if result is None:
        return {"tld": "", "domain": "", "subdomain": "", "fld": ""}
    return {
        "tld": norm(getattr(result, "tld", "")),
        "domain": norm(getattr(result, "domain", "")),
        "subdomain": norm(getattr(result, "subdomain", "")),
        "fld": norm(getattr(result, "fld", "")),
    }


def split_with_tldextract(extractor, url: str) -> dict:
    try:
        result = extractor(url.strip())
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return {"tld": "", "domain": "", "subdomain": "", "fld": ""}
    suffix = norm(result.suffix)
    domain = norm(result.domain)
    subdomain = norm(result.subdomain)
    fld = f"{domain}.{suffix}" if domain and suffix else ""
    return {"tld": suffix, "domain": domain, "subdomain": subdomain, "fld": fld}


def apply_ip_rule(parts: dict, url: str, rule: bool) -> dict:
    if rule and is_ip_host(url):
        return {"tld": "", "domain": "", "subdomain": "", "fld": ""}
    return parts


def compare_columns(rows, stored_map, lib_map, label: str, rule: bool) -> dict:
    fields = ("tld", "domain", "fld", "subdomain")
    stored_field = {"tld": "TLD", "domain": "Domain", "fld": "FLD", "subdomain": "Subdomain"}
    stats = {
        field: {
            "agree": 0,
            "disagree": 0,
            "stored_missing": 0,
            "lib_missing": 0,
            "examples": [],
        }
        for field in fields
    }
    for i, url in enumerate(rows):
        for field in fields:
            stored = norm(stored_map[i][stored_field[field]])
            lib = norm(apply_ip_rule(lib_map[i], url, rule)[field])
            if rule:
                lib = lib.lower()
                stored = stored.lower()
            item = stats[field]
            if stored == "":
                item["stored_missing"] += 1
            if lib == "":
                item["lib_missing"] += 1
            if stored == lib:
                item["agree"] += 1
            else:
                item["disagree"] += 1
                if len(item["examples"]) < 6:
                    item["examples"].append((i, url[:60], stored, lib))
    total = len(rows)
    emit()
    emit(f"A{i_label(label)}: rows={total}")
    emit(
        f"{'column':<11}{'agree':>6}{'rate%':>8}{'disagree':>10}"
        f"{'stored_mis':>11}{'lib_mis':>9}"
    )
    for field in fields:
        item = stats[field]
        rate = 100.0 * item["agree"] / total
        emit(
            f"{field:<11}{item['agree']:>6}{rate:>8.2f}{item['disagree']:>10}"
            f"{item['stored_missing']:>11}{item['lib_missing']:>9}"
        )
    for field in fields:
        for (i, url, stored, lib) in stats[field]["examples"]:
            emit(
                f"  mismatch {field:<10} row={i:<4} stored={stored!r:<22}"
                f" lib={lib!r:<22} url={url}"
            )
    return stats


def i_label(label: str) -> str:
    return f" [{label}]"


def run_part_a(args) -> dict:
    import pandas as pd

    df = pd.read_parquet(args.sample)
    rows = [str(u) for u in df["URL"].tolist()]
    stored_map = df.to_dict("records")
    get_tld, extractor = load_libs()

    emit("=" * 78)
    emit("PART A - URL decomposition: tld vs tldextract")
    emit("=" * 78)
    emit(f"sample={args.sample}")
    emit(f"rows={len(rows)}")

    tld_map = [split_with_tld(get_tld, u) for u in rows]
    ext_map = [split_with_tldextract(extractor, u) for u in rows]

    non_lowercase = sum(
        1
        for rec in stored_map
        for col in ("TLD", "Domain", "FLD", "Subdomain")
        if norm(rec[col]) != norm(rec[col]).lower()
    )
    emit(f"stored values that are not lowercase (all columns): {non_lowercase}")
    emit(f"rows with IP host: {sum(1 for u in rows if is_ip_host(u))}")

    raw_tld = compare_columns(rows, stored_map, tld_map, "tld raw", rule=False)
    raw_ext = compare_columns(rows, stored_map, ext_map, "tldextract raw", rule=False)
    rule_tld = compare_columns(rows, stored_map, tld_map, "tld + rule v1 (lower+IP)", rule=True)
    rule_ext = compare_columns(rows, stored_map, ext_map, "tldextract + rule v1 (lower+IP)", rule=True)

    emit()
    emit("Edge behaviour (raw library output, no normalisation):")
    header = (
        f"{'case':<18}{'lib':<12}{'tld/suffix':<16}{'domain':<26}"
        f"{'subdomain':<14}{'fld'}"
    )
    emit(header)
    for name, probe in PROBE_CASES:
        tld_parts = split_with_tld(get_tld, probe)
        ext_parts = split_with_tldextract(extractor, probe)
        for lib, parts in (("tld", tld_parts), ("tldextract", ext_parts)):
            emit(
                f"{name:<18}{lib:<12}{parts['tld']:<16}{parts['domain']:<26}"
                f"{parts['subdomain']:<14}{parts['fld']}"
            )
    return {
        "tld_raw": raw_tld,
        "ext_raw": raw_ext,
        "tld_rule": rule_tld,
        "ext_rule": rule_ext,
    }


# ---------------------------------------------------------------------------
# Part B - SSL hypothesis H1
# ---------------------------------------------------------------------------


def run_part_b(args) -> dict:
    import pandas as pd

    df = pd.read_parquet(args.sample)
    emit()
    emit("=" * 78)
    emit("PART B - SSL hypothesis H1: SSL == 1 iff scheme is https")
    emit("=" * 78)
    emit(f"SSL dtype={df['SSL'].dtype} nulls={int(df['SSL'].isna().sum())}")

    table = {
        ("https", "ssl_true"): 0,
        ("https", "ssl_false"): 0,
        ("http", "ssl_true"): 0,
        ("http", "ssl_false"): 0,
        ("other", "ssl_true"): 0,
        ("other", "ssl_false"): 0,
    }
    other_examples: list[str] = []
    agree = 0
    total = 0
    for url, ssl_value in zip(df["URL"], df["SSL"], strict=True):
        scheme = urlsplit(str(url).strip()).scheme.lower()
        if scheme not in {"http", "https"}:
            scheme_key = "other"
            if len(other_examples) < 5:
                other_examples.append(str(url)[:80])
        else:
            scheme_key = scheme
        ssl_key = "ssl_true" if bool(ssl_value) else "ssl_false"
        table[(scheme_key, ssl_key)] += 1
        total += 1
        if (scheme_key == "https") == (ssl_key == "ssl_true"):
            agree += 1
    rate = agree / total if total else 0.0
    emit()
    emit("confusion table (scheme x SSL):")
    emit(f"{'scheme':<10}{'SSL=True':>10}{'SSL=False':>11}")
    for scheme_key in ("https", "http", "other"):
        emit(
            f"{scheme_key:<10}{table[(scheme_key, 'ssl_true')]:>10}"
            f"{table[(scheme_key, 'ssl_false')]:>11}"
        )
    for example in other_examples:
        emit(f"  non-http(s) example: {example}")
    emit(f"H1 agreement: {agree}/{total} = {rate * 100:.2f}% (bar {SSL_BAR * 100:.0f}%)")
    return {"agree": agree, "total": total, "rate": rate, "table": {str(k): v for k, v in table.items()}}


# ---------------------------------------------------------------------------
# Part C - BeautifulSoup_text extraction variants
# ---------------------------------------------------------------------------


def extract_variant(html: str, parser: str, drop_tags: bool, separator: str, collapse: bool) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, parser)
    if drop_tags:
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
    text = soup.get_text(separator)
    if collapse:
        text = " ".join(text.split())
    return text.strip()


def build_variants() -> list[tuple[str, dict]]:
    return [
        ("V1_html.parser_get_text(' ')", {"parser": "html.parser", "drop_tags": False, "separator": " ", "collapse": False}),
        ("V2_html.parser_get_text('')", {"parser": "html.parser", "drop_tags": False, "separator": "", "collapse": False}),
        ("V3_html.parser_no_tags_sep_' '", {"parser": "html.parser", "drop_tags": True, "separator": " ", "collapse": False}),
        ("V4_html.parser_no_tags_sep_' '_collapse", {"parser": "html.parser", "drop_tags": True, "separator": " ", "collapse": True}),
        ("V5_lxml_no_tags_sep_' '_collapse", {"parser": "lxml", "drop_tags": True, "separator": " ", "collapse": True}),
        ("V6_lxml_plain_sep_' '_collapse", {"parser": "lxml", "drop_tags": False, "separator": " ", "collapse": True}),
        ("V7_html.parser_get_text(' ',strip=True)", {"parser": "html.parser", "drop_tags": False, "separator": " ", "collapse": False, "strip": True}),
        ("V8_html.parser_no_tags_strip_collapse", {"parser": "html.parser", "drop_tags": True, "separator": " ", "collapse": True, "strip": True}),
        ("V9_html.parser_get_text('')+bom_lstrip", {"parser": "html.parser", "drop_tags": False, "separator": "", "collapse": False, "bom": True}),
        ("V10_html.parser_bytes_get_text('')", {"parser": "html.parser", "drop_tags": False, "separator": "", "collapse": False, "as_bytes": True}),
    ]


def extract_variant_kw(
    html: str,
    *,
    parser: str,
    drop_tags: bool,
    separator: str,
    collapse: bool,
    strip: bool = False,
    bom: bool = False,
    as_bytes: bool = False,
) -> str:
    from bs4 import BeautifulSoup

    payload = html.encode("utf-8", errors="replace") if as_bytes else html
    soup = BeautifulSoup(payload, parser)
    if drop_tags:
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
    text = soup.get_text(separator, strip=strip)
    if collapse:
        text = " ".join(text.split())
    text = text.strip()
    if bom:
        text = text.lstrip("\ufeff")
    return text


def load_tokenizer(tokenizer_dir: Path):
    from transformers import AutoTokenizer

    if tokenizer_dir is not None and tokenizer_dir.exists():
        return AutoTokenizer.from_pretrained(
            str(tokenizer_dir), local_files_only=True, revision=TOKENIZER_REVISION
        )
    from transformers import AutoTokenizer as _AT

    return _AT.from_pretrained("distilbert-base-uncased", revision=TOKENIZER_REVISION)


def ids256(tokenizer, text: str) -> list[int]:
    encoded = tokenizer(
        text,
        max_length=MAX_TOKENS,
        padding="max_length",
        truncation=True,
        return_tensors=None,
    )
    return list(encoded["input_ids"])


def run_part_c(args) -> dict:
    import pandas as pd

    df = pd.read_parquet(args.sample)
    emit()
    emit("=" * 78)
    emit("PART C - BeautifulSoup_text extraction variants")
    emit("=" * 78)
    stored_raw = ["" if pd.isna(v) else str(v) for v in df["BeautifulSoup_text"].tolist()]
    htmls = ["" if pd.isna(v) else str(v) for v in df["full_html"].tolist()]
    empty_stored = sum(1 for v in stored_raw if v.strip() == "")
    emit(f"rows={len(stored_raw)} stored null/empty={empty_stored} "
         f"({100.0 * empty_stored / len(stored_raw):.2f}%)")

    tokenizer = load_tokenizer(args.tokenizer_dir)
    emit(f"tokenizer={args.tokenizer_dir} revision={TOKENIZER_REVISION}")
    stored_tokens = [ids256(tokenizer, v.strip()) for v in stored_raw]

    results = []
    stored_stripped = [v.strip() for v in stored_raw]
    for name, kwargs in build_variants():
        variants = [extract_variant_kw(html, **kwargs) for html in htmls]
        exact = sum(1 for got, want in zip(variants, stored_raw, strict=True) if got == want)
        exact_strip = sum(
            1 for got, want in zip(variants, stored_stripped, strict=True) if got == want
        )
        tok_ok = 0
        ws_only = 0
        first_diffs: list[tuple[int, int]] = []
        examples: list[tuple[int, str, str]] = []
        for i, (got, want_raw) in enumerate(zip(variants, stored_raw, strict=True)):
            got_ids = ids256(tokenizer, got)
            want_ids = stored_tokens[i]
            if got_ids == want_ids:
                tok_ok += 1
                if got != want_raw.strip():
                    ws_only += 1
            else:
                pos = next(
                    (j for j, (a, b) in enumerate(zip(got_ids, want_ids)) if a != b),
                    min(len(got_ids), len(want_ids)),
                )
                first_diffs.append((i, pos))
                if len(examples) < 3:
                    examples.append((i, want_raw[:70], got[:70]))
        results.append(
            {
                "name": name,
                "exact": exact,
                "exact_strip": exact_strip,
                "tokens": tok_ok,
                "exact_rate": exact / len(stored_raw),
                "exact_strip_rate": exact_strip / len(stored_raw),
                "token_rate": tok_ok / len(stored_raw),
                "ws_only": ws_only,
                "first_diff_positions": first_diffs,
                "examples": examples,
            }
        )

    emit()
    emit(f"{'variant':<46}{'exact%':>9}{'exact_st%':>10}{'tokens256%':>13}{'ws_only':>9}{'tok_fail':>10}")
    for item in results:
        emit(
            f"{item['name']:<46}{100 * item['exact_rate']:>9.2f}"
            f"{100 * item['exact_strip_rate']:>10.2f}"
            f"{100 * item['token_rate']:>13.2f}{item['ws_only']:>9}"
            f"{len(item['first_diff_positions']):>10}"
        )
    best = max(results, key=lambda item: (item["token_rate"], item["exact_strip_rate"]))
    emit()
    emit(f"best variant: {best['name']} (tokens {100 * best['token_rate']:.2f}% "
         f"bar {100 * TOKENIZER_BAR:.0f}%)")
    if best["token_rate"] < TOKENIZER_BAR:
        emit("RESULT: BELOW BAR -> feature marked UNKNOWN in the spec")
    for item in results:
        for (i, pos) in item["first_diff_positions"][:4]:
            emit(f"  token mismatch {item['name']} row={i} first_diff_at={pos}")
        for (i, want, got) in item["examples"]:
            emit(
                f"  example {item['name']} row={i} stored={want!r} got={got!r}"
            )
    return {
        "stored_null_empty": empty_stored,
        "stored_null_empty_rate": empty_stored / len(stored_raw),
        "variants": [
            {k: v for k, v in item.items() if k not in {"first_diff_positions", "examples"}}
            for item in results
        ],
        "best": best["name"],
        "best_token_rate": best["token_rate"],
        "best_exact_rate": best["exact_rate"],
        "below_bar": best["token_rate"] < TOKENIZER_BAR,
    }


# ---------------------------------------------------------------------------
# Golden-sample sensitivity (SSL flip, TLD/Subdomain -> UNKNOWN)
# ---------------------------------------------------------------------------


def run_sensitivity(args) -> dict:
    import httpx
    import pandas as pd

    csv_path = Path(args.golden_dir) / "golden_samples.csv"
    df = pd.read_csv(csv_path)
    emit("=" * 78)
    emit("SENSITIVITY - golden samples: SSL flip, TLD/Subdomain -> UNKNOWN")
    emit("=" * 78)
    emit(f"golden_dir={args.golden_dir} service={args.inference_url} samples={len(df)}")

    headers = {"X-API-Key": args.api_key}
    rows_out = []
    baseline_meta_err = 0.0
    baseline_fusion_err = 0.0

    for record in df.to_dict("records"):
        idx = int(record["sample_index"])
        png_path = Path(args.golden_dir) / f"{idx}.png"
        screenshot_bytes = png_path.read_bytes()
        ssl_original = str(record["SSL"]).strip().lower() in {"1", "true", "yes"}
        tld_original = "" if pd.isna(record["TLD"]) else str(record["TLD"])
        sub_original = "" if pd.isna(record["Subdomain"]) else str(record["Subdomain"])
        url = str(record["URL"])
        text = "" if pd.isna(record["html_text"]) else str(record["html_text"])

        def call(
            ssl_val: str,
            tld_val: str,
            sub_val: str,
            url: str = url,
            text: str = text,
            idx: int = idx,
            screenshot_bytes: bytes = screenshot_bytes,
        ) -> dict:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    f"{args.inference_url.rstrip('/')}/predict",
                    headers=headers,
                    data={
                        "url": url,
                        "text": text,
                        "ssl": ssl_val,
                        "tld": tld_val,
                        "subdomain": sub_val,
                    },
                    files={"screenshot": (f"{idx}.png", screenshot_bytes, "image/png")},
                )
            response.raise_for_status()
            return response.json()

        base = call("true" if ssl_original else "false", tld_original, sub_original)
        flipped = call("false" if ssl_original else "true", tld_original, sub_original)
        unknown = call(
            "true" if ssl_original else "false", "UNKNOWN", "UNKNOWN"
        )
        if base.get("status") != "complete":
            emit(f"sample {idx}: baseline not complete: {base}")
            continue

        base_meta = base["base_probabilities"]["metadata_phishing_probability"]
        base_fusion = base["phishing_probability"]
        flipped_meta = flipped.get("base_probabilities", {}).get("metadata_phishing_probability")
        flipped_fusion = flipped.get("phishing_probability")
        unknown_meta = unknown.get("base_probabilities", {}).get("metadata_phishing_probability")
        unknown_fusion = unknown.get("phishing_probability")

        exp_meta = float(record["metadata_phishing_probability"])
        exp_fusion = float(record["fusion_mlp_phishing_probability"])
        baseline_meta_err = max(baseline_meta_err, abs(base_meta - exp_meta))
        baseline_fusion_err = max(baseline_fusion_err, abs(base_fusion - exp_fusion))

        rows_out.append(
            {
                "sample": idx,
                "ssl": int(ssl_original),
                "meta_base": base_meta,
                "meta_flip": flipped_meta,
                "d_meta_flip": None if flipped_meta is None else flipped_meta - base_meta,
                "fusion_base": base_fusion,
                "fusion_flip": flipped_fusion,
                "d_fusion_flip": None if flipped_fusion is None else flipped_fusion - base_fusion,
                "meta_unknown": unknown_meta,
                "d_meta_unknown": None if unknown_meta is None else unknown_meta - base_meta,
                "fusion_unknown": unknown_fusion,
                "d_fusion_unknown": None if unknown_fusion is None else unknown_fusion - base_fusion,
                "decision_base": base["prediction"],
                "decision_flip": flipped.get("prediction"),
                "decision_unknown": unknown.get("prediction"),
            }
        )

    emit()
    emit("baseline reproduction vs golden expected (must be <= 1e-4):")
    emit(f"  max |metadata delta| = {baseline_meta_err:.3e}")
    emit(f"  max |fusion delta|   = {baseline_fusion_err:.3e}")
    emit()
    emit(
        f"{'sample':>7}{'ssl':>5}{'meta_base':>11}{'meta_flip':>11}{'d_meta':>10}"
        f"{'fusion_base':>13}{'fusion_flip':>13}{'d_fusion':>11}"
        f"{'meta_unk':>11}{'d_unk':>10}{'fusion_unk':>13}{'d_funk':>11}"
    )
    for row in rows_out:
        emit(
            f"{row['sample']:>7}{row['ssl']:>5}"
            f"{row['meta_base']:>11.6f}"
            f"{'' if row['meta_flip'] is None else format(row['meta_flip'], '.6f'):>11}"
            f"{'' if row['d_meta_flip'] is None else format(row['d_meta_flip'], '+.6f'):>10}"
            f"{row['fusion_base']:>13.6f}"
            f"{'' if row['fusion_flip'] is None else format(row['fusion_flip'], '.6f'):>13}"
            f"{'' if row['d_fusion_flip'] is None else format(row['d_fusion_flip'], '+.6f'):>11}"
            f"{'' if row['meta_unknown'] is None else format(row['meta_unknown'], '.6f'):>11}"
            f"{'' if row['d_meta_unknown'] is None else format(row['d_meta_unknown'], '+.6f'):>10}"
            f"{'' if row['fusion_unknown'] is None else format(row['fusion_unknown'], '.6f'):>13}"
            f"{'' if row['d_fusion_unknown'] is None else format(row['d_fusion_unknown'], '+.6f'):>11}"
        )

    def stats(key: str) -> tuple[float, float]:
        values = [abs(r[key]) for r in rows_out if r[key] is not None]
        if not values:
            return (0.0, 0.0)
        return (sum(values) / len(values), max(values))

    mean_flip, max_flip = stats("d_meta_flip")
    mean_fusion_flip, max_fusion_flip = stats("d_fusion_flip")
    mean_unk, max_unk = stats("d_meta_unknown")
    mean_funk, max_funk = stats("d_fusion_unknown")
    flips_meta = sum(1 for r in rows_out if r["d_meta_flip"] and abs(r["d_meta_flip"]) > 1e-9)
    flips_fusion = sum(1 for r in rows_out if r["d_fusion_flip"] and abs(r["d_fusion_flip"]) > 1e-9)
    decision_changes_flip = sum(
        1 for r in rows_out if r["decision_flip"] not in (None, r["decision_base"])
    )
    decision_changes_unknown = sum(
        1 for r in rows_out if r["decision_unknown"] not in (None, r["decision_base"])
    )
    emit()
    emit("summary (20 golden samples):")
    emit(f"  SSL flip     : |d_metadata| mean={mean_flip:.6f} max={max_flip:.6f} "
         f"samples_changed={flips_meta}")
    emit(f"  SSL flip     : |d_fusion|   mean={mean_fusion_flip:.6f} max={max_fusion_flip:.6f} "
         f"samples_changed={flips_fusion}")
    emit(f"  SSL flip     : decision changes at 0.5 = {decision_changes_flip}/{len(rows_out)}")
    emit(f"  TLD+SUB=UNK  : |d_metadata| mean={mean_unk:.6f} max={max_unk:.6f}")
    emit(f"  TLD+SUB=UNK  : |d_fusion|   mean={mean_funk:.6f} max={max_funk:.6f}")
    emit(f"  TLD+SUB=UNK  : decision changes at 0.5 = {decision_changes_unknown}/{len(rows_out)}")
    return {
        "samples": len(rows_out),
        "baseline_max_meta_err": baseline_meta_err,
        "baseline_max_fusion_err": baseline_fusion_err,
        "ssl_flip_meta_mean_abs": mean_flip,
        "ssl_flip_meta_max_abs": max_flip,
        "ssl_flip_fusion_mean_abs": mean_fusion_flip,
        "ssl_flip_fusion_max_abs": max_fusion_flip,
        "ssl_flip_decision_changes": decision_changes_flip,
        "unknown_meta_mean_abs": mean_unk,
        "unknown_meta_max_abs": max_unk,
        "unknown_fusion_mean_abs": mean_funk,
        "unknown_fusion_max_abs": max_funk,
        "unknown_decision_changes": decision_changes_unknown,
        "rows": rows_out,
    }


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--tokenizer-dir", type=Path, default=None)
    parser.add_argument("--evidence", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--skip-text", action="store_true")
    parser.add_argument("--sensitivity", action="store_true")
    parser.add_argument("--inference-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--golden-dir", type=Path, default=DEFAULT_GOLDEN_DIR)
    args = parser.parse_args()

    if args.sensitivity:
        if args.evidence is None:
            args.evidence = DEFAULT_SENSITIVITY_EVIDENCE
        summary = {"sensitivity": run_sensitivity(args)}
    else:
        if args.evidence is None:
            args.evidence = DEFAULT_EVIDENCE
        summary = {"part_a": run_part_a(args), "part_b": run_part_b(args)}
        if not args.skip_text:
            summary["part_c"] = run_part_c(args)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        emit(f"[json written to {args.json}]")
    flush_evidence(args.evidence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
