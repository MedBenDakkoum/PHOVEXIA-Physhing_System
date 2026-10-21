"""Blocklist and protected-brands business logic (US38-US41, US55 / BR-03, BR-12).

Everything that is not a pure HTTP concern lives here:
- domain normalization (lowercase, IDNA/punycode, no trailing dot, valid
  hostname, never an IP address),
- BR-03: only ONE active entry per domain (conditional UniqueConstraint),
- BR-07 pipeline hook (US41): after validate_url and BEFORE queueing, a
  blocked domain gets an immediate PHISHING verdict (score 1.0,
  detection_source=BLOCKLIST) through the BR-04 graph, with NO Celery task,
- BR-12: removing an entry REQUIRES a reason (soft delete),
- CSV export helpers with CSV-injection protection,
- find_lookalike(): pure-Python homoglyph + Levenshtein lookalike check
  (US19 groundwork, no new library).
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import record
from scans.models import Scan
from scans.services.workflows import change_status

from .models import BlocklistEntry, ProtectedBrand

# Hostname: labels of 1-63 chars (letters, digits, hyphen; no leading/trailing
# hyphen), 2 to 63 total, TLD at least 2 chars. ASCII form only (after IDNA).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)

_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@")


class InvalidDomain(ValueError):
    """The value cannot be a blocklist/brand domain."""


def normalize_domain(raw: str) -> str:
    """Normalize a domain for storage and comparison.

    lowercase -> strip -> IDNA/punycode -> strip trailing dot -> hostname
    validation -> refuse IP addresses (v4, v6, IPv4-mapped).
    Raises InvalidDomain with a safe, machine-readable message.
    """
    if raw is None:
        raise InvalidDomain("empty")
    value = str(raw).strip().lower()
    if not value:
        raise InvalidDomain("empty")
    if len(value) > 253:
        raise InvalidDomain("too_long")
    value = value.rstrip(".")
    if not value:
        raise InvalidDomain("empty")
    # Unicode -> ASCII punycode (already-ASCII domains pass through unchanged).
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("invalid_syntax") from exc
    # Refuse any IP literal form before hostname validation.
    try:
        ipaddress.ip_address(ascii_value)
    except ValueError:
        pass  # not an IP: normal hostname path
    else:
        raise InvalidDomain("ip_address")
    if not _HOSTNAME_RE.match(ascii_value):
        raise InvalidDomain("invalid_syntax")
    return ascii_value


def is_blocked(domain: str) -> BlocklistEntry | None:
    """US41 - the domain itself or any parent domain, active entries only.

    `sub.evil.com` matches an active entry for `sub.evil.com` OR `evil.com`.
    A malformed domain never matches (it cannot have been stored).
    """
    try:
        normalized = normalize_domain(domain)
    except InvalidDomain:
        return None
    labels = normalized.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels))]
    return (
        BlocklistEntry.objects.filter(domain__in=candidates, is_active=True)
        .order_by("domain")
        .first()
    )


def apply_blocked_verdict(scan: Scan) -> Scan:
    """US41 - stamp the immediate verdict and walk SUBMITTED->ANALYZING->DETECTED.

    Called INSIDE the caller's transaction, AFTER the Scan row exists and the
    audit entry is written, and instead of enqueueing a Celery task. The
    transitions go through the BR-04 graph so the audit trail is identical to
    a normal run (actor = system = None).
    """
    scan.verdict = "phishing"
    scan.score = 1.0
    scan.detection_source = Scan.DetectionSource.BLOCKLIST
    scan.save(update_fields=["verdict", "score", "detection_source", "updated_at"])
    change_status(scan, Scan.Status.ANALYZING, actor=None)
    change_status(scan, Scan.Status.DETECTED, actor=None)
    return scan


@dataclass(frozen=True)
class AddResult:
    """Outcome of add_entry(): the row, or None when BR-03 refused a duplicate."""

    entry: BlocklistEntry | None


def add_entry(
    *,
    domain: str,
    reason: str,
    note: str = "",
    added_by,
    source_scan: Scan | None = None,
    request=None,
) -> AddResult:
    """US38 / BR-03 - add a domain to the blocklist.

    Normalizes the domain, refuses a second ACTIVE entry for the same domain
    (returns entry=None so the caller decides 409 vs silent skip) and writes
    the immutable `blocklist.added` audit entry.
    """
    normalized = normalize_domain(domain)
    with transaction.atomic():
        if BlocklistEntry.objects.filter(domain=normalized, is_active=True).exists():
            return AddResult(None)
        try:
            entry = BlocklistEntry.objects.create(
                domain=normalized,
                reason=reason,
                note=note or "",
                added_by=added_by,
                source_scan=source_scan,
            )
        except IntegrityError:
            # Concurrent insert won the conditional unique constraint.
            return AddResult(None)
        record(
            AuditLog.Action.BLOCKLIST_ADDED,
            request=request,
            user=added_by,
            target=entry,
            metadata={"domain": normalized, "reason": reason},
        )
    return AddResult(entry)


def remove_entry(*, entry: BlocklistEntry, reason: str, removed_by, request=None) -> BlocklistEntry:
    """US39 / BR-12 - soft delete. `reason` is REQUIRED and non-blank."""
    cleaned = (reason or "").strip()
    if not cleaned:
        raise InvalidDomain("removal_reason_required")
    with transaction.atomic():
        locked = BlocklistEntry.objects.select_for_update().get(pk=entry.pk)
        if not locked.is_active:
            return locked  # idempotent: already removed
        locked.is_active = False
        locked.removed_by = removed_by
        locked.removed_at = timezone.now()
        locked.removal_reason = cleaned
        locked.save(
            update_fields=["is_active", "removed_by", "removed_at", "removal_reason"]
        )
        record(
            AuditLog.Action.BLOCKLIST_REMOVED,
            request=request,
            user=removed_by,
            target=locked,
            metadata={"domain": locked.domain, "reason": cleaned},
        )
    return locked


def csv_safe(value: object) -> str:
    """US40 - CSV-injection protection: a cell starting with = + - @ or a
    leading tab/CR gets a leading apostrophe so Excel/LibreOffice never
    interprets it as a formula."""
    text = "" if value is None else str(value)
    if text[:1] in _CSV_DANGEROUS_PREFIXES or text[:1] in ("\t", "\r"):
        return "'" + text
    return text


def export_rows(entries):
    """US40 - yield one CSV row per entry (header first). Injection-safe."""
    yield ["domain", "reason", "note", "added_by", "created_at"]
    for entry in entries:
        yield [
            csv_safe(entry.domain),
            csv_safe(entry.reason),
            csv_safe(entry.note),
            csv_safe(entry.added_by.email if entry.added_by else ""),
            csv_safe(entry.created_at.isoformat() if entry.created_at else ""),
        ]


def write_csv(stream, entries) -> None:
    """US40 - stream a CSV file of active entries into `stream`."""
    writer = csv.writer(stream)
    for row in export_rows(entries):
        writer.writerow(row)


# --- Lookalike detection (US19 groundwork, pure Python, no new library) -----

# Order matters: multi-character folds first so "rn" becomes "m" before the
# single-character folds could touch the "n".
_HOMOGLYPHS: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "i"),
    ("l", "i"),
)

LOOKALIKE_MAX_DISTANCE = 2
LOOKALIKE_MIN_LENGTH = 5


def homoglyph_fold(value: str) -> str:
    """Fold common homoglyphs so paypa1.com and paypal.com compare equal."""
    folded = value
    for source, target in _HOMOGLYPHS:
        folded = folded.replace(source, target)
    return folded


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert / delete / substitute), O(len(a)*len(b))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,       # deletion
                    current[j - 1] + 1,    # insertion
                    previous[j - 1] + (ca != cb),  # substitution
                )
            )
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class Lookalike:
    brand: ProtectedBrand
    distance: int
    reason: str


def find_lookalike(domain: str) -> Lookalike | None:
    """US19 groundwork - (brand, distance, reason) or None.

    Pure Python: homoglyph fold + Levenshtein. An exact brand domain or a
    subdomain of it is NEVER a lookalike. Otherwise the folded candidate is
    compared to every active brand domain; a distance <= 2 on strings of 5+
    characters is a hit. `reason` is "homoglyph" when the fold alone explains
    the match, else "edit_distance".
    """
    try:
        normalized = normalize_domain(domain)
    except InvalidDomain:
        return None
    if len(normalized) < LOOKALIKE_MIN_LENGTH:
        return None
    folded = homoglyph_fold(normalized)
    best: Lookalike | None = None
    for brand in ProtectedBrand.objects.filter(is_active=True):
        # Exact brand domain or its subdomain: legitimate, not a lookalike.
        if normalized == brand.domain or normalized.endswith("." + brand.domain):
            continue
        brand_folded = homoglyph_fold(brand.domain)
        if len(brand_folded) < LOOKALIKE_MIN_LENGTH:
            continue
        distance = levenshtein(folded, brand_folded)
        if distance > LOOKALIKE_MAX_DISTANCE:
            continue
        reason = "homoglyph" if folded != normalized and distance == 0 else "edit_distance"
        candidate = Lookalike(brand=brand, distance=distance, reason=reason)
        if best is None or candidate.distance < best.distance:
            best = candidate
    return best


__all__ = [
    "AddResult",
    "InvalidDomain",
    "Lookalike",
    "add_entry",
    "apply_blocked_verdict",
    "csv_safe",
    "export_rows",
    "find_lookalike",
    "homoglyph_fold",
    "is_blocked",
    "levenshtein",
    "normalize_domain",
    "remove_entry",
    "write_csv",
]
