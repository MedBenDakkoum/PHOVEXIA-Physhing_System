"""Transparent, non-DL brand policy (US19 / US55 / ISO-6.1).

The model over-flags high-traffic legitimate domains because the training data
contains every major brand only in the phishing class. This module applies a
small, fully documented rule set on top of the model output. It never erases
the model verdict: `model_verdict` / `model_score` keep the raw prediction,
while `verdict` / `score` hold the FINAL decision.

Rules (in this order):
1. OFFICIAL_BRAND_HOMEPAGE - the normalized host is exactly an active
   ProtectedBrand domain (or its "www." variant) AND the URL is the home page
   ("/" or empty path, no query, no fragment, no credentials): the final
   verdict becomes LEGITIMATE and the detection source becomes BRAND_POLICY.
2. OFFICIAL_DOMAIN_DEEP_LINK - any other URL on that official domain (or one
   of its subdomains) is NEVER auto-legitimate (open redirects exist). The
   model verdict is kept; if it is PHISHING or UNCERTAIN the scan is sent to
   the analyst queue.
3. BRAND_LOOKALIKE - on a NON-official host, find_lookalike() flags a brand
   imitation (brand + edit distance). The model verdict is kept. A LEGITIMATE
   or UNCERTAIN verdict goes to the analyst queue; the policy NEVER turns a
   scan into PHISHING.
4. Subdomains of an official domain are NOT official: only the exact domain
   and its "www." variant can trigger rule 1.

Everything here is deterministic: same URL + same active brands + same model
output always produce the same flags (no randomness, no network).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from blocklist.models import ProtectedBrand
from blocklist.services import (
    InvalidDomain,
    find_lookalike,
    normalize_domain,
)

from ..models import Scan
from .inference import VERDICT_LEGITIMATE, VERDICT_PHISHING, VERDICT_UNCERTAIN

OFFICIAL_BRAND_HOMEPAGE = "OFFICIAL_BRAND_HOMEPAGE"
OFFICIAL_DOMAIN_DEEP_LINK = "OFFICIAL_DOMAIN_DEEP_LINK"
BRAND_LOOKALIKE = "BRAND_LOOKALIKE"

_ESCALATING_VERDICTS = (VERDICT_PHISHING, VERDICT_UNCERTAIN)
_LOOKALIKE_ESCALATING_VERDICTS = (VERDICT_LEGITIMATE, VERDICT_UNCERTAIN)


@dataclass(frozen=True)
class BrandPolicyResult:
    """Final decision produced by the brand rules.

    `flags` is a JSON-serialisable list (stored on Scan.policy_flags).
    `detection_source` is the Scan.DetectionSource value to store.
    """

    verdict: str
    score: float | None
    detection_source: str
    flags: list[dict[str, Any]]
    note: str
    escalate_to_review: bool


def is_official_homepage(url: str) -> bool:
    """True for "/" or an empty path with no query/fragment/credentials."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    path = parts.path or "/"
    return (
        path == "/"
        and not parts.query
        and not parts.fragment
        and parts.username is None
        and parts.password is None
    )


def _normalize_host(host: str) -> str:
    try:
        return normalize_domain(host)
    except InvalidDomain:
        return (host or "").strip().lower().rstrip(".")


def _brand_for_official_host(
    normalized_host: str, brands: list[ProtectedBrand]
) -> ProtectedBrand | None:
    """Exact official domain or its "www." variant only (rule 4)."""
    for brand in brands:
        if normalized_host in (brand.domain, f"www.{brand.domain}"):
            return brand
    return None


def _brand_for_domain_tree(
    normalized_host: str, brands: list[ProtectedBrand]
) -> ProtectedBrand | None:
    """The official domain itself or any subdomain of it."""
    for brand in brands:
        if normalized_host == brand.domain or normalized_host.endswith(
            "." + brand.domain
        ):
            return brand
    return None


def _score_text(score: float | None) -> str:
    return f"{score:.3f}" if isinstance(score, (int, float)) else "n/a"


def apply_brand_policy(
    *,
    url: str,
    host: str,
    model_verdict: str,
    model_score: float | None,
    brands: list[ProtectedBrand] | None = None,
) -> BrandPolicyResult:
    """Apply the brand rules to one complete model result.

    `brands` may be supplied (tests / callers that already loaded them); when
    omitted the active ProtectedBrand rows are read once.
    """
    if brands is None:
        brands = list(ProtectedBrand.objects.filter(is_active=True))
    normalized_host = _normalize_host(host)

    def unchanged(flags: list[dict[str, Any]], note: str, escalate: bool):
        return BrandPolicyResult(
            verdict=model_verdict,
            score=model_score,
            detection_source=Scan.DetectionSource.MODEL,
            flags=flags,
            note=note,
            escalate_to_review=escalate,
        )

    official = _brand_for_official_host(normalized_host, brands)
    homepage = is_official_homepage(url)

    # Rule 1: official home page -> final verdict LEGITIMATE.
    if official is not None and homepage:
        return BrandPolicyResult(
            verdict=VERDICT_LEGITIMATE,
            score=model_score,
            detection_source=Scan.DetectionSource.BRAND_POLICY,
            flags=[
                {
                    "code": OFFICIAL_BRAND_HOMEPAGE,
                    "brand": official.domain,
                }
            ],
            note=(
                f"Page d'accueil officielle de la marque protégée "
                f"{official.domain} : le verdict final est forcé à Légitime. "
                f"Le modèle seul disait {model_verdict} ({_score_text(model_score)})."
            ),
            escalate_to_review=False,
        )

    # Rule 2: another URL on an official domain -> never auto-legitimate.
    on_official_domain = _brand_for_domain_tree(normalized_host, brands)
    if on_official_domain is not None:
        if model_verdict not in _ESCALATING_VERDICTS:
            return unchanged([], "", False)
        escalate = True
        return unchanged(
            [
                {
                    "code": OFFICIAL_DOMAIN_DEEP_LINK,
                    "brand": on_official_domain.domain,
                }
            ],
            (
                f"Lien profond sur le domaine officiel "
                f"{on_official_domain.domain} : le verdict du modèle "
                f"({model_verdict}) est conservé et le scan est envoyé en revue "
                f"(redirections ouvertes possibles)."
            ),
            escalate,
        )

    # Rule 3: lookalike on a non-official host -> review, never auto-phishing.
    lookalike = find_lookalike(normalized_host)
    if lookalike is not None:
        escalate = model_verdict in _LOOKALIKE_ESCALATING_VERDICTS
        return unchanged(
            [
                {
                    "code": BRAND_LOOKALIKE,
                    "brand": lookalike.brand.domain,
                    "brand_name": lookalike.brand.name,
                    "distance": lookalike.distance,
                }
            ],
            (
                f"Domaine ressemblant à la marque protégée "
                f"{lookalike.brand.name} ({lookalike.brand.domain}), "
                f"distance {lookalike.distance} : le verdict du modèle "
                f"({model_verdict}) est conservé"
                + (
                    " et le scan est envoyé en revue."
                    if escalate
                    else "."
                )
            ),
            escalate,
        )

    # No rule applied: the model decision is final and untouched.
    return unchanged([], "", False)


__all__ = [
    "BRAND_LOOKALIKE",
    "OFFICIAL_BRAND_HOMEPAGE",
    "OFFICIAL_DOMAIN_DEEP_LINK",
    "BrandPolicyResult",
    "apply_brand_policy",
    "is_official_homepage",
]
