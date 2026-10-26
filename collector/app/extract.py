"""Feature rules A/B/C for the metadata branch (spec v1 sections 1, 2 and 3)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract
from bs4 import BeautifulSoup

# Frozen bundled PSL, private domains ON, NEVER a network call (spec v1 1.1).
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


@dataclass(frozen=True)
class UrlFeatures:
    ssl: int
    tld: str | None
    domain: str | None
    fld: str | None
    subdomain: str | None


def extract_text(html: str) -> str:
    """Chosen variant V9 class: tags kept, separator "", strip, BOM stripped."""
    return BeautifulSoup(html, "html.parser").get_text("").strip().lstrip("\ufeff")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def url_features(url: str) -> UrlFeatures:
    """Rule v1 on the final URL: SSL = scheme is https; IP hosts = all missing."""
    parts = urlsplit(url)
    ssl_flag = 1 if parts.scheme.lower() == "https" else 0
    host = parts.hostname
    if not host:
        return UrlFeatures(ssl=ssl_flag, tld=None, domain=None, fld=None, subdomain=None)
    host = host.lower().rstrip(".")
    if _is_ip_literal(host):
        return UrlFeatures(ssl=ssl_flag, tld=None, domain=None, fld=None, subdomain=None)
    extracted = _EXTRACTOR(host)
    domain = extracted.domain
    suffix = extracted.suffix
    fld = f"{domain}.{suffix}" if domain and suffix else ""
    return UrlFeatures(
        ssl=ssl_flag,
        tld=suffix,
        domain=domain,
        fld=fld,
        subdomain=extracted.subdomain,
    )
