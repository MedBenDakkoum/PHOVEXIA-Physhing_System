"""
BR-07 URL validation with SSRF protection (US13).

The validator is the gate at scan-submission time. It is NOT enough on its
own for live fetching: the crawler must re-check the resolved address at
connection time (DNS rebinding) and after every redirect — see docs/HANDOFF.md.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Time budget for ONE hostname resolution (Step 7 / US16): the API must never
# hang on a dead DNS server. socket.getaddrinfo() has no timeout parameter,
# so the lookup runs in a worker thread with this budget.
DNS_TIMEOUT_SECONDS = 3.0

# 100.64.0.0/10 (CGNAT / shared address space): not flagged by
# ipaddress.is_private on every Python version, checked explicitly.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class RejectionCode(StrEnum):
    EMPTY = "empty"
    TOO_LONG = "too_long"
    INVALID_SYNTAX = "invalid_syntax"
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    CREDENTIALS_NOT_ALLOWED = "credentials_not_allowed"
    EMPTY_HOST = "empty_host"
    BLOCKED_HOST = "blocked_host"
    FORBIDDEN_ADDRESS = "forbidden_address"
    DNS_FAILURE = "dns_failure"
    DNS_TIMEOUT = "dns_timeout"


class InvalidURL(Exception):
    """Raised when a URL fails BR-07 validation."""

    def __init__(self, code: RejectionCode):
        self.code = code
        super().__init__(str(code))


class DNSTimeoutError(Exception):
    """Raised when the DNS lookup exceeds DNS_TIMEOUT_SECONDS."""


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    scheme: str
    host: str
    port: int | None


def is_forbidden_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """
    True when the address must never be fetched (BR-07).

    Covers loopback, private (RFC 1918 + ULA fc00::/7), link-local
    (169.254.0.0/16 incl. 169.254.169.254, fe80::/10), multicast, reserved,
    unspecified (0.0.0.0, ::), IPv4-mapped IPv6 (::ffff:a.b.c.d is checked
    as a.b.c.d) and CGNAT 100.64.0.0/10 (explicit: not always is_private).
    """
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True
    return address.version == 4 and address in _CGNAT_NETWORK


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _resolve_host(host: str) -> list[str]:
    """Resolve host to every address (A + AAAA), bounded by DNS_TIMEOUT_SECONDS.

    Mocked in tests (socket.getaddrinfo is replaced). getaddrinfo() cannot be
    interrupted, so it runs in a single worker thread and the result is awaited
    with a time budget: on expiry DNSTimeoutError is raised and the pool is
    shut down without waiting, the worker finishing in the background.
    The worker is never given a hostname that would be fetched: its result is
    only read here.
    """
    budget = DNS_TIMEOUT_SECONDS
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="url-dns")
    try:
        future = pool.submit(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
        try:
            infos = future.result(timeout=budget)
        except FuturesTimeoutError as exc:
            raise DNSTimeoutError(
                f"DNS resolution of {host} exceeded {budget} seconds"
            ) from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    return addresses


def validate_url(url: str | None) -> ValidatedURL:
    """
    Validate a URL for scanning (BR-07). Returns the normalized URL or
    raises InvalidURL with a machine-readable RejectionCode.

    Refuses: non-http(s) schemes, > 2048 chars, credentials in the URL,
    empty host, "localhost" (any case, with or without trailing dot, and
    *.localhost), IP literals that are loopback/private/link-local/reserved/
    multicast/unspecified/CGNAT (IPv4 and IPv6, incl. IPv4-mapped IPv6),
    hostnames where ANY resolved address is forbidden, DNS failures and DNS
    resolutions slower than DNS_TIMEOUT_SECONDS (code dns_timeout).
    """
    if url is None or not url.strip():
        raise InvalidURL(RejectionCode.EMPTY)
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL(RejectionCode.TOO_LONG)
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidURL(RejectionCode.INVALID_SYNTAX) from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(RejectionCode.SCHEME_NOT_ALLOWED)

    if parts.username is not None or parts.password is not None:
        raise InvalidURL(RejectionCode.CREDENTIALS_NOT_ALLOWED)

    try:
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidURL(RejectionCode.INVALID_SYNTAX) from exc
    if not host:
        raise InvalidURL(RejectionCode.EMPTY_HOST)

    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
        if not host:
            raise InvalidURL(RejectionCode.EMPTY_HOST)
    if host == "localhost" or host.endswith(".localhost"):
        raise InvalidURL(RejectionCode.BLOCKED_HOST)

    literal = _parse_ip(host)
    if literal is not None:
        if is_forbidden_ip(literal):
            raise InvalidURL(RejectionCode.FORBIDDEN_ADDRESS)
        return ValidatedURL(url=url, scheme=scheme, host=host, port=port)

    try:
        addresses = _resolve_host(host)
    except DNSTimeoutError as exc:
        raise InvalidURL(RejectionCode.DNS_TIMEOUT) from exc
    except OSError as exc:
        raise InvalidURL(RejectionCode.DNS_FAILURE) from exc
    if not addresses:
        raise InvalidURL(RejectionCode.DNS_FAILURE)
    for addr in addresses:
        parsed = _parse_ip(addr)
        if parsed is None:
            raise InvalidURL(RejectionCode.DNS_FAILURE)
        if is_forbidden_ip(parsed):
            raise InvalidURL(RejectionCode.FORBIDDEN_ADDRESS)
    return ValidatedURL(url=url, scheme=scheme, host=host, port=port)
