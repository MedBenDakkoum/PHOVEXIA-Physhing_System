"""BR-07 URL validation, mirrored from backend/scans/services/url_validation.py.

The collector validates at submission time (validate_url) and the forward
proxy re-validates at connection time (resolve_addresses), which is what
defends against DNS rebinding and forbidden redirect hops (spec v1 section 4).
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
DNS_TIMEOUT_SECONDS = 3.0

# 100.64.0.0/10 (CGNAT): not flagged by is_private on every Python version.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class RejectionCode(str, Enum):
    """Stable machine-readable rejection codes (same values as the backend)."""

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

    def __init__(self, code: RejectionCode) -> None:
        self.code = code
        super().__init__(code.value)


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
    """True when the address must never be fetched (BR-07, spec v1 section 4)."""
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

    socket.getaddrinfo() has no timeout, so it runs in one worker thread and
    the result is awaited with a time budget (same approach as the backend).
    """
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="collector-dns")
    try:
        future = pool.submit(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
        try:
            infos = future.result(timeout=DNS_TIMEOUT_SECONDS)
        except FuturesTimeoutError as exc:
            raise DNSTimeoutError(
                f"DNS resolution of {host} exceeded {DNS_TIMEOUT_SECONDS} seconds"
            ) from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    return addresses


def resolve_addresses(host: str, allow_private: frozenset[str] = frozenset()) -> list[str]:
    """Resolve host and enforce the forbidden-range rules; return usable addresses.

    `allow_private` (test-only hostnames, refused at startup when
    COLLECTOR_ENV=production) skips the range check for its members. Raises
    InvalidURL with dns_failure / dns_timeout / forbidden_address.
    """
    literal = _parse_ip(host)
    if literal is not None:
        if is_forbidden_ip(literal) and host not in allow_private:
            raise InvalidURL(RejectionCode.FORBIDDEN_ADDRESS)
        return [str(literal)]
    try:
        addresses = _resolve_host(host)
    except DNSTimeoutError as exc:
        raise InvalidURL(RejectionCode.DNS_TIMEOUT) from exc
    except OSError as exc:
        raise InvalidURL(RejectionCode.DNS_FAILURE) from exc
    if not addresses:
        raise InvalidURL(RejectionCode.DNS_FAILURE)
    if host in allow_private:
        return addresses
    for addr in addresses:
        parsed = _parse_ip(addr)
        if parsed is None:
            raise InvalidURL(RejectionCode.DNS_FAILURE)
        if is_forbidden_ip(parsed):
            raise InvalidURL(RejectionCode.FORBIDDEN_ADDRESS)
    return addresses


def validate_url(url: str | None, allow_private: frozenset[str] = frozenset()) -> ValidatedURL:
    """Validate a URL for collection (BR-07); raise InvalidURL with a RejectionCode."""
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

    resolve_addresses(host, allow_private)
    return ValidatedURL(url=url, scheme=scheme, host=host, port=port)
