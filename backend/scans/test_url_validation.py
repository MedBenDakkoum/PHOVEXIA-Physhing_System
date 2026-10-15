"""
BR-07 URL validation / SSRF tests for scans/services/url_validation.py (US13).

DNS is ALWAYS mocked (socket.getaddrinfo is replaced): no test touches the
network. IP-literal tests install a strict mock that fails on any lookup, to
prove literals are never resolved.
"""
import socket

import pytest

from scans.services import url_validation
from scans.services.url_validation import (
    MAX_URL_LENGTH,
    InvalidURL,
    RejectionCode,
    is_forbidden_ip,
    validate_url,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def install_dns(monkeypatch, mapping, record=None):
    """Replace getaddrinfo with a fake resolver: host -> list of addresses."""

    def fake_getaddrinfo(host, port, /, *args, **kwargs):
        if record is not None:
            record.append(host)
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        out = []
        for addr in mapping[host]:
            if ":" in addr:
                out.append(
                    (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, 0, 0, 0))
                )
            else:
                out.append(
                    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))
                )
        return out

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", fake_getaddrinfo)


def install_dns_guard(monkeypatch):
    """Fail loudly if any DNS lookup is attempted (IP literals must not resolve)."""

    def guard(*args, **kwargs):
        raise AssertionError(f"Unexpected DNS lookup: {args!r}")

    monkeypatch.setattr(url_validation.socket, "getaddrinfo", guard)


# --- Accepted URLs ---------------------------------------------------------


def test_valid_public_ipv4_url():
    result = validate_url(f"http://{PUBLIC_V4}/login")
    assert result.url == f"http://{PUBLIC_V4}/login"
    assert result.scheme == "http"
    assert result.host == PUBLIC_V4
    assert result.port is None


def test_valid_public_hostname_with_mocked_dns(monkeypatch):
    install_dns(monkeypatch, {"example.com": [PUBLIC_V4]})
    result = validate_url("https://example.com/path?q=1#frag")
    assert result.scheme == "https"
    assert result.host == "example.com"
    assert result.url == "https://example.com/path?q=1#frag"


def test_uppercase_scheme_and_host_normalized(monkeypatch):
    install_dns(monkeypatch, {"example.com": [PUBLIC_V4]})
    result = validate_url(f"HTTP://{PUBLIC_V4.upper()}:8443/Path")
    assert result.scheme == "http"
    assert result.host == PUBLIC_V4
    assert result.port == 8443


def test_trailing_dot_on_public_host_stripped(monkeypatch):
    install_dns(monkeypatch, {"example.com": [PUBLIC_V4]})
    result = validate_url("http://example.com./")
    assert result.host == "example.com"


def test_public_ipv6_url_accepted():
    result = validate_url(f"http://[{PUBLIC_V6}]/")
    assert result.host == PUBLIC_V6


def test_ipv4_mapped_public_address_accepted():
    result = validate_url("http://[::ffff:93.184.216.34]/")
    assert result.host == "::ffff:93.184.216.34"


def test_host_with_only_public_addresses_accepted(monkeypatch):
    install_dns(monkeypatch, {"mixed.example": [PUBLIC_V4, PUBLIC_V6]})
    result = validate_url("http://mixed.example/")
    assert result.host == "mixed.example"


def test_url_of_exactly_max_length_accepted(monkeypatch):
    url = "http://example.com/?" + "a" * (MAX_URL_LENGTH - len("http://example.com/?"))
    assert len(url) == MAX_URL_LENGTH
    install_dns(monkeypatch, {"example.com": [PUBLIC_V4]})
    assert validate_url(url).url == url


def test_surrounding_whitespace_is_stripped(monkeypatch):
    install_dns(monkeypatch, {"example.com": [PUBLIC_V4]})
    assert validate_url("  http://example.com/  ").url == "http://example.com/"


# --- Schemes, credentials, length, empty -----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "mailto:user@example.com",
        "gopher://example.com/",
    ],
)
def test_non_http_schemes_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.SCHEME_NOT_ALLOWED


@pytest.mark.parametrize("url", ["", "   ", None])
def test_empty_url_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.EMPTY


def test_url_longer_than_max_refused():
    url = "http://example.com/?" + "a" * MAX_URL_LENGTH
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.TOO_LONG


@pytest.mark.parametrize(
    "url",
    [
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "http://:pass@example.com/",
        "http://@example.com/",
    ],
)
def test_credentials_in_url_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.CREDENTIALS_NOT_ALLOWED


@pytest.mark.parametrize("url", ["http://", "https:///path", "http://?query=1"])
def test_empty_host_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.EMPTY_HOST


def test_host_that_is_only_a_dot_refused():
    with pytest.raises(InvalidURL) as exc:
        validate_url("http://./")
    assert exc.value.code == RejectionCode.EMPTY_HOST


@pytest.mark.parametrize("url", ["http://example.com:99999/", "http://example.com:abc/"])
def test_invalid_port_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.INVALID_SYNTAX


@pytest.mark.parametrize("url", ["http://[::1/", "http://::1/"])
def test_malformed_ipv6_refused(url):
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code in (RejectionCode.INVALID_SYNTAX, RejectionCode.EMPTY_HOST)


# --- localhost -------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://LOCALHOST/",
        "http://LocalHost:8080/",
        "http://localhost./",
        "http://LOCALHOST./",
        "http://sub.localhost/",
        "https://a.b.localhost/x",
    ],
)
def test_localhost_variants_refused_without_dns(monkeypatch, url):
    install_dns_guard(monkeypatch)
    with pytest.raises(InvalidURL) as exc:
        validate_url(url)
    assert exc.value.code == RejectionCode.BLOCKED_HOST


# --- Forbidden IP literals (no DNS) ----------------------------------------


FORBIDDEN_LITERALS = [
    # IPv4: unspecified, loopback /8, RFC1918, link-local incl. metadata IP
    "0.0.0.0",
    "127.0.0.1",
    "127.5.5.5",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.168.255.255",
    "169.254.0.1",
    "169.254.169.254",
    # CGNAT 100.64.0.0/10 (explicit: not always is_private)
    "100.64.0.1",
    "100.127.255.255",
    # multicast + reserved + broadcast
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
]


@pytest.mark.parametrize("ip", FORBIDDEN_LITERALS)
def test_forbidden_ipv4_literals_refused_without_dns(monkeypatch, ip):
    install_dns_guard(monkeypatch)
    with pytest.raises(InvalidURL) as exc:
        validate_url(f"http://{ip}/")
    assert exc.value.code == RejectionCode.FORBIDDEN_ADDRESS


FORBIDDEN_IPV6 = [
    "::1",  # loopback
    "::",  # unspecified
    "fc00::1",  # unique-local fc00::/7
    "fd12:3456::1",  # unique-local
    "fe80::1",  # link-local fe80::/10
    "ff02::1",  # multicast
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
    "::ffff:169.254.169.254",  # IPv4-mapped metadata IP
    "::ffff:7f00:1",  # same, hex form
]


@pytest.mark.parametrize("ip", FORBIDDEN_IPV6)
def test_forbidden_ipv6_literals_refused_without_dns(monkeypatch, ip):
    install_dns_guard(monkeypatch)
    with pytest.raises(InvalidURL) as exc:
        validate_url(f"http://[{ip}]/")
    assert exc.value.code == RejectionCode.FORBIDDEN_ADDRESS


def test_address_just_outside_cgnat_accepted():
    assert validate_url("http://100.128.0.1/").host == "100.128.0.1"


# --- IP literals in decimal / hex / octal (OS resolver semantics) ----------


@pytest.mark.parametrize(
    ("host", "resolves_to"),
    [
        ("2130706433", ["127.0.0.1"]),  # decimal for 127.0.0.1
        ("3232235777", ["192.168.1.1"]),  # decimal for 192.168.1.1
        ("0x7f000001", ["127.0.0.1"]),  # hex for 127.0.0.1
        ("0x7f.1", ["127.0.0.1"]),  # hex octets
        ("0177.0.0.1", ["127.0.0.1"]),  # octal
        ("0", ["0.0.0.0"]),
    ],
)
def test_decimal_hex_octal_ip_literals_refused_via_dns(monkeypatch, host, resolves_to):
    # The OS inet resolver (getaddrinfo) interprets these numeric forms;
    # the fake simulates that behaviour, then BR-07 refuses the address.
    install_dns(monkeypatch, {host: resolves_to})
    with pytest.raises(InvalidURL) as exc:
        validate_url(f"http://{host}/")
    assert exc.value.code == RejectionCode.FORBIDDEN_ADDRESS


# --- Hostnames where ANY address is forbidden ------------------------------


@pytest.mark.parametrize(
    "addresses",
    [
        [PUBLIC_V4, "127.0.0.1"],
        ["127.0.0.1", PUBLIC_V4],
        ["10.0.0.5", PUBLIC_V4],
        [PUBLIC_V4, "169.254.169.254"],
        [PUBLIC_V4, "::1"],
        [PUBLIC_V4, "fe80::1"],
        [PUBLIC_V4, "100.64.0.1"],
        ["224.0.0.1", PUBLIC_V4],
    ],
)
def test_hostname_resolving_to_any_forbidden_address_refused(monkeypatch, addresses):
    install_dns(monkeypatch, {"evil.example": addresses})
    with pytest.raises(InvalidURL) as exc:
        validate_url("http://evil.example/")
    assert exc.value.code == RejectionCode.FORBIDDEN_ADDRESS


# --- DNS failures ----------------------------------------------------------


def test_dns_failure_refused(monkeypatch):
    install_dns(monkeypatch, {})  # every host -> gaierror
    with pytest.raises(InvalidURL) as exc:
        validate_url("http://unknown-host.example/")
    assert exc.value.code == RejectionCode.DNS_FAILURE


def test_empty_dns_answer_refused(monkeypatch):
    install_dns(monkeypatch, {"empty.example": []})
    with pytest.raises(InvalidURL) as exc:
        validate_url("http://empty.example/")
    assert exc.value.code == RejectionCode.DNS_FAILURE


def test_dns_returning_non_ip_answer_refused(monkeypatch):
    # Defensive: a resolver answer that is not a parseable IP is a failure.
    install_dns(monkeypatch, {"weird.example": ["not-an-ip"]})
    with pytest.raises(InvalidURL) as exc:
        validate_url("http://weird.example/")
    assert exc.value.code == RejectionCode.DNS_FAILURE


# --- is_forbidden_ip unit checks (real Python 3.14 semantics, no DNS) ------


@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
    ],
)
def test_is_forbidden_ip_true(ip):
    assert is_forbidden_ip(__import__("ipaddress").ip_address(ip)) is True


@pytest.mark.parametrize(
    "ip",
    [PUBLIC_V4, "8.8.8.8", "100.128.0.1", PUBLIC_V6, "::ffff:93.184.216.34"],
)
def test_is_forbidden_ip_false(ip):
    assert is_forbidden_ip(__import__("ipaddress").ip_address(ip)) is False
