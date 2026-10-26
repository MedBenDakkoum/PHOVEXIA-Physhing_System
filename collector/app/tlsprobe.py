"""Out-of-band TLS probe: the proxy tunnels without MITM (spec v1 section 5.6)."""
from __future__ import annotations

import asyncio
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any

PROBE_TIMEOUT_S = 3.0
_SOCKET_TIMEOUT_S = 3.0
_NOT_AFTER_FORMAT = "%b %d %H:%M:%S %Y %Z"


def empty_info(error: str | None) -> dict[str, Any]:
    """The tls block shape with nothing measured (error says why)."""
    return {
        "ok": False,
        "error": error,
        "subject": None,
        "issuer": None,
        "not_after": None,
        "days_remaining": None,
        "self_signed": None,
    }


def _classify(exc: BaseException) -> str:
    """Class-level error strings only; never the raw exception text."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "cert_verification_failed"
    if isinstance(exc, ssl.SSLError):
        return "ssl_error"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, OSError):
        return "connection_error"
    return "unknown_error"


def _format_name(name: Any) -> str:
    parts = []
    for rdn in name or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _cert_info(cert: dict[str, Any]) -> dict[str, Any]:
    subject = _format_name(cert.get("subject"))
    issuer = _format_name(cert.get("issuer"))
    not_after = None
    days_remaining = None
    raw_not_after = cert.get("notAfter")
    if raw_not_after:
        expiry = datetime.strptime(str(raw_not_after), _NOT_AFTER_FORMAT).replace(
            tzinfo=timezone.utc
        )
        not_after = expiry.isoformat().replace("+00:00", "Z")
        days_remaining = (expiry - datetime.now(timezone.utc)).days
    return {
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "self_signed": bool(subject) and subject == issuer,
    }


def _connect(address: str, port: int, context: ssl.SSLContext, hostname: str) -> socket.socket:
    raw = socket.create_connection((address, port), timeout=_SOCKET_TIMEOUT_S)
    try:
        raw.settimeout(_SOCKET_TIMEOUT_S)
        return context.wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def _decode_der(der: bytes) -> dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        return ssl._ssl._test_decode_cert(path)
    finally:
        if path is not None:
            os.unlink(path)


def _probe_blocking(address: str, hostname: str, port: int) -> dict[str, Any]:
    info = empty_info(None)
    try:
        verified_context = ssl.create_default_context()
        with _connect(address, port, verified_context, hostname) as sock:
            cert = sock.getpeercert()
        info["ok"] = True
        info.update(_cert_info(cert or {}))
        return info
    except ssl.SSLCertVerificationError:
        info["error"] = "cert_verification_failed"
    except (ssl.SSLError, OSError, ValueError, TypeError) as exc:
        info["error"] = _classify(exc)
        return info
    try:
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        with _connect(address, port, unverified, hostname) as sock:
            der = sock.getpeercert(binary_form=True)
        if der:
            info.update(_cert_info(_decode_der(der)))
    except (ssl.SSLError, OSError, ValueError, TypeError) as exc:
        info["error"] = info["error"] or _classify(exc)
    return info


async def probe_tls(address: str, hostname: str, port: int) -> dict[str, Any]:
    """Probe the validated IP with SNI = hostname; never raises (spec v1 5.6)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_probe_blocking, address, hostname, port),
            PROBE_TIMEOUT_S,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return empty_info("timeout")
