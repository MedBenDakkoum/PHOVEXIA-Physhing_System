"""In-process forward proxy enforcing BR-07 at connection time (spec v1 section 4).

Chromium sends every request here: the proxy resolves the hostname itself,
refuses forbidden addresses (recording the refusal for reason mapping), and
opens the socket to the validated IP only. HTTPS is relayed as a raw CONNECT
tunnel, so SNI stays correct and no certificate is ever intercepted.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Iterable
from urllib.parse import urlsplit

from . import urlrules
from .config import Settings

logger = logging.getLogger("collector.proxy")

IDLE_TIMEOUT_S = 30.0
CONNECT_TIMEOUT_S = 10.0
MAX_HEAD_BYTES = 65536
_READ_CHUNK = 8192
_WRITE_CHUNK = 65536
_HOP_BY_HOP_DROP = frozenset(
    {
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
    }
)
_FORBIDDEN_CODES = (
    urlrules.RejectionCode.FORBIDDEN_ADDRESS,
    urlrules.RejectionCode.BLOCKED_HOST,
)


class ForwardProxy:
    """Loopback-only HTTP/CONNECT proxy; one instance per collector process."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.refusals: deque[str] = deque(maxlen=256)
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, "127.0.0.1", self.settings.proxy_port
        )
        logger.info("forward proxy listening on 127.0.0.1:%d", self.settings.proxy_port)

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    def pop_refusal(self, hosts: Iterable[str]) -> bool:
        """True when one of `hosts` was refused here; matched entries are consumed."""
        wanted = {host.lower().rstrip(".") for host in hosts if host}
        found = False
        kept: deque[str] = deque(maxlen=256)
        for refused in self.refusals:
            if refused in wanted:
                found = True
            else:
                kept.append(refused)
        self.refusals = kept
        return found

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await _read_head(reader)
            if head is None:
                return
            head_bytes, rest = head
            lines = head_bytes.split(b"\r\n")
            parts = lines[0].decode("latin-1").split(" ")
            if len(parts) != 3:
                await _write(writer, _error_response(400, "Bad Request"))
                return
            method, target, version = parts
            headers = _parse_headers(lines[1:])
            if method.upper() == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_plain(
                    reader, writer, method, target, version, headers, rest
                )
        except asyncio.CancelledError:
            raise
        except ConnectionError:
            logger.debug("client connection ended early")
        except Exception:
            logger.debug("proxy request failed", exc_info=True)
        finally:
            await _close(writer)

    async def _handle_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str
    ) -> None:
        try:
            host, port = _split_authority(target)
        except ValueError:
            await _write(writer, _error_response(400, "Bad Request"))
            return
        dialed = await self._dial(host, port, writer)
        if dialed is None:
            return
        up_reader, up_writer = dialed
        tunnel_tasks: list[asyncio.Task[None]] = []
        try:
            await _write(writer, b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunnel_tasks = [
                asyncio.create_task(_pump(reader, up_writer)),
                asyncio.create_task(_pump(up_reader, writer)),
            ]
            await asyncio.wait(tunnel_tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tunnel_tasks:
                task.cancel()
            if tunnel_tasks:
                await asyncio.gather(*tunnel_tasks, return_exceptions=True)
            await _close(up_writer)

    async def _handle_plain(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
        rest: bytes,
    ) -> None:
        origin = _origin_from(target, headers)
        if origin is None:
            await _write(writer, _error_response(400, "Bad Request"))
            return
        host, port, path = origin
        dialed = await self._dial(host, port, writer)
        if dialed is None:
            return
        up_reader, up_writer = dialed
        try:
            await _write(up_writer, _build_request_head(method, path, version, headers))
            await _forward_request_body(headers, rest, reader, up_writer)
            await _relay_response(up_reader, writer)
        finally:
            await _close(up_writer)

    async def _dial(
        self, host: str, port: int, client_writer: asyncio.StreamWriter
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Resolve + enforce ranges + connect to the first validated (pinned) IP."""
        try:
            addresses = urlrules.resolve_addresses(
                host, self.settings.allow_private_hosts
            )
        except urlrules.InvalidURL as exc:
            if exc.code in _FORBIDDEN_CODES:
                self.refusals.append(host.lower().rstrip("."))
                logger.warning("refused forbidden address %s (%s)", host, exc.code.value)
                await _write(client_writer, _error_response(403, "Forbidden"))
            else:
                logger.warning("resolution failed for %s (%s)", host, exc.code.value)
                await _write(client_writer, _error_response(502, "Bad Gateway"))
            return None
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(addresses[0], port),
                timeout=CONNECT_TIMEOUT_S,
            )
        except (OSError, asyncio.TimeoutError):
            logger.warning("upstream connection to %s failed", host)
            await _write(client_writer, _error_response(502, "Bad Gateway"))
            return None
        return up_reader, up_writer


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(reader.read(_WRITE_CHUNK), IDLE_TIMEOUT_S)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        raise
    except (ConnectionError, asyncio.TimeoutError):
        logger.debug("proxy pump stopped")


async def _read_head(reader: asyncio.StreamReader) -> tuple[bytes, bytes] | None:
    """Read up to and including CRLFCRLF; return (head, bytes_read_past_head)."""
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEAD_BYTES:
            return None
        data = await asyncio.wait_for(reader.read(_READ_CHUNK), IDLE_TIMEOUT_S)
        if not data:
            return None
        buffer += data
    head, rest = buffer.split(b"\r\n\r\n", 1)
    return head, rest


async def _write(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except ConnectionError:
        pass


def _error_response(status: int, reason: str) -> bytes:
    body = reason.encode("ascii")
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def _split_authority(authority: str) -> tuple[str, int]:
    parts = urlsplit("//" + authority)
    host = parts.hostname
    if not host:
        raise ValueError("missing host in authority")
    return host.lower().rstrip("."), parts.port or 443


def _parse_headers(lines: list[bytes]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for raw in lines:
        if not raw:
            continue
        name, sep, value = raw.decode("latin-1").partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
    return headers


def _header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    for header_name, value in headers:
        if header_name.lower() == name:
            return value
    return None


def _header_int(headers: list[tuple[str, str]], name: str) -> int | None:
    value = _header_value(headers, name)
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _origin_from(
    target: str, headers: list[tuple[str, str]]
) -> tuple[str, int, str] | None:
    """Host, port and origin-form path for an absolute-form (or origin-form) target."""
    try:
        parts = urlsplit(target)
        scheme = parts.scheme.lower()
        if scheme == "http":
            host = parts.hostname
            port = parts.port or 80
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
        elif scheme:
            return None
        else:
            authority = _header_value(headers, "host") or ""
            host_parts = urlsplit("//" + authority)
            host = host_parts.hostname
            port = host_parts.port or 80
            path = target
    except ValueError:
        return None
    if not host:
        return None
    return host.lower().rstrip("."), port, path


def _build_request_head(
    method: str, path: str, version: str, headers: list[tuple[str, str]]
) -> bytes:
    """Origin-form request head; hop-by-hop headers dropped, Connection: close set."""
    lines = [f"{method} {path} {version}"]
    for name, value in headers:
        lowered = name.lower()
        if lowered in _HOP_BY_HOP_DROP or lowered == "connection":
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    lines.append("")
    return ("\r\n".join(lines) + "\r\n").encode("latin-1")


async def _forward_request_body(
    headers: list[tuple[str, str]],
    rest: bytes,
    reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    content_length = _header_int(headers, "content-length")
    transfer_encoding = (_header_value(headers, "transfer-encoding") or "").lower()
    if content_length is not None:
        if rest:
            up_writer.write(rest)
            await up_writer.drain()
        remaining = content_length - len(rest)
        while remaining > 0:
            data = await asyncio.wait_for(
                reader.read(min(_WRITE_CHUNK, remaining)), IDLE_TIMEOUT_S
            )
            if not data:
                break
            up_writer.write(data)
            remaining -= len(data)
            await up_writer.drain()
        return
    if "chunked" in transfer_encoding:
        await _relay_chunks(reader, up_writer, rest)
        return
    if rest:
        up_writer.write(rest)
        await up_writer.drain()


async def _relay_chunks(
    source: asyncio.StreamReader,
    sink: asyncio.StreamWriter,
    buffer: bytes,
) -> None:
    """Forward a chunked body verbatim until the terminating chunk."""
    while True:
        while b"\r\n" not in buffer:
            data = await asyncio.wait_for(source.read(_READ_CHUNK), IDLE_TIMEOUT_S)
            if not data:
                return
            buffer += data
        size_line, buffer = buffer.split(b"\r\n", 1)
        sink.write(size_line + b"\r\n")
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            return
        need = size + 2
        while len(buffer) < need:
            data = await asyncio.wait_for(source.read(_READ_CHUNK), IDLE_TIMEOUT_S)
            if not data:
                return
            buffer += data
        sink.write(buffer[:need])
        buffer = buffer[need:]
        await sink.drain()
        if size == 0:
            while True:
                while b"\r\n" not in buffer:
                    data = await asyncio.wait_for(source.read(_READ_CHUNK), IDLE_TIMEOUT_S)
                    if not data:
                        return
                    buffer += data
                trailer, buffer = buffer.split(b"\r\n", 1)
                sink.write(trailer + b"\r\n")
                if not trailer:
                    await sink.drain()
                    return


async def _relay_response(
    up_reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Forward the upstream response, re-framed with Connection: close."""
    head = await _read_head(up_reader)
    if head is None:
        return
    head_bytes, rest = head
    lines = head_bytes.split(b"\r\n")
    out_lines = [lines[0].decode("latin-1")]
    content_length: int | None = None
    chunked = False
    for raw_line in lines[1:]:
        if not raw_line:
            continue
        decoded = raw_line.decode("latin-1")
        name, sep, value = decoded.partition(":")
        lowered = name.strip().lower() if sep else ""
        if lowered == "connection" or lowered in _HOP_BY_HOP_DROP:
            continue
        if lowered == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                content_length = None
        if lowered == "transfer-encoding" and "chunked" in value.lower():
            chunked = True
        out_lines.append(decoded)
    out_lines.append("Connection: close")
    await _write(writer, ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin-1"))
    if chunked:
        await _relay_chunks(up_reader, writer, rest)
        return
    if rest:
        writer.write(rest)
        await writer.drain()
    remaining = None if content_length is None else content_length - len(rest)
    if remaining is not None:
        while remaining > 0:
            data = await asyncio.wait_for(
                up_reader.read(min(_WRITE_CHUNK, remaining)), IDLE_TIMEOUT_S
            )
            if not data:
                break
            writer.write(data)
            remaining -= len(data)
            await writer.drain()
        await writer.drain()
        return
    while True:
        data = await asyncio.wait_for(up_reader.read(_WRITE_CHUNK), IDLE_TIMEOUT_S)
        if not data:
            break
        writer.write(data)
        await writer.drain()
