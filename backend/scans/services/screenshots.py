"""Screenshot storage (US20 / US26).

The collector returns a base64 PNG (hard-capped at 5 MB by the sandbox).
Before it hits the disk we check the PNG signature and the size; an invalid
file is simply dropped (the scan becomes a partial / missing-screenshot
result at inference time) - we never crash a scan on a bad screenshot.

The file is written under MEDIA_ROOT/screenshots/<public_id>.png. The API
exposes it only through GET /api/scans/<uuid>/screenshot/ (owner/analyst/admin),
never through the media root.
"""
from __future__ import annotations

import base64
import binascii
import logging
from pathlib import Path
from uuid import UUID

from django.conf import settings

logger = logging.getLogger(__name__)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PNG_BYTES = 5 * 1024 * 1024  # same hard cap as the collector sandbox


def prepare_screenshot(scan_public_id: UUID, png_base64: str | None) -> tuple[str, bytes | None]:
    """Decode, validate and write the PNG.

    Returns (relative_path, raw_png_bytes): the path stored on the scan (or
    "") and the validated bytes to forward to the inference service (or None).
    Never raises: an invalid or oversized screenshot is logged and dropped so
    the scan still completes (the inference service then reports
    MISSING_SCREENSHOT -> partial).
    """
    if not png_base64:
        return "", None
    try:
        raw = base64.b64decode(png_base64, validate=True)
    except (binascii.Error, ValueError):
        logger.warning("prepare_screenshot: scan %s: invalid base64", scan_public_id)
        return "", None
    if not raw.startswith(PNG_SIGNATURE):
        logger.warning("prepare_screenshot: scan %s: not a PNG", scan_public_id)
        return "", None
    if len(raw) > MAX_PNG_BYTES:
        logger.warning("prepare_screenshot: scan %s: PNG too large", scan_public_id)
        return "", None
    relative = f"screenshots/{scan_public_id}.png"
    full = Path(settings.MEDIA_ROOT) / relative
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(raw)
    return relative, raw
