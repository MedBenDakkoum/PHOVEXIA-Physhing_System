"""Safe screenshot decoding (contract section 2A, ISO 6.8 input limits)."""

from __future__ import annotations

import io

import pytest
from app.errors import ImageValidationError
from app.images import decode_screenshot
from PIL import Image


def _png_bytes(width: int = 64, height: int = 64) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color=(10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


def test_valid_png_decodes_to_rgb():
    image = decode_screenshot(_png_bytes(), max_pixels=1_000_000)
    assert image.mode == "RGB"
    assert image.size == (64, 64)


def test_corrupted_bytes_rejected():
    with pytest.raises(ImageValidationError) as excinfo:
        decode_screenshot(b"\x89PNG\r\n\x1a\nNOT-A-REAL-IMAGE", max_pixels=1_000_000)
    assert excinfo.value.reason_code == "INVALID_SCREENSHOT"


def test_bmp_rejected_even_if_valid_image():
    buf = io.BytesIO()
    Image.new("RGB", (16, 16)).save(buf, format="BMP")
    with pytest.raises(ImageValidationError) as excinfo:
        decode_screenshot(buf.getvalue(), max_pixels=1_000_000)
    assert excinfo.value.reason_code == "INVALID_SCREENSHOT"


def test_pixel_bomb_rejected():
    # 3000x3000 = 9M pixels, above a 1M limit but below Pillow's 2x abort.
    buf = io.BytesIO()
    Image.new("RGB", (3000, 3000)).save(buf, format="PNG")
    with pytest.raises(ImageValidationError) as excinfo:
        decode_screenshot(buf.getvalue(), max_pixels=1_000_000)
    assert excinfo.value.reason_code == "INVALID_SCREENSHOT"
