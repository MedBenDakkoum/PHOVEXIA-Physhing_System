"""Safe screenshot decoding: PNG/JPEG only, bounded pixels, RGB output."""

from __future__ import annotations

import io

from PIL import Image, UnidentifiedImageError

from app.errors import ImageValidationError

ALLOWED_FORMATS = {"PNG", "JPEG"}


def decode_screenshot(data: bytes, max_pixels: int) -> Image.Image:
    """Decode bytes into an RGB PIL image or raise ImageValidationError."""
    if not data:
        raise ImageValidationError("MISSING_SCREENSHOT", "screenshot")
    previous_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        with Image.open(io.BytesIO(data)) as probe:
            fmt = (probe.format or "").upper()
            if fmt not in ALLOWED_FORMATS:
                raise ImageValidationError("INVALID_SCREENSHOT", "screenshot")
            probe.verify()
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            if img.width * img.height > max_pixels:
                raise ImageValidationError("INVALID_SCREENSHOT", "screenshot")
            return img.convert("RGB")
    except ImageValidationError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        raise ImageValidationError("INVALID_SCREENSHOT", "screenshot") from None
    finally:
        Image.MAX_IMAGE_PIXELS = previous_limit
