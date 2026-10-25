"""Stable error types for the inference service."""

from __future__ import annotations


class BundleIntegrityError(RuntimeError):
    """A bundle file is missing or its SHA-256 does not match the manifest."""


class BundleLoadError(RuntimeError):
    """A verified file could not be loaded safely or failed a shape check."""


class InputValidationError(ValueError):
    """A /predict input field is missing or invalid."""

    def __init__(self, reason_code: str, signal: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.signal = signal


class ImageValidationError(InputValidationError):
    """Screenshot bytes are not a safely decodable PNG/JPEG."""


class FusionInputError(ValueError):
    """Fusion vector is not four finite values in [0, 1]."""
