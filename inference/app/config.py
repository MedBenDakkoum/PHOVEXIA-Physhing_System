"""Environment-driven configuration for the inference service."""

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when the service environment is unusable."""


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be > 0, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    artifacts_dir: Path
    hf_local_dir: Path
    api_key: str
    predict_timeout_seconds: int
    max_image_bytes: int
    max_text_bytes: int
    max_url_length: int
    max_image_pixels: int

    @property
    def manifest_path(self) -> Path:
        return self.artifacts_dir / "manifest.json"


def load_settings() -> Settings:
    api_key = os.environ.get("INFERENCE_API_KEY", "")
    if not api_key:
        raise ConfigError(
            "INFERENCE_API_KEY is required and must not be empty "
            "(shared secret between worker and service)."
        )
    artifacts = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
    if not artifacts.is_dir():
        raise ConfigError(f"ARTIFACTS_DIR does not exist: {artifacts}")
    hf_dir = Path(os.environ.get("HF_LOCAL_DIR", "/models_html"))
    if not hf_dir.is_dir():
        raise ConfigError(f"HF_LOCAL_DIR does not exist: {hf_dir}")
    return Settings(
        artifacts_dir=artifacts,
        hf_local_dir=hf_dir,
        api_key=api_key,
        predict_timeout_seconds=_int_env("PREDICT_TIMEOUT_SECONDS", 30),
        max_image_bytes=_int_env("MAX_IMAGE_BYTES", 5 * 1024 * 1024),
        max_text_bytes=_int_env("MAX_TEXT_BYTES", 500 * 1024),
        max_url_length=_int_env("MAX_URL_LENGTH", 2048),
        max_image_pixels=_int_env("MAX_IMAGE_PIXELS", 25_000_000),
    )
