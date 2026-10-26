"""Business logic of the admin control panel (US45, US48, US49, US52-US54).

Thin views, logic here (AGENTS.md). `settings` and `model_versions` are
re-exported because scans.services.quota / inference and scans.tasks import
them through the package.
"""
from .model_versions import (
    ModelVersionError,
    get_active_model_version,
    get_active_model_version_label,
    register_model_version,
)
from .settings import SettingsValues, get_detection_settings

__all__ = [
    "ModelVersionError",
    "SettingsValues",
    "get_active_model_version",
    "get_active_model_version_label",
    "get_detection_settings",
    "register_model_version",
]
