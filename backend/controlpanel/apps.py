from django.apps import AppConfig

from . import openapi_ext  # noqa: F401  (registers the Api-Key scheme early)


class ControlPanelConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "controlpanel"
    verbose_name = "Admin control panel"
