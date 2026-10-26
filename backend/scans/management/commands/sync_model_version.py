"""Register the inference bundle as a ModelVersion (US20 / US26 / US48).

Reads the inference service GET /health and creates a ModelVersion row of
kind TORCH_BUNDLE (name "torch-bundle", version = model_bundle_version,
metrics = /health checks). The /health payload does NOT expose the manifest
hash, so sha256 stays empty and the registration is metadata-only.

BR-11: the command NEVER activates the version. Activation stays an admin
action through the control-panel API (activate_model_version), which audits
model.activated.

Usage (from backend/, venv active; INFERENCE_URL must reach the service):
    python manage.py sync_model_version            # uses settings
    python manage.py sync_model_version --url http://127.0.0.1:8000
"""
from __future__ import annotations

import requests
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from controlpanel.models import ModelVersion
from controlpanel.services import ModelVersionError, register_model_version

BUNDLE_NAME = "torch-bundle"


class Command(BaseCommand):
    help = (
        "Register the inference bundle (from GET /health) as a TORCH_BUNDLE "
        "ModelVersion. Does not activate it (BR-11: only an admin activates)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--url",
            default=settings.INFERENCE_URL,
            help="Inference base URL (default: INFERENCE_URL).",
        )
        parser.add_argument(
            "--api-key",
            default=settings.INFERENCE_API_KEY,
            help="X-API-Key sent to the inference service (default: INFERENCE_API_KEY).",
        )

    def handle(self, *args, **options):
        url = (options["url"] or "").rstrip("/")
        api_key = options["api_key"] or ""
        if not url:
            raise CommandError(
                "INFERENCE_URL is not configured (set it or pass --url)."
            )
        headers = {"X-API-Key": api_key} if api_key else {}
        timeout = float(settings.INFERENCE_TIMEOUT or 30.0)
        try:
            resp = requests.get(
                f"{url}/health",
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise CommandError(f"inference service unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise CommandError(
                f"inference /health returned HTTP {resp.status_code}."
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise CommandError("inference /health did not return JSON.") from exc

        version = payload.get("model_bundle_version") or "unknown"
        checks = payload.get("checks") or {}

        if ModelVersion.objects.filter(name=BUNDLE_NAME, version=version).exists():
            self.stdout.write(
                f"{BUNDLE_NAME} {version} already registered (not re-registering)."
            )
            return

        try:
            registered = register_model_version(
                data={
                    "name": BUNDLE_NAME,
                    "version": version,
                    "kind": ModelVersion.Kind.TORCH_BUNDLE,
                    "file_path": "",
                    "metrics": checks,
                    "notes": (
                        "Registered from inference /health by sync_model_version. "
                        "/health does not expose the manifest hash; sha256 stays empty."
                    ),
                },
                created_by=None,
            )
        except ModelVersionError as exc:
            raise CommandError(exc.detail) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"registered {BUNDLE_NAME} {version} "
                f"(kind={registered.kind}, is_active={registered.is_active})."
            )
        )
        self.stdout.write("Activate it via the admin API when ready (BR-11).")
