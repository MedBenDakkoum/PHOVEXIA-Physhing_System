"""US48 / US49 / BR-11 - model version registry service.

- register_model_version(): metadata only (no upload). `file_path` must be a
  RELATIVE path inside settings.MODELS_DIR (path traversal refused), the
  file must exist for ONNX, and sha256 is computed when the file exists.
- activate_model_version(): verifies the file hash, then in ONE transaction
  locks every row, deactivates the previous version and activates the new
  one (BR-11 = at most one active). Audit: model.activated.
- rollback_model_version(): reactivates the previously active version
  (409 when there is none).
- compare_model_versions(): side-by-side metrics + deltas vs the first id.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

from django.conf import settings as django_settings
from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog
from audit.services import record

from ..models import ModelVersion

# Numeric metric keys compared side by side (missing key = null in output).
METRIC_KEYS: tuple[str, ...] = (
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "latency_ms",
    "test_set_size",
)

CHUNK = 1024 * 64


class ModelVersionError(ValueError):
    """Business refusal: `code` + `detail` (HTTP status decided by the view)."""

    def __init__(self, code: str, detail: str, http_status: int = 400):
        self.code = code
        self.detail = detail
        self.http_status = http_status
        super().__init__(f"{code}: {detail}")


def models_dir() -> Path:
    return Path(django_settings.MODELS_DIR).resolve()


def resolve_file_path(file_path: str) -> Path:
    """Resolve `file_path` under MODELS_DIR, refusing anything that escapes."""
    if not file_path:
        raise ModelVersionError(
            "invalid_path", "file_path est requis pour ce type de version."
        )
    relative = Path(file_path)
    if relative.is_absolute() or ".." in relative.parts or relative.drive:
        raise ModelVersionError(
            "path_traversal", "file_path doit être un chemin relatif à MODELS_DIR."
        )
    full = (models_dir() / relative).resolve()
    if not full.is_relative_to(models_dir()):
        raise ModelVersionError(
            "path_traversal", "file_path doit rester à l'intérieur de MODELS_DIR."
        )
    return full


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def register_model_version(*, data: dict, created_by) -> ModelVersion:
    """Create a version row (metadata, no upload). Raises ModelVersionError."""
    kind = data["kind"]
    file_path = data.get("file_path", "") or ""
    full: Path | None = None
    sha256 = ""
    if kind == ModelVersion.Kind.ONNX:
        if not file_path:
            raise ModelVersionError(
                "file_required", "file_path est obligatoire pour un modèle ONNX."
            )
        full = resolve_file_path(file_path)
        if not full.is_file():
            raise ModelVersionError(
                "file_not_found", "Le fichier du modèle est introuvable dans MODELS_DIR."
            )
        sha256 = compute_sha256(full)
    elif file_path:
        # MOCK: the file is optional but must be inside MODELS_DIR if given.
        full = resolve_file_path(file_path)
        if full.is_file():
            sha256 = compute_sha256(full)
    if ModelVersion.objects.filter(
        name=data["name"], version=data["version"]
    ).exists():
        raise ModelVersionError(
            "already_exists",
            "Une version avec ce nom et ce numéro existe déjà.",
            http_status=409,
        )
    return ModelVersion.objects.create(
        name=data["name"],
        version=data["version"],
        kind=kind,
        file_path=file_path,
        sha256=sha256,
        metrics=data.get("metrics") or {},
        notes=data.get("notes", ""),
        created_by=created_by,
    )


def _verify_file(version: ModelVersion) -> None:
    """At activation: the file must still exist and still hash the same."""
    if not version.file_path:
        return
    full = resolve_file_path(version.file_path)
    if not full.is_file():
        raise ModelVersionError(
            "file_not_found", "Le fichier du modèle est introuvable dans MODELS_DIR."
        )
    if version.sha256:
        digest = compute_sha256(full)
        if digest != version.sha256:
            raise ModelVersionError(
                "sha256_mismatch",
                "Le SHA-256 du fichier ne correspond pas à celui enregistré.",
            )


def activate_model_version(
    version: ModelVersion, *, user, request=None, rollback: bool = False
) -> ModelVersion:
    """Make `version` the single active one (BR-11), audit model.activated."""
    _verify_file(version)
    now = timezone.now()
    with transaction.atomic():
        rows = list(ModelVersion.objects.select_for_update())
        # Deactivate FIRST: the partial unique index (BR-11) rejects any
        # instant with two active rows, so activating before deactivating
        # would raise IntegrityError on the very first UPDATE.
        for row in rows:
            if row.pk != version.pk and row.is_active:
                row.is_active = False
                row.save(update_fields=["is_active"])
        for row in rows:
            if row.pk == version.pk:
                row.is_active = True
                row.activated_at = now
                row.save(update_fields=["is_active", "activated_at"])
        # The instance must reflect the locked state for the caller/audit.
        version.refresh_from_db(fields=["is_active", "activated_at"])
        record(
            AuditLog.Action.MODEL_ACTIVATED,
            request=request,
            user=user,
            target=version,
            metadata={
                "name": version.name,
                "version": version.version,
                "kind": version.kind,
                "rollback": rollback,
            },
        )
    return version


def rollback_model_version(*, user, request=None) -> ModelVersion:
    """Reactivate the previously active version; 409 when there is none."""
    with transaction.atomic():
        rows = list(ModelVersion.objects.select_for_update())
        current = next((row for row in rows if row.is_active), None)
        previous = None
        if current is not None and current.activated_at is not None:
            candidates = [
                row
                for row in rows
                if row.activated_at is not None
                and row.activated_at < current.activated_at
            ]
            if candidates:
                previous = max(candidates, key=lambda row: row.activated_at)
        if previous is None:
            raise ModelVersionError(
                "no_previous_version",
                "Aucune version précédemment active à réactiver.",
                http_status=409,
            )
        return activate_model_version(previous, user=user, request=request, rollback=True)


def compare_model_versions(ids: list[UUID]) -> dict:
    """Side-by-side metrics for >= 2 known versions, deltas vs the FIRST id."""
    if len(ids) < 2:
        raise ModelVersionError(
            "compare_needs_two",
            "Au moins deux identifiants de versions sont requis (ids=a,b).",
        )
    if len(set(ids)) != len(ids):
        raise ModelVersionError(
            "compare_duplicate_id", "Les identifiants fournis doivent être distincts."
        )
    versions = ModelVersion.objects.filter(public_id__in=ids)
    found = {version.public_id: version for version in versions}
    missing = [str(i) for i in ids if i not in found]
    if missing:
        raise ModelVersionError(
            "unknown_id", f"Version(s) inconnue(s) : {', '.join(missing)}."
        )
    ordered = [found[i] for i in ids]
    metrics_keys: list[str] = list(METRIC_KEYS)
    for version in ordered:
        for key in (version.metrics or {}):
            if key not in metrics_keys:
                metrics_keys.append(key)

    def metric_of(version: ModelVersion, key: str):
        value = (version.metrics or {}).get(key)
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    baseline = ordered[0]
    models_payload = [
        {
            "id": str(version.public_id),
            "name": version.name,
            "version": version.version,
            "kind": version.kind,
            "is_active": version.is_active,
            "created_at": version.created_at.isoformat(),
            "metrics": version.metrics or {},
        }
        for version in ordered
    ]
    metrics_payload = []
    for key in metrics_keys:
        values = [metric_of(version, key) for version in ordered]
        baseline_value = values[0]
        deltas = [
            None if (baseline_value is None or value is None) else value - baseline_value
            for value in values
        ]
        metrics_payload.append(
            {"metric": key, "values": values, "delta_vs_baseline": deltas}
        )
    return {
        "baseline_id": str(baseline.public_id),
        "models": models_payload,
        "metrics": metrics_payload,
    }


def get_active_model_version_label() -> str:
    """Label (`version`) of the active ModelVersion, or "" when none is active."""
    return (
        ModelVersion.objects.filter(is_active=True)
        .values_list("version", flat=True)
        .first()
        or ""
    )
