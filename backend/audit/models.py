from typing import ClassVar

from django.conf import settings
from django.db import models


class ImmutableAuditLogError(RuntimeError):
    """Levée dès qu'on tente de modifier ou de supprimer une entrée d'audit."""


class AuditLogQuerySet(models.QuerySet):
    # update() est aussi utilisé par bulk_update() : les deux sont donc bloqués.
    def update(self, **kwargs):
        raise ImmutableAuditLogError("Le journal d'audit est en lecture seule.")

    def delete(self):
        raise ImmutableAuditLogError("Le journal d'audit ne peut pas être supprimé.")


class AuditLog(models.Model):
    class Action(models.TextChoices):
        REGISTER = "register", "Inscription"
        LOGIN_SUCCESS = "login_success", "Connexion réussie"
        LOGIN_FAILED = "login_failed", "Connexion échouée"
        ROLE_CHANGE = "role_change", "Changement de rôle"
        USER_SUSPEND = "user_suspend", "Suspension d'un compte"
        USER_REACTIVATE = "user_reactivate", "Réactivation d'un compte"
        # Branchées quand les apps correspondantes existeront :
        DECISION = "decision", "Décision"
        BLOCKLIST_ADD = "blocklist_add", "Ajout à la blocklist"
        BLOCKLIST_REMOVE = "blocklist_remove", "Retrait de la blocklist"
        MODEL_UPDATE = "model_update", "Modèle"
        SCAN_CREATED = "scan_created", "Création d'un scan"
        SCAN_STATUS_CHANGED = "scan_status_changed", "Changement de statut d'un scan"
        # Step 9 (US11): anonymous quick check. Metadata = domain only, plus
        # the client IP: the full URL is deliberately never stored.
        QUICK_CHECK_CREATED = "quick_check.created", "Quick check anonyme"
        # Step 10 (US31, US34-US36): human review workflow. Same dotted
        # namespace as quick_check.created; metadata stays small (label,
        # lengths, statuses) - never a comment/note body, never a URL.
        REPORT_CREATED = "report.created", "Signalement d'un verdict"
        SCAN_DECIDED = "scan.decided", "Décision d'un analyste"
        NOTE_ADDED = "note.added", "Note interne d'un analyste"
        SCAN_RESCANNED = "scan.rescanned", "Nouveau scan relancé par un analyste"
        # Blocklist (US38-US41): dotted namespace, domain only in metadata,
        # never a full URL. Migration 0006.
        BLOCKLIST_ADDED = "blocklist.added", "Ajout à la blocklist"
        BLOCKLIST_REMOVED = "blocklist.removed", "Retrait de la blocklist"
        BLOCKLIST_EXPORTED = "blocklist.exported", "Export de la blocklist"
        # Step 12 (US52, US48, US54): admin control panel. metadata =
        # old/new values (settings), model version label (activation),
        # key prefix only - NEVER the secret (US54). Migration 0007.
        SETTINGS_CHANGED = "settings.changed", "Réglages de détection modifiés"
        MODEL_ACTIVATED = "model.activated", "Version de modèle activée"
        APIKEY_CREATED = "apikey.created", "Création d'une clé API"
        APIKEY_REVOKED = "apikey.revoked", "Révocation d'une clé API"
        # Step 13 (US5): password reset. Written by the Celery task (user id
        # only when the account exists and is active); the typed email of an
        # unknown address is NEVER stored. Migration 0008.
        PASSWORD_RESET_REQUESTED = "password.reset_requested", "Demande de réinitialisation"
        PASSWORD_RESET_COMPLETED = "password.reset_completed", "Mot de passe réinitialisé"

    # Qui : FK (filtrage) + copie de l'email (conservée même si le compte disparaît,
    # et utilisable pour une tentative de connexion sur un email inconnu).
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                             on_delete=models.SET_NULL, related_name="audit_entries")
    user_email = models.CharField(max_length=254, blank=True)

    action = models.CharField(max_length=30, choices=Action.choices, db_index=True)

    # Cible de l'action
    target_type = models.CharField(max_length=50, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    target_repr = models.CharField(max_length=255, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)  # ex. {"old": "viewer", "new": "analyst"}
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    objects = AuditLogQuerySet.as_manager()

    class Meta:
        ordering: ClassVar[list[str]] = ["-created_at", "-id"]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["action", "created_at"]),
        ]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} {self.user_email}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ImmutableAuditLogError("Une entrée d'audit ne peut pas être modifiée.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ImmutableAuditLogError("Une entrée d'audit ne peut pas être supprimée.")