import ipaddress

from django.conf import settings

from .models import AuditLog


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def get_client_ip(request):
    """
    IP du client. X-Forwarded-For est falsifiable : il n'est lu que si
    AUDIT_TRUST_X_FORWARDED_FOR = True (à n'activer que derrière un proxy de confiance).
    """
    if request is None:
        return None
    if getattr(settings, "AUDIT_TRUST_X_FORWARDED_FOR", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        first = forwarded.split(",")[0].strip()
        if first and _valid_ip(first):
            return first
    addr = request.META.get("REMOTE_ADDR")
    return addr if _valid_ip(addr) else None


def record(action, *, request=None, user=None, email=None, target=None, metadata=None):
    """
    Enregistre UNE entrée d'audit.

    action   : AuditLog.Action.<...>
    request  : sert à lire l'IP, et l'acteur si `user` n'est pas donné
    user     : l'acteur (sinon request.user s'il est authentifié)
    email    : email à conserver si pas d'acteur (connexion échouée)
    target   : instance de modèle visée (utilisateur modifié, entrée blocklist, ...)
    metadata : dict JSON (ancienne / nouvelle valeur, ...)
    """
    actor = user
    if actor is None and request is not None:
        actor = getattr(request, "user", None)
    if actor is not None and not getattr(actor, "is_authenticated", False):
        actor = None

    entry = AuditLog(
        user=actor,
        user_email=(email or getattr(actor, "email", "") or "")[:254],
        action=action,
        ip_address=get_client_ip(request),
        metadata=metadata or {},
    )
    if target is not None:
        entry.target_type = target._meta.model_name
        entry.target_id = str(target.pk)
        entry.target_repr = str(target)[:255]
    entry.save()
    return entry


def log_status_change(scan, transition_label, actor, old_status, new_status) -> None:
    """
    Write an immutable audit entry for a scan status change (BR-04 / US46).

    old_status must be the status BEFORE the change: the caller mutates
    scan.status before saving, so we never read it from the instance here.
    """
    record(
        action=AuditLog.Action.SCAN_STATUS_CHANGED,
        user=actor,
        target=scan,
        metadata={
            "from_status": old_status,
            "to_status": new_status,
            "transition": transition_label,
        },
    )