from rest_framework.permissions import SAFE_METHODS, BasePermission


class IsEndUser(BasePermission):
    """Accès : EndUser ou supérieur (Analyst, Admin)."""

    def has_permission(self, request, view):
        u = request.user
        if not u or not u.is_authenticated:
            return False
        return u.role in ("end_user", "analyst", "admin")


class IsAnalyst(BasePermission):
    """Accès : Analyste ou Admin uniquement."""

    def has_permission(self, request, view):
        u = request.user
        if not u or not u.is_authenticated:
            return False
        return u.role in ("analyst", "admin")


class IsAdmin(BasePermission):
    """Accès : Administrateur uniquement."""

    def has_permission(self, request, view):
        u = request.user
        if not u or not u.is_authenticated:
            return False
        return u.role == "admin"


class IsReadOnly(BasePermission):
    """Accès en lecture seule pour les méthodes sûres."""

    def has_permission(self, request, view):
        return request.method in SAFE_METHODS
