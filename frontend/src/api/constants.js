// Valeurs et libellés EXACTEMENT alignés sur le backend Django.

// accounts.models.User.Role
export const ROLES = {
  admin: "Administrateur",
  analyst: "Analyste",
  viewer: "Lecteur",
};
export const ROLE_VALUES = Object.keys(ROLES);

// audit.models.AuditLog.Action
export const AUDIT_ACTIONS = {
  register: "Inscription",
  login_success: "Connexion réussie",
  login_failed: "Connexion échouée",
  role_change: "Changement de rôle",
  user_suspend: "Suspension d'un compte",
  user_reactivate: "Réactivation d'un compte",
  decision: "Décision",
  blocklist_add: "Ajout à la blocklist",
  blocklist_remove: "Retrait de la blocklist",
  model_update: "Modèle",
};
export const AUDIT_ACTION_VALUES = Object.keys(AUDIT_ACTIONS);

// audit.views.AuditPagination
export const AUDIT_PAGE_SIZES = [10, 20, 50, 100];
export const AUDIT_DEFAULT_PAGE_SIZE = 20;

// Endpoints (config/urls.py + accounts/urls.py + audit/urls.py)
export const ENDPOINTS = {
  register: "/api/auth/register/",
  login: "/api/auth/login/",
  refresh: "/api/auth/refresh/",
  logout: "/api/auth/logout/",
  me: "/api/auth/me/",
  changePassword: "/api/auth/change-password/",
  users: "/api/auth/users/",
  user: (id) => `/api/auth/users/${id}/`,
  auditLogs: "/api/audit/logs/",
  auditLog: (id) => `/api/audit/logs/${id}/`,
  docs: "/api/docs/",
};
