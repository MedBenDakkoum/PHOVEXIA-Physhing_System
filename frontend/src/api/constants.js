// Contract EXACT from backend/openapi.yaml + HANDOFF.md inference codes.
// UI text: French. IDs: UUID strings.
export const ROLES = {
  admin: { label: "Administrateur", key: "admin" },
  analyst: { label: "Analyste", key: "analyst" },
  end_user: { label: "Utilisateur", key: "end_user" },
};
export const ROLE_VALUES = ["admin", "analyst", "end_user"];
export const ROLE_ORDER = ["end_user", "analyst", "admin"]; // hierarchy
export const ROLE_BADGE = {
  admin: "bg--danger-soft text--danger border--danger",
  analyst: "bg--info-soft text--info border--info",
  end_user: "bg--neutral-soft text--text-2 border--line",
};

export const SCAN_STATUS = {
  submitted: { label: "Soumis", badge: "bg--neutral-soft" },
  analyzing: { label: "Analyse", badge: "bg--info-soft text--info" },
  detected: { label: "Détecté", badge: "bg--danger-soft text--danger" },
  under_review: { label: "En revue", badge: "bg--gold-soft text--gold" },
  confirmed: { label: "Confirmé", badge: "bg--danger-soft text--danger" },
  false_positive: { label: "Faux positif", badge: "bg--success-soft text--success" },
  blocked: { label: "Bloqué", badge: "bg--danger-soft text--danger" },
  failed: { label: "Échoué", badge: "bg--neutral-soft text--text-3" },
};
export const SCAN_STATUS_VALUES = Object.keys(SCAN_STATUS);
export const TERMINAL_SCAN_STATUSES = [
  "detected",
  "under_review",
  "confirmed",
  "false_positive",
  "blocked",
  "failed",
];

export const VERDICT = {
  phishing: { label: "Phishing", badge: "bg--danger-soft text--danger" },
  legitimate: { label: "Légitime", badge: "bg--success-soft text--success" },
  uncertain: { label: "Incertain", badge: "bg--gold-soft text--gold" },
};
export const VERDICT_VALUES = Object.keys(VERDICT);

export const REASON_CODE = {
  COLLECTOR_BUSY: "Service de collecte momentanément occupé",
  COLLECTOR_TIMEOUT: "Délai de collecte dépassé",
  COLLECTOR_UNAVAILABLE: "Service de collecte indisponible",
  INFERENCE_UNAVAILABLE: "Service d'inférence indisponible",
  COLLECTOR_NOT_CONFIGURED: "Service de collecte non configuré",
  INFERENCE_NOT_CONFIGURED: "Service d'inférence non configuré",
  COLLECTOR_UNREACHABLE: "Récolte impossible",
  INFERENCE_UNREACHABLE: "Inférence indisponible",
  MISSING_URL: "URL manquante",
  EMPTY_URL: "URL vide",
  URL_TOO_LONG: "URL trop longue",
  MISSING_TEXT: "HTML manquant",
  EMPTY_TEXT: "HTML vide",
  TEXT_TOO_LARGE: "HTML trop grand",
  MISSING_SSL: "SSL manquant",
  INVALID_SSL: "SSL invalide",
  MISSING_SCREENSHOT: "Capture manquante",
  IMAGE_TOO_LARGE: "Image trop grande",
  INVALID_SCREENSHOT: "Image invalide",
  MODEL_ERROR: "Erreur modèle",
  TIMEOUT: "Délai dépassé",
  INTERNAL_ERROR: "Erreur interne",
  MODEL_MISMATCH: "Version modèle incohérente",
};

export const MODALITY_LABEL = {
  url: "URL",
  page_text: "Texte de la page",
  text: "Texte",
  screenshot: "Capture",
  metadata: "Métadonnées",
  signals: "Signaux",
  fusion: "Fusion",
};
export const PROBABILITY_MODALITIES = ["url", "page_text", "screenshot", "metadata", "fusion"];

export const DETECTION_SOURCE = {
  model: "Modèle",
  blocklist: "Blocklist",
};
export const DETECTION_SOURCE_VALUES = Object.keys(DETECTION_SOURCE);

export const NOTIFICATION_KIND = {
  report_decision: "Décision de signalement",
};
export const NOTIFICATION_KIND_VALUES = Object.keys(NOTIFICATION_KIND);

export const MODE = { fast: "Rapide", full: "Complet" };
export const MODE_VALUES = Object.keys(MODE);

export const CLAIMED_LABEL = { safe: "Sûr", phishing: "Phishing" };
export const CLAIMED_LABEL_VALUES = Object.keys(CLAIMED_LABEL);

export const DECISION = { confirm_phishing: "Confirmer phishing", false_positive: "Faux positif" };
export const DECISION_VALUES = Object.keys(DECISION);

export const REPORT_STATUS = { open: "Ouvert", resolved: "Résolu" };
export const REPORT_STATUS_VALUES = Object.keys(REPORT_STATUS);

export const BLOCKLIST_REASON = {
  confirmed_phishing: "Phishing confirmé",
  campaign: "Campagne",
  manual: "Manuel",
};
export const BLOCKLIST_REASON_VALUES = Object.keys(BLOCKLIST_REASON);

export const REVIEW_SOURCE = {
  uncertain: "Incertain",
  reported: "Signalé",
};

export const MODEL_VERSION_KIND = { MOCK: "Mock", ONNX: "ONNX", TORCH_BUNDLE: "Torch bundle" };
export const MODEL_VERSION_KIND_VALUES = Object.keys(MODEL_VERSION_KIND);

export const SCOPE = { "scan:create": "Créer scan", "scan:read": "Lire scan" };

export const AUDIT_ACTIONS = {
  register: "Inscription",
  login_success: "Connexion réussie",
  login_failed: "Connexion échouée",
  role_change: "Changement de rôle",
  user_suspend: "Suspension",
  user_reactivate: "Réactivation",
  decision: "Décision",
  blocklist_add: "Ajout blocklist",
  blocklist_remove: "Retrait blocklist",
  model_update: "Modèle",
  scan_created: "Scan créé",
  scan_status_changed: "Statut scan",
  quick_check_created: "Quick-check",
  report_created: "Signalement",
  scan_decided: "Décision scan",
  note_added: "Note ajoutée",
  scan_rescanned: "Rescan",
  blocklist_added: "Ajout blocklist",
  blocklist_removed: "Retrait blocklist",
  blocklist_exported: "Export blocklist",
  settings_changed: "Paramètres",
  model_activated: "Modèle activé",
  apikey_created: "Clé API créée",
  apikey_revoked: "Clé API révoquée",
  password_reset_requested: "Réinitialisation demandée",
  password_reset_completed: "Réinitialisation terminée",
};
export const AUDIT_ACTION_VALUES = Object.keys(AUDIT_ACTIONS);

// Endpoints (from openapi + HANDOFF)
export const AUDIT_PAGE_SIZES = [10, 20, 50, 100];
export const AUDIT_DEFAULT_PAGE_SIZE = 20;

export const ENDPOINTS = {
  register: "/api/auth/register/",
  login: "/api/auth/login/",
  refresh: "/api/auth/refresh/",
  logout: "/api/auth/logout/",
  me: "/api/auth/me/",
  changePassword: "/api/auth/change-password/",
  passwordReset: "/api/auth/password-reset/",
  passwordResetConfirm: "/api/auth/password-reset/confirm/",
  users: "/api/auth/users/",
  user: (id) => `/api/auth/users/${id}/`,
  scans: "/api/scans/",
  scanQuota: "/api/scans/quota/",
  scan: (id) => `/api/scans/${id}/`,
  scanScreenshot: (id) => `/api/scans/${id}/screenshot/`,
  scanReport: (id) => `/api/scans/${id}/report/`,
  quickCheck: "/api/quick-check/",
  quickCheckDetail: (id) => `/api/quick-check/${id}/`,
  blocklist: "/api/blocklist/",
  blocklistEntry: (id) => `/api/blocklist/${id}/`,
  blocklistExport: "/api/blocklist/export/",
  brands: "/api/brands/",
  brand: (id) => `/api/brands/${id}/`,
  campaigns: "/api/campaigns/",
  campaign: (id) => `/api/campaigns/${id}/`,
  reviewQueue: "/api/review/queue/",
  review: (id) => `/api/review/${id}/`,
  reviewDecision: (id) => `/api/review/${id}/decision/`,
  reviewNotes: (id) => `/api/review/${id}/notes/`,
  reviewRescan: (id) => `/api/review/${id}/rescan/`,
  auditLogs: "/api/audit/logs/",
  auditLog: (id) => `/api/audit/logs/${id}/`,
  notifications: "/api/notifications/",
  notifyRead: (id) => `/api/notifications/${id}/read/`,
  adminSettings: "/api/admin/settings/",
  adminModels: "/api/admin/models/",
  adminModel: (id) => `/api/admin/models/${id}/`,
  adminModelActivate: (id) => `/api/admin/models/${id}/activate/`,
  adminModelRollback: "/api/admin/models/rollback/",
  adminModelCompare: "/api/admin/models/compare/",
  adminDashboard: "/api/admin/dashboard/",
  adminHealth: "/api/admin/health/",
  adminApiKeys: "/api/admin/api-keys/",
  adminApiKey: (id) => `/api/admin/api-keys/${id}/`,
  docs: "/api/docs/",
  schema: "/api/schema/",
  health: "/api/health/",
};
