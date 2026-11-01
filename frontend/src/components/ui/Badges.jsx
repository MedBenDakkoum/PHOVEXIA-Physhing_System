import {
  Crown,
  Cpu,
  Eye,
  Gavel,
  LogIn,
  Radar,
  ShieldAlert,
  ShieldBan,
  ShieldOff,
  UserCheck,
  UserCog,
  UserPlus,
  UserX,
} from "lucide-react";
import {
  AUDIT_ACTIONS,
  CLAIMED_LABEL,
  DETECTION_SOURCE,
  PARTIAL_STATUS_LABEL,
  PARTIAL_VERDICT_LABEL,
  ROLES,
  SCAN_STATUS,
  VERDICT,
} from "../../api/constants";

// Clés = valeurs de Role.choices du backend : admin | analyst | end_user
// ("viewer" n'existe pas côté backend ; on le garde comme alias défensif).
export const ROLE_META = {
  admin: { icon: Crown, tone: "gold", desc: "Gère les comptes, les rôles et le journal d'audit." },
  analyst: { icon: Radar, tone: "info", desc: "Examine les scans incertains et les signalements." },
  end_user: { icon: Eye, tone: "neutral", desc: "Vérifie ses liens et consulte ses analyses." },
};
ROLE_META.viewer = ROLE_META.end_user;

export const ACTION_META = {
  register: { icon: UserPlus, tone: "info" },
  login_success: { icon: LogIn, tone: "success" },
  login_failed: { icon: ShieldAlert, tone: "danger" },
  role_change: { icon: UserCog, tone: "gold" },
  user_suspend: { icon: UserX, tone: "danger" },
  user_reactivate: { icon: UserCheck, tone: "success" },
  decision: { icon: Gavel, tone: "gold" },
  blocklist_add: { icon: ShieldBan, tone: "danger" },
  blocklist_remove: { icon: ShieldOff, tone: "neutral" },
  model_update: { icon: Cpu, tone: "info" },
};

const toneClass = (tone) => (tone && tone !== "neutral" ? `badge-${tone}` : "");

export function RoleBadge({ role }) {
  const meta = ROLE_META[role] || { tone: "neutral" };
  return <span className={`badge ${toneClass(meta.tone)}`}>{ROLES[role]?.label || role}</span>;
}

export function StatusBadge({ active }) {
  return <span className={`badge ${active ? "badge-success" : "badge-danger"}`}>{active ? "Actif" : "Suspendu"}</span>;
}

export function ActionBadge({ action, label }) {
  const meta = ACTION_META[action] || { tone: "neutral" };
  return <span className={`badge ${toneClass(meta.tone)}`}>{label || AUDIT_ACTIONS[action] || action}</span>;
}

const VERDICT_TONE = { phishing: "danger", legitimate: "success", uncertain: "gold" };
const STATUS_TONE = {
  submitted: "neutral",
  analyzing: "info",
  detected: "danger",
  under_review: "gold",
  confirmed: "danger",
  false_positive: "success",
  blocked: "danger",
  failed: "neutral",
};

export function VerdictBadge({ verdict, partial = false }) {
  if (partial) return <span className="badge">{PARTIAL_VERDICT_LABEL}</span>;
  if (!verdict) return <span className="badge">—</span>;
  return (
    <span className={`badge ${toneClass(VERDICT_TONE[verdict])}`}>
      {VERDICT[verdict]?.label || verdict}
    </span>
  );
}

export function ScanStatusBadge({ status, partial = false }) {
  if (!status) return <span className="badge">—</span>;
  if (partial && status === "detected") {
    return <span className="badge">{PARTIAL_STATUS_LABEL}</span>;
  }
  return (
    <span className={`badge ${toneClass(STATUS_TONE[status])}`}>
      {SCAN_STATUS[status]?.label || status}
    </span>
  );
}

export function DetectionBadge({ source }) {
  if (!source) return null;
  return (
    <span className={`badge ${source === "blocklist" ? "badge-danger" : "badge-info"}`}>
      {DETECTION_SOURCE[source] || source}
    </span>
  );
}

export function ReportBadge({ reported, claimedLabel }) {
  if (!reported) return <span className="badge">Non signalé</span>;
  return (
    <span className="badge badge-gold">
      Signalé{claimedLabel ? ` · ${CLAIMED_LABEL[claimedLabel] || claimedLabel}` : ""}
    </span>
  );
}
