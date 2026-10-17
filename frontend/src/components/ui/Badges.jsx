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
import { AUDIT_ACTIONS, ROLES } from "../../api/constants";

export const ROLE_META = {
  admin: { icon: Crown, tone: "gold", desc: "Gère les comptes, les rôles et le journal d'audit." },
  analyst: { icon: Radar, tone: "info", desc: "Accès analyste aux modules de détection." },
  viewer: { icon: Eye, tone: "neutral", desc: "Accès en lecture. Rôle attribué à l'inscription." },
};

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
  return <span className={`badge ${toneClass(meta.tone)}`}>{ROLES[role] || role}</span>;
}

export function StatusBadge({ active }) {
  return <span className={`badge ${active ? "badge-success" : "badge-danger"}`}>{active ? "Actif" : "Suspendu"}</span>;
}

export function ActionBadge({ action, label }) {
  const meta = ACTION_META[action] || { tone: "neutral" };
  return <span className={`badge ${toneClass(meta.tone)}`}>{label || AUDIT_ACTIONS[action] || action}</span>;
}
