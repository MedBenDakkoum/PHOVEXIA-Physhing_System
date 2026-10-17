const dateFmt = new Intl.DateTimeFormat("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat("fr-FR", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const fullFmt = new Intl.DateTimeFormat("fr-FR", { dateStyle: "full", timeStyle: "medium" });
const rtf = new Intl.RelativeTimeFormat("fr", { numeric: "auto" });

const valid = (v) => {
  const d = v ? new Date(v) : null;
  return d && !Number.isNaN(d.getTime()) ? d : null;
};

export const formatDate = (v) => (valid(v) ? dateFmt.format(valid(v)) : "—");
export const formatDateTime = (v) => (valid(v) ? dateTimeFmt.format(valid(v)) : "—");
export const formatFull = (v) => (valid(v) ? fullFmt.format(valid(v)) : "—");

export function relativeTime(v) {
  const d = valid(v);
  if (!d) return "—";
  const diff = (d.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "à l'instant";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), "day");
  return rtf.format(Math.round(diff / (86400 * 30)), "month");
}

export const fullName = (u) => [u?.first_name, u?.last_name].filter(Boolean).join(" ").trim();
export const displayName = (u) => fullName(u) || u?.email || "—";

export function initials(u) {
  const f = u?.first_name?.[0];
  const l = u?.last_name?.[0];
  if (f || l) return `${f || ""}${l || ""}`.toUpperCase();
  return (u?.email?.[0] || "?").toUpperCase();
}

export const formatNumber = (n) => new Intl.NumberFormat("fr-FR").format(n ?? 0);

/** Date locale YYYY-MM-DD (pour <input type="date">). */
export const toDateInput = (d) => {
  const x = new Date(d);
  return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, "0")}-${String(x.getDate()).padStart(2, "0")}`;
};

/** Date UTC YYYY-MM-DD : le backend filtre sur created_at en UTC (TIME_ZONE = "UTC"). */
export const utcDay = (d = new Date()) => new Date(d).toISOString().slice(0, 10);
