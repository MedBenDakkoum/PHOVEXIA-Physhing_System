import { Link } from "react-router-dom";
import {
  Activity,
  ArrowUpRight,
  Ban,
  Gavel,
  KeyRound,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  ScrollText,
  Cpu,
  Users as UsersIcon,
  UserRound,
} from "lucide-react";
import { listAuditLogs } from "../api/audit";
import { ROLES } from "../api/constants";
import { listUsers } from "../api/users";
import { useAuth } from "../context/AuthContext";
import AegisEmblem from "../components/brand/AegisEmblem";
import UrlAnalysisForm from "../components/analysis/UrlAnalysisForm";
import Donut from "../components/charts/Donut";
import StackedBars from "../components/charts/StackedBars";
import Avatar from "../components/ui/Avatar";
import { ACTION_META, RoleBadge, ROLE_META } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { EmptyState, ErrorState, Skeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { displayName, formatDate, formatNumber, relativeTime, utcDay } from "../utils/format";

/* --------------------------------------------------------------- bannière */
function greeting() {
  return new Date().getHours() >= 18 ? "Bonsoir" : "Bonjour";
}

const LEAD = {
  admin: "Voici l'état de votre plateforme : comptes, connexions et activité récente.",
  analyst: "Collez une adresse web à vérifier et retrouvez vos outils d’analyse ici.",
  viewer: "Vous disposez d'un accès en lecture. Un administrateur peut faire évoluer votre rôle.",
};

function CommandBanner({ user }) {
  const name = user.first_name || user.email.split("@")[0];
  const today = new Intl.DateTimeFormat("fr-FR", { weekday: "long", day: "numeric", month: "long", year: "numeric" }).format(new Date());
  const RoleIcon = ROLE_META[user.role].icon;
  return (
    <section className="command" aria-label="Accueil">
      <div>
        <h1 className="command-title">
          {greeting()}, {name}
        </h1>
        <p className="command-lead">{LEAD[user.role]}</p>
        <div className="command-meta">
          <span className="badge badge-nodot">
            <RoleIcon size={14} aria-hidden="true" /> {ROLES[user.role]}
          </span>
          <span className="command-date">{today.charAt(0).toUpperCase() + today.slice(1)}</span>
        </div>
      </div>
      <AegisEmblem className="command-emblem" />
    </section>
  );
}

/* -------------------------------------------------------------- à venir */
function Roadmap() {
  const items = [
    { icon: Gavel, title: "Décisions", text: "Consultez les verdicts rendus sur les messages analysés." },
    { icon: ShieldBan, title: "Blocklist", text: "Bloquez ou débloquez les expéditeurs et les liens malveillants." },
    { icon: Cpu, title: "Modèle de détection", text: "Suivez les mises à jour du modèle et leur impact." },
  ];
  return (
    <section className="card card-pad" aria-label="Modules à venir">
      <div className="card-head">
        <div>
          <h2 className="card-title">Prochainement</h2>
          <p className="card-sub">Ces modules rejoindront la plateforme. Leurs actions sont déjà prévues dans le journal d'audit.</p>
        </div>
        <span className="badge badge-gold">Bientôt</span>
      </div>
      <div className="roadmap">
        {items.map(({ icon: Icon, title, text }) => (
          <div className="road-item" key={title}>
            <span className="road-ico">
              <Icon size={22} />
            </span>
            <h3>{title}</h3>
            <p>{text}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------ administrateur */
const CATEGORY = {
  login_success: "success",
  login_failed: "failed",
  role_change: "admin",
  user_suspend: "admin",
  user_reactivate: "admin",
  register: "register",
};
const SERIES = [
  { key: "success", label: "Connexions réussies", color: "var(--success)" },
  { key: "failed", label: "Échecs de connexion", color: "var(--danger)" },
  { key: "admin", label: "Administration", color: "var(--gold)" },
  { key: "register", label: "Inscriptions", color: "var(--info)" },
  { key: "other", label: "Autres", color: "var(--text-3)" },
];
const dayFmt = new Intl.DateTimeFormat("fr-FR", { weekday: "short", day: "numeric", timeZone: "UTC" });
const dayFull = new Intl.DateTimeFormat("fr-FR", { weekday: "long", day: "numeric", month: "long", timeZone: "UTC" });

function lastSevenDays(events) {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    days.push(utcDay(d));
  }
  const map = Object.fromEntries(days.map((k) => [k, { success: 0, failed: 0, admin: 0, register: 0, other: 0 }]));
  events.forEach((e) => {
    const k = utcDay(e.created_at);
    if (map[k]) map[k][CATEGORY[e.action] || "other"] += 1;
  });
  return days.map((k) => {
    const d = new Date(`${k}T00:00:00Z`);
    return { label: dayFmt.format(d).replace(".", ""), title: dayFull.format(d), values: map[k] };
  });
}

function Kpi({ icon: Icon, label, value, foot, tone = "" }) {
  return (
    <div className={`kpi ${tone}`}>
      <div className="kpi-top">
        <span>{label}</span>
        <span className="kpi-ico">
          <Icon size={18} />
        </span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-foot">{foot}</div>
    </div>
  );
}

function AdminOverview() {
  const { data, error, loading, reload } = useAsync(async (signal) => {
    const today = utcDay(); // le backend filtre en UTC
    const [users, total, failed, recent] = await Promise.all([
      listUsers({}, signal),
      listAuditLogs({ page_size: 1 }, signal),
      listAuditLogs({ page_size: 1, action: "login_failed", date_from: today }, signal),
      listAuditLogs({ page_size: 100 }, signal),
    ]);
    return { users, total: total.count, failedToday: failed.count, recent: recent.results };
  }, []);

  if (error) {
    return (
      <div className="card">
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  }
  if (loading || !data) {
    return (
      <>
        <div className="kpis">
          {[0, 1, 2, 3].map((i) => (
            <div className="kpi" key={i}>
              <Skeleton h={14} w="55%" />
              <Skeleton h={38} w="40%" style={{ marginTop: 16 }} />
              <Skeleton h={12} w="70%" style={{ marginTop: 14 }} />
            </div>
          ))}
        </div>
        <div className="dash-grid">
          <div className="card card-pad">
            <Skeleton h={260} r={14} />
          </div>
          <div className="card card-pad">
            <Skeleton h={260} r={14} />
          </div>
        </div>
      </>
    );
  }

  const { users, total, failedToday, recent } = data;
  const nActive = users.filter((u) => u.is_active).length;
  const byRole = (r) => users.filter((u) => u.role === r).length;
  const series = SERIES.filter((s) => s.key !== "other" || recent.some((e) => !CATEGORY[e.action]));
  const days = lastSevenDays(recent);
  const feed = recent.slice(0, 7);

  return (
    <>
      <div className="kpis">
        <Kpi icon={UsersIcon} tone="tone-gold" label="Comptes" value={formatNumber(users.length)} foot={`${formatNumber(nActive)} actifs`} />
        <Kpi
          icon={Ban}
          label="Comptes suspendus"
          value={formatNumber(users.length - nActive)}
          foot={users.length - nActive ? "Accès bloqués" : "Aucun accès bloqué"}
        />
        <Kpi icon={ScrollText} label="Événements d'audit" value={formatNumber(total)} foot="Depuis la mise en service" />
        <Kpi
          icon={failedToday ? ShieldAlert : ShieldCheck}
          tone={failedToday ? "tone-danger" : "tone-success tone-calm"}
          label="Échecs de connexion"
          value={formatNumber(failedToday)}
          foot={failedToday ? "Aujourd'hui : à surveiller" : "Aujourd'hui : rien à signaler"}
        />
      </div>

      <div className="dash-grid">
        <section className="card card-pad" aria-label="Activité sur 7 jours">
          <div className="card-head">
            <div>
              <h2 className="card-title">Activité des 7 derniers jours</h2>
              <p className="card-sub">
                {total > recent.length
                  ? `Calculée sur les ${recent.length} événements les plus récents (sur ${formatNumber(total)}).`
                  : "Tous les événements du journal d'audit."}
              </p>
            </div>
            <Button variant="quiet" size="sm" to="/app/admin/audit" iconRight={ArrowUpRight}>
              Journal
            </Button>
          </div>
          <StackedBars data={days} series={series} ariaLabel="Événements d'audit par jour sur les 7 derniers jours" />
        </section>

        <section className="card card-pad" aria-label="Répartition des rôles">
          <div className="card-head">
            <div>
              <h2 className="card-title">Rôles</h2>
              <p className="card-sub">Répartition des comptes.</p>
            </div>
            <Button variant="quiet" size="sm" to="/app/admin/users" iconRight={ArrowUpRight}>
              Gérer
            </Button>
          </div>
          <div className="donut-wrap">
            <Donut
              slices={[
                { label: ROLES.admin, value: byRole("admin"), color: "var(--gold)" },
                { label: ROLES.analyst, value: byRole("analyst"), color: "var(--info)" },
                { label: ROLES.viewer, value: byRole("viewer"), color: "var(--text-3)" },
              ]}
              centerValue={formatNumber(users.length)}
              centerLabel="comptes"
              ariaLabel="Répartition des comptes par rôle"
            />
            <ul className="donut-list">
              {[
                ["admin", "var(--gold)"],
                ["analyst", "var(--info)"],
                ["viewer", "var(--text-3)"],
              ].map(([r, c]) => (
                <li key={r} style={{ "--c": c }}>
                  <span className="lbl">
                    <i />
                    {ROLES[r]}
                  </span>
                  <b className="tabular">{byRole(r)}</b>
                </li>
              ))}
            </ul>
          </div>
        </section>
      </div>

      <div className="dash-grid even">
        <section className="card card-pad" aria-label="Derniers événements">
          <div className="card-head">
            <div>
              <h2 className="card-title">Derniers événements</h2>
              <p className="card-sub">Ce qui vient de se passer sur la plateforme.</p>
            </div>
            <Button variant="quiet" size="sm" to="/app/admin/audit" iconRight={ArrowUpRight}>
              Tout voir
            </Button>
          </div>
          {feed.length === 0 ? (
            <EmptyState icon={Activity} title="Aucun événement">
              L'activité de la plateforme apparaîtra ici.
            </EmptyState>
          ) : (
            <ul className="feed">
              {feed.map((e) => {
                const meta = ACTION_META[e.action] || { icon: Activity, tone: "neutral" };
                const Icon = meta.icon;
                return (
                  <li className="feed-item" key={e.id}>
                    <span className={`feed-ico tone-${meta.tone}-i`}>
                      <Icon size={18} />
                    </span>
                    <div className="feed-body">
                      <strong>{e.action_label}</strong>
                      <span className="truncate">
                        {e.user_email || "Anonyme"}
                        {e.target_repr && e.target_repr !== e.user_email ? ` · ${e.target_repr}` : ""}
                      </span>
                    </div>
                    <time className="feed-time" dateTime={e.created_at}>
                      {relativeTime(e.created_at)}
                    </time>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section className="card card-pad" aria-label="Comptes récents">
          <div className="card-head">
            <div>
              <h2 className="card-title">Derniers inscrits</h2>
              <p className="card-sub">Les comptes les plus récents.</p>
            </div>
            <Button variant="quiet" size="sm" to="/app/admin/users" iconRight={ArrowUpRight}>
              Utilisateurs
            </Button>
          </div>
          <ul className="feed">
            {users.slice(0, 6).map((u) => (
              <li className="feed-item" key={u.id}>
                <Avatar user={u} />
                <div className="feed-body">
                  <strong>{displayName(u)}</strong>
                  <span className="truncate">{u.email}</span>
                </div>
                <div style={{ textAlign: "right", display: "grid", gap: 4, justifyItems: "end" }}>
                  <RoleBadge role={u.role} />
                  <span className="feed-time">{formatDate(u.date_joined)}</span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </>
  );
}

/* ----------------------------------------------------------- analyste / lecteur */
function MemberOverview({ user }) {
  return (
    <div className="dash-grid even">
      <section className="card card-pad" aria-label="Votre compte">
        <div className="card-head">
          <div>
            <h2 className="card-title">Votre compte</h2>
            <p className="card-sub">{ROLE_META[user.role].desc}</p>
          </div>
          <RoleBadge role={user.role} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
          <Avatar user={user} size="lg" />
          <div style={{ minWidth: 0 }}>
            <strong style={{ display: "block", fontSize: "var(--fs-md)" }}>{displayName(user)}</strong>
            <span className="muted truncate" style={{ display: "block" }}>
              {user.email}
            </span>
            <span className="faint" style={{ fontSize: "var(--fs-xs)" }}>
              Membre depuis le {formatDate(user.date_joined)}
            </span>
          </div>
        </div>
        <Button variant="ghost" to="/app/profile" icon={UserRound}>
          Modifier mon profil
        </Button>
      </section>

      <section className="card card-pad" aria-label="Sécurité">
        <div className="card-head">
          <div>
            <h2 className="card-title">Sécurité du compte</h2>
            <p className="card-sub">Un mot de passe solide protège votre accès à la plateforme.</p>
          </div>
        </div>
        <div className="alert alert-gold" style={{ marginBottom: 18 }}>
          <KeyRound size={18} />
          <span>Utilisez un mot de passe unique, d'au moins 8 caractères, et changez-le s'il a pu être exposé.</span>
        </div>
        <Button variant="gold" to="/app/profile" icon={ShieldCheck}>
          Changer mon mot de passe
        </Button>
      </section>
    </div>
  );
}

export default function Dashboard() {
  useDocumentTitle("Tableau de bord");
  const { user, isAdmin } = useAuth();
  return (
    <>
      <CommandBanner user={user} />
      <UrlAnalysisForm role={user.role} />
      {isAdmin ? <AdminOverview /> : <MemberOverview user={user} />}
      <Roadmap />
    </>
  );
}
