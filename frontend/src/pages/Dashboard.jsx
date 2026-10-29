import { ArrowRight, History, KeyRound, Plus, ShieldCheck, UserRound } from "lucide-react";
import { Link } from "react-router-dom";
import { ROLES } from "../api/constants";
import { getScanQuota, listScans } from "../api/scans";
import { useAuth } from "../context/AuthContext";
import AdminOverview from "../components/admin/AdminOverview";
import AegisEmblem from "../components/brand/AegisEmblem";
import { ScanStatusBadge, VerdictBadge, RoleBadge, ROLE_META } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import SafeUrl from "../components/ui/SafeUrl";
import { Skeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { displayName, formatDate, formatNumber, relativeTime } from "../utils/format";

function greeting() {
  return new Date().getHours() >= 18 ? "Bonsoir" : "Bonjour";
}

const LEAD = {
  admin: "Pilotez les comptes, les modèles et la santé de la plateforme depuis cet espace.",
  analyst: "Examinez les scans incertains et les signalements, puis vérifiez vos propres liens.",
  end_user: "Vérifiez un lien, suivez vos analyses et signalez un verdict erroné.",
};

function CommandBanner({ user }) {
  const name = user.first_name || (user.email ? user.email.split("@")[0] : "Utilisateur");
  const today = new Intl.DateTimeFormat("fr-FR", { weekday: "long", day: "numeric", month: "long", year: "numeric" }).format(new Date());
  const meta = ROLE_META[user.role] || ROLE_META.end_user;
  const RoleIcon = meta.icon;
  return (
    <section className="command" aria-label="Accueil">
      <div>
        <h1 className="command-title">
          {greeting()}, {name}
        </h1>
        <p className="command-lead">{LEAD[user.role] || LEAD.end_user}</p>
        <div className="command-meta">
          <span className="badge badge-nodot">
            <RoleIcon size={14} aria-hidden="true" /> {ROLES[user.role]?.label || user.role}
          </span>
          <span className="command-date">{today.charAt(0).toUpperCase() + today.slice(1)}</span>
        </div>
      </div>
      <AegisEmblem className="command-emblem" />
    </section>
  );
}

function ScanOverview() {
  const scans = useAsync((signal) => listScans({ page_size: 5 }, signal), []);
  const quota = useAsync((signal) => getScanQuota(signal), []);
  const rows = scans.data?.results || [];

  return (
    <div className="dash-grid even">
      <section className="card card-pad" aria-labelledby="recent-scans-title" data-testid="recent-scans">
        <div className="card-head">
          <div>
            <h2 id="recent-scans-title" className="card-title">Analyses récentes</h2>
            <p className="card-sub">Vos cinq derniers scans, du plus récent au plus ancien.</p>
          </div>
          <div className="toggle-group">
            <Button variant="ghost" size="sm" to="/scans" icon={History}>
              Tout voir
            </Button>
            <Button variant="gold" size="sm" to="/scans/new" icon={Plus}>
              Nouveau scan
            </Button>
          </div>
        </div>

        {scans.loading && !scans.data ? (
          <div className="stack-sm">
            {Array.from({ length: 4 }, (_, index) => (
              <Skeleton key={index} h={44} r={10} />
            ))}
          </div>
        ) : scans.error ? (
          <p className="alert alert-error" role="alert">
            Impossible de charger vos analyses : {scans.error.message || "erreur inconnue"}.
          </p>
        ) : rows.length === 0 ? (
          <div className="dashboard-empty">
            <p className="muted">Aucune analyse pour le moment.</p>
            <Button variant="gold" to="/scans/new" icon={ArrowRight}>
              Lancer mon premier scan
            </Button>
          </div>
        ) : (
          <ul className="dash-scan-list">
            {rows.map((scan) => (
              <li key={scan.id}>
                <Link to={`/scans/${scan.id}`} className="dash-scan-row">
                  <span className="dash-scan-main">
                    <strong className="truncate"><SafeUrl value={scan.domain || scan.url} /></strong>
                    <span className="faint">{relativeTime(scan.created_at)}</span>
                  </span>
                  <span className="dash-scan-badges">
                    <VerdictBadge verdict={scan.verdict} />
                    <ScanStatusBadge status={scan.status} />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card card-pad" aria-labelledby="dash-quota-title" data-testid="dashboard-quota">
        <div className="card-head">
          <div>
            <h2 id="dash-quota-title" className="card-title">Quota du jour</h2>
            <p className="card-sub">Votre capacité de scans complets.</p>
          </div>
        </div>
        {quota.loading && !quota.data ? (
          <Skeleton h={24} w="50%" />
        ) : quota.error ? (
          <p className="muted" style={{ margin: 0 }}>Quota indisponible pour le moment.</p>
        ) : quota.data ? (
          <>
            <div className="quota-number">
              <strong>{formatNumber(quota.data.remaining)}</strong>
              <span>restant{quota.data.remaining === 1 ? "" : "s"} sur {formatNumber(quota.data.limit)}</span>
            </div>
            <div className="quota-meter" aria-hidden="true">
              <span
                style={{
                  width: `${quota.data.limit > 0 ? Math.min(100, (quota.data.used / quota.data.limit) * 100) : 0}%`,
                }}
                className={quota.data.remaining <= 0 ? "is-empty" : ""}
              />
            </div>
            <p className="muted" style={{ margin: "10px 0 16px", fontSize: "var(--fs-xs)" }}>
              Réinitialisation le {new Date(quota.data.reset_at).toLocaleString("fr-FR")}.
            </p>
            <Button variant="ghost" to="/scans" icon={History}>
              Consulter mon historique
            </Button>
          </>
        ) : null}
      </section>
    </div>
  );
}

function MemberOverview({ user }) {
  return (
    <div className="dash-grid even">
      <section className="card card-pad" aria-label="Votre compte">
        <div className="card-head">
          <div>
            <h2 className="card-title">Votre compte</h2>
            <p className="card-sub">{(ROLE_META[user.role] || ROLE_META.end_user).desc}</p>
          </div>
          <RoleBadge role={user.role} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
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
      <ScanOverview />
      {isAdmin ? <AdminOverview /> : <MemberOverview user={user} />}
    </>
  );
}
