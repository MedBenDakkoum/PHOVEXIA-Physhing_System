import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { ROLES } from "../api/constants";
import { useAuth } from "../context/AuthContext";
import AdminOverview from "../components/admin/AdminOverview";
import AegisEmblem from "../components/brand/AegisEmblem";
import UrlAnalysisForm from "../components/analysis/UrlAnalysisForm";
import Avatar from "../components/ui/Avatar";
import { RoleBadge, ROLE_META } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { displayName, formatDate } from "../utils/format";

function greeting() {
  return new Date().getHours() >= 18 ? "Bonsoir" : "Bonjour";
}

const LEAD = {
  admin: "Pilotez les comptes, les modèles et la santé de la plateforme depuis cet espace.",
  analyst: "Collez une adresse web à vérifier et retrouvez vos outils d’analyse ici.",
  end_user: "Vous disposez d'un accès en lecture. Un administrateur peut faire évoluer votre rôle.",
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
      {isAdmin ? (
        <AdminOverview />
      ) : (
        <>
          <UrlAnalysisForm role={user.role} />
          <MemberOverview user={user} />
        </>
      )}
    </>
  );
}
