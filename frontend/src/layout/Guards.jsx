import { Navigate, Outlet, useLocation } from "react-router-dom";
import { Lock, RefreshCw, WifiOff } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import AegisEmblem from "../components/brand/AegisEmblem";
import Button from "../components/ui/Button";
import { EmptyState } from "../components/ui/States";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export function Splash({ message = "Vérification de votre session…" }) {
  return (
    <div className="fullscreen-center">
      <div className="splash" role="status">
        <AegisEmblem className="splash-emblem" minimal />
        <p className="muted">{message}</p>
      </div>
    </div>
  );
}

function Offline() {
  const { retryBoot } = useAuth();
  return (
    <div className="fullscreen-center">
      <EmptyState
        icon={WifiOff}
        title="Serveur injoignable"
        action={
          <Button variant="gold" icon={RefreshCw} onClick={retryBoot}>
            Réessayer
          </Button>
        }
      >
        Impossible de joindre l'API. Vérifiez que le backend Django est lancé, puis réessayez. Votre session est conservée.
      </EmptyState>
    </div>
  );
}

/** Pages réservées aux utilisateurs connectés. */
export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "loading") return <Splash />;
  if (status === "offline") return <Offline />;
  if (status !== "authenticated") {
    // Après une déconnexion volontaire, on revient à l'accueil plutôt qu'à la page de connexion.
    if (sessionStorage.getItem("pm.loggedOut")) return <Navigate to="/" replace />;
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return <Outlet />;
}

/** Pages de connexion / inscription : inaccessibles une fois connecté. */
export function PublicOnly() {
  const { status } = useAuth();
  const location = useLocation();
  if (status === "loading") return <Splash />;
  if (status === "offline") return <Offline />;
  if (status === "authenticated") {
    const from = location.state?.from;
    return <Navigate to={from ? `${from.pathname}${from.search || ""}` : "/app"} replace />;
  }
  return <Outlet />;
}

function Forbidden() {
  useDocumentTitle("Accès refusé");
  return (
    <div className="card">
      <EmptyState
        icon={Lock}
        title="Accès non autorisé"
        action={
          <Button variant="gold" to="/app">
            Retour au tableau de bord
          </Button>
        }
      >
        Votre rôle ne permet pas d'ouvrir cette page. Contactez un administrateur si vous pensez que c'est une erreur.
      </EmptyState>
    </div>
  );
}

/** Pages réservées à certains rôles (cf. IsAdminRole côté backend). */
export function RequireRole({ roles }) {
  const { user } = useAuth();
  if (!roles.includes(user?.role)) return <Forbidden />;
  return <Outlet />;
}
