import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

/**
 * Bouton « Retour ».
 *  - avec `to` : lien fixe (ex. retour à l'accueil depuis la connexion)
 *  - sans `to` : revient à la page précédente de l'historique, sinon à l'accueil
 * tone="sky" pour les fonds sombres des bandeaux héroïques.
 */
export default function BackLink({ to, label = "Retour", tone }) {
  const navigate = useNavigate();
  const location = useLocation();
  const cls = `back-link ${tone === "sky" ? "back-sky" : ""}`;

  if (to) {
    return (
      <Link to={to} className={cls}>
        <ArrowLeft size={17} aria-hidden="true" /> {label}
      </Link>
    );
  }
  return (
    <button
      type="button"
      className={cls}
      onClick={() => (location.key !== "default" ? navigate(-1) : navigate("/"))}
    >
      <ArrowLeft size={17} aria-hidden="true" /> {label}
    </button>
  );
}
