import { Home } from "lucide-react";
import Button from "../components/ui/Button";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFound() {
  useDocumentTitle("Page introuvable");
  return (
    <div className="fullscreen-center">
      <div className="splash">
        <div className="error-code">404</div>
        <h1 style={{ fontSize: "var(--fs-xl)" }}>Cette page n'existe pas</h1>
        <p className="muted" style={{ maxWidth: "42ch" }}>
          L'adresse saisie est incorrecte ou la page a été déplacée.
        </p>
        <Button variant="gold" icon={Home} to="/">
          Retour à l'accueil
        </Button>
      </div>
    </div>
  );
}
