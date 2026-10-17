import { KeyRound, Layers, ScrollText } from "lucide-react";
import AegisEmblem from "../components/brand/AegisEmblem";
import Logo from "../components/brand/Logo";
import BackLink from "../components/ui/BackLink";
import ThemeToggle from "../components/ui/ThemeToggle";

export default function AuthLayout({ children }) {
  return (
    <div className="auth">
      <section className="auth-hero">
        <Logo to="/" />
        <AegisEmblem className="auth-emblem" />
        <div className="auth-copy">
          <p className="hero-title">Défendez chaque boîte de réception.</p>
          <p className="hero-lead">
            Un seul poste de commandement pour détecter le phishing, gérer les accès de vos équipes et garder une trace de
            chaque décision.
          </p>
          <ul className="proofs">
            <li>
              <span className="ico">
                <Layers size={18} />
              </span>
              Détection multimodale : e-mails, liens, images et textes
            </li>
            <li>
              <span className="ico">
                <KeyRound size={18} />
              </span>
              Accès par rôle : administrateur, analyste ou lecteur
            </li>
            <li>
              <span className="ico">
                <ScrollText size={18} />
              </span>
              Journal d'audit en lecture seule : chaque action sensible est tracée
            </li>
          </ul>
        </div>
      </section>

      <main className="auth-panel">
        <div className="auth-panel-top">
          <ThemeToggle />
        </div>
        <div className="auth-card">
          <BackLink to="/" label="Retour à l'accueil" />
          <div className="auth-mobile-brand">
            <Logo to="/" size={44} sub="Détection du phishing" />
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
