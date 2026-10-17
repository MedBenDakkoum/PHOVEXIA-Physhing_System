import { Cpu, KeyRound, ScrollText, ShieldCheck } from "lucide-react";
import AegisEmblem from "../../components/brand/AegisEmblem";
import Button from "../../components/ui/Button";
import PageHero from "../../components/ui/PageHero";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";

const STEPS = [
  { title: "Créez votre compte", text: "L'inscription ne demande que votre e-mail et un mot de passe solide. Vous démarrez avec le rôle Lecteur." },
  { title: "Un administrateur ajuste votre rôle", text: "Selon votre mission, il vous attribue le rôle Analyste ou Administrateur. Chaque changement est consigné." },
  { title: "Travaillez dans votre espace", text: "Tableau de bord, profil, gestion des comptes et journal d'audit s'adaptent à ce que votre rôle vous permet." },
];

const PRINCIPLES = [
  { icon: ShieldCheck, title: "Sécurité d'abord", text: "Authentification par jetons, sessions de 15 minutes, révocation à la déconnexion et limitation du nombre de requêtes." },
  { icon: ScrollText, title: "Traçabilité complète", text: "Le journal d'audit est en lecture seule : aucune entrée ne peut être modifiée ni supprimée, même par un administrateur." },
  { icon: KeyRound, title: "Moindre privilège", text: "Chacun n'accède qu'à ce que son rôle exige. Les rôles ne se choisissent jamais à l'inscription." },
  { icon: Cpu, title: "Prête à évoluer", text: "Les décisions, la blocklist et les mises à jour du modèle sont déjà prévues dans le journal d'audit." },
];

const STACK = ["Django REST Framework", "JSON Web Tokens", "React", "API documentée (OpenAPI)"];

export default function About() {
  useDocumentTitle("À propos");
  return (
    <>
      <PageHero
        title="À propos de la plateforme"
        lead="Phishing Multimodal est né d'un constat simple : les attaques d'hameçonnage ne se limitent plus à un e-mail. Il faut les regarder sous tous leurs angles, avec des équipes qui savent qui fait quoi."
      />

      <section className="section">
        <div className="split split-center">
          <div>
            <h2 className="section-title">Notre mission</h2>
            <p className="prose">
              Donner à chaque équipe de sécurité un poste de commandement clair pour détecter le phishing, décider vite et garder
              la preuve de ce qui a été fait.
            </p>
            <p className="prose">
              « Multimodal » signifie que la plateforme est conçue pour analyser ensemble les e-mails, les liens, les images et les
              textes, plutôt que de les traiter en silos.
            </p>
            <div className="chip-row" aria-label="Technologies">
              {STACK.map((s) => (
                <span className="badge badge-gold badge-nodot" key={s}>
                  {s}
                </span>
              ))}
            </div>
          </div>
          <div className="about-emblem" aria-hidden="true">
            <AegisEmblem minimal />
          </div>
        </div>
      </section>

      <section className="section section-tint" aria-labelledby="steps-title">
        <div className="section-head">
          <h2 id="steps-title" className="section-title">
            Comment ça marche
          </h2>
        </div>
        <ol className="steps">
          {STEPS.map((s, i) => (
            <li className="step" key={s.title}>
              <span className="step-n" aria-hidden="true">
                {i + 1}
              </span>
              <div>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="section" aria-labelledby="principles-title">
        <div className="section-head">
          <h2 id="principles-title" className="section-title">
            Nos principes
          </h2>
        </div>
        <div className="principles">
          {PRINCIPLES.map(({ icon: Icon, title, text }) => (
            <div className="principle" key={title}>
              <span className="row-ico">
                <Icon size={24} />
              </span>
              <h3>{title}</h3>
              <p>{text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="sky cta-band">
        <div className="cta-in">
          <div>
            <h2 className="cta-title">Une question avant de commencer ?</h2>
            <p className="hero-lead" style={{ marginTop: 10 }}>
              Écrivez-nous, nous vous répondrons dès que possible.
            </p>
          </div>
          <div className="hero-cta" style={{ marginTop: 0 }}>
            <Button variant="gold" size="lg" to="/contact">
              Nous contacter
            </Button>
            <Button variant="ghost" size="lg" to="/location">
              Où nous trouver
            </Button>
          </div>
        </div>
      </section>
    </>
  );
}
