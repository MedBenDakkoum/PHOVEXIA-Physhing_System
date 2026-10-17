import { ArrowRight, Crown, Eye, Image, KeyRound, Link2, LogIn, MessageSquareText, Mail, Radar, ScrollText, ShieldCheck, UserPlus } from "lucide-react";
import AegisEmblem from "../../components/brand/AegisEmblem";
import UrlAnalysisForm from "../../components/analysis/UrlAnalysisForm";
import Button from "../../components/ui/Button";
import { useAuth } from "../../context/AuthContext";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";

const FRONTS = [
  { icon: Mail, title: "E-mails", text: "Les messages suspects qui imitent un expéditeur de confiance." },
  { icon: Link2, title: "Liens", text: "Les adresses piégées cachées derrière un texte anodin." },
  { icon: Image, title: "Images", text: "Les captures et visuels qui reproduisent une marque pour vous tromper." },
  { icon: MessageSquareText, title: "Textes", text: "Les messages dont le ton pousse à agir sans réfléchir." },
];

const GUARANTEES = [
  {
    icon: KeyRound,
    title: "Chacun voit ce qu'il doit voir",
    text: "Trois rôles, Administrateur, Analyste et Lecteur, déterminent l'accès. Les nouveaux comptes démarrent en Lecteur.",
  },
  {
    icon: ScrollText,
    title: "Une mémoire qui ne se réécrit pas",
    text: "Connexions, échecs, changements de rôle, suspensions : chaque action sensible est consignée et ne peut plus être modifiée.",
  },
  {
    icon: ShieldCheck,
    title: "Des sessions courtes et révocables",
    text: "L'accès expire après 15 minutes et se renouvelle seul. La déconnexion révoque immédiatement la session.",
  },
];

const ROLES = [
  { icon: Crown, name: "Administrateur", text: "Gère les comptes et les rôles, suspend un accès, consulte tout le journal d'audit.", lead: true },
  { icon: Radar, name: "Analyste", text: "Travaille dans l'espace d'analyse. Les modules de détection le rejoindront à leur mise en service." },
  { icon: Eye, name: "Lecteur", text: "Consulte en lecture seule. C'est le rôle attribué à chaque nouvelle inscription." },
];

export default function Home() {
  useDocumentTitle("");
  const { status } = useAuth();
  const connected = status === "authenticated";

  return (
    <>
      <section className="sky">
        <div className="home-hero">
          <div>
            <h1 className="hero-title">Repérez l'hameçonnage avant qu'il ne frappe.</h1>
            <p className="hero-lead">
              Phishing Multimodal réunit sur une seule plateforme la détection des menaces, la gestion des accès de vos équipes et
              la traçabilité de chaque décision.
            </p>
            <div className="hero-cta">
              {connected ? (
                <Button variant="gold" size="lg" to="/app" iconRight={ArrowRight}>
                  Ouvrir mon espace
                </Button>
              ) : (
                <>
                  <Button variant="gold" size="lg" to="/login" icon={LogIn}>
                    Se connecter
                  </Button>
                  
                </>
              )}
              <Button variant="quiet" size="lg" to="/about" iconRight={ArrowRight} className="sky-quiet">
                Découvrir
              </Button>
            </div>
            <ul className="pill-row" aria-label="Points clés">
              <li>Accès par rôle</li>
              <li>Journal d'audit en lecture seule</li>
              <li>Sessions de 15 minutes</li>
            </ul>
          </div>
          <div className="home-emblem" aria-hidden="true">
            <AegisEmblem />
          </div>
        </div>
      </section>

      <section className="section home-url-section" aria-label="Vérifier une adresse web">
        <UrlAnalysisForm role="guest" />
      </section>

      <section className="section" aria-labelledby="fronts-title">
        <div className="section-head">
          <h2 id="fronts-title" className="section-title">
            Quatre fronts, un seul bouclier
          </h2>
          <p className="muted">
            Une attaque de phishing prend toutes les formes. La plateforme est pensée pour les regarder ensemble, pas séparément.
          </p>
        </div>
        <div className="pillars">
          {FRONTS.map(({ icon: Icon, title, text }) => (
            <div className="pillar" key={title}>
              <span className="pillar-ico">
                <Icon size={30} />
              </span>
              <h3>{title}</h3>
              <p>{text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section section-tint" aria-labelledby="guarantees-title">
        <div className="split">
          <div className="split-lead">
            <h2 id="guarantees-title" className="section-title">
              Conçue pour qu'on puisse lui faire confiance
            </h2>
            <p className="muted">
              Une plateforme de sécurité doit d'abord être irréprochable sur sa propre sécurité. Trois garanties, intégrées dès la
              conception.
            </p>
            <Button variant="ghost" to="/about" iconRight={ArrowRight} style={{ marginTop: 22 }}>
              En savoir plus
            </Button>
          </div>
          <ul className="rows">
            {GUARANTEES.map(({ icon: Icon, title, text }) => (
              <li className="row" key={title}>
                <span className="row-ico">
                  <Icon size={24} />
                </span>
                <div>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="section" aria-labelledby="roles-title">
        <div className="section-head">
          <h2 id="roles-title" className="section-title">
            Un rôle pour chaque mission
          </h2>
        </div>
        <div className="role-cards">
          {ROLES.map(({ icon: Icon, name, text, lead }) => (
            <article className={`role-card ${lead ? "lead" : ""}`} key={name}>
              <span className="role-card-ico">
                <Icon size={26} />
              </span>
              <h3>{name}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="sky cta-band">
        <div className="cta-in">
          <div>
            <h2 className="cta-title">Prenez le commandement de votre défense.</h2>
            <p className="hero-lead" style={{ marginTop: 10 }}>
              Créez votre compte en quelques secondes ou reconnectez-vous à votre espace.
            </p>
          </div>
          <div className="hero-cta" style={{ marginTop: 0 }}>
            {connected ? (
              <Button variant="gold" size="lg" to="/app" iconRight={ArrowRight}>
                Ouvrir mon espace
              </Button>
            ) : (
              <>
                <Button variant="gold" size="lg" to="/login" icon={LogIn}>
                  Se connecter
                </Button>
                <Button variant="ghost" size="lg" to="/contact">
                  Nous contacter
                </Button>
              </>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
