import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { ArrowRight, LogIn, Mail, MapPin, Menu as MenuIcon, X } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { SITE } from "../config/site";
import Logo from "../components/brand/Logo";
import Button from "../components/ui/Button";
import ThemeToggle from "../components/ui/ThemeToggle";
import { Skeleton } from "../components/ui/States";

const LINKS = [
  { to: "/", label: "Accueil", end: true },
  { to: "/about", label: "À propos" },
  { to: "/location", label: "Localisation" },
  { to: "/contact", label: "Contact" },
];

function AccountButtons({ block, onNavigate, hideRegister }) {
  const { status } = useAuth();
  if (status === "authenticated") {
    return (
      <Button variant="gold" to="/app" iconRight={ArrowRight} block={block} onClick={onNavigate}>
        Mon espace
      </Button>
    );
  }
  if (status === "loading") return <Skeleton w={132} h={42} r={10} />;
  return (
    <>
      {!hideRegister && (
        <Button variant="ghost" to="/register" className={block ? "" : "hide-m"} block={block} onClick={onNavigate}>
          Créer un compte
        </Button>
      )}
      <Button variant="gold" to="/login" icon={LogIn} block={block} onClick={onNavigate}>
        Se connecter
      </Button>
    </>
  );
}

export default function PublicLayout() {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const hideRegister = ["/", "/about", "/location", "/contact"].includes(pathname);

  // Le drapeau de déconnexion volontaire a rempli son rôle une fois l'accueil affiché
  useEffect(() => {
    sessionStorage.removeItem("pm.loggedOut");
  }, []);

  useEffect(() => {
    setOpen(false);
    window.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <div className="pub">
      <a href="#contenu-public" className="skip-link">
        Aller au contenu
      </a>
      <header className="pub-header">
        <div className="pub-header-in">
          <Logo to="/" sub={null} />
          <nav className="pub-nav" aria-label="Navigation du site">
            {LINKS.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => `pub-link ${isActive ? "active" : ""}`}>
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="pub-actions">
            <ThemeToggle />
            <AccountButtons hideRegister={hideRegister} />
            <button
              className="icon-btn pub-burger"
              onClick={() => setOpen((o) => !o)}
              aria-label={open ? "Fermer le menu" : "Ouvrir le menu"}
              aria-expanded={open}
            >
              {open ? <X size={22} /> : <MenuIcon size={22} />}
            </button>
          </div>
        </div>
        <div className={`pub-mobile ${open ? "open" : ""}`}>
          {LINKS.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => `pub-link ${isActive ? "active" : ""}`}>
              {l.label}
            </NavLink>
          ))}
          <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
            <AccountButtons block hideRegister={hideRegister} onNavigate={() => setOpen(false)} />
          </div>
        </div>
      </header>

      <main id="contenu-public" className="pub-main">
        <div key={pathname} className="page-in">
          <Outlet />
        </div>
      </main>

      <footer className="pub-footer">
        <div className="pub-footer-in">
          <div className="foot-brand">
            <Logo to="/" sub={null} />
            <p className="muted">Plateforme de détection du phishing : accès par rôle, sessions sécurisées et journal d'audit.</p>
          </div>
          <div>
            <h3 className="foot-title">Le site</h3>
            <ul className="foot-list">
              {LINKS.map((l) => (
                <li key={l.to}>
                  <Link to={l.to}>{l.label}</Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="foot-title">Espace membre</h3>
            <ul className="foot-list">
              <li>
                <Link to="/login">Se connecter</Link>
              </li>
              <li>
                <Link to="/register">Créer un compte</Link>
              </li>
            </ul>
          </div>
          <div>
            <h3 className="foot-title">Nous joindre</h3>
            <ul className="foot-list">
              <li>
                <a href={`mailto:${SITE.email}`}>
                  <Mail size={15} /> {SITE.email}
                </a>
              </li>
              <li>
                <Link to="/location">
                  <MapPin size={15} /> {SITE.address.city}, {SITE.address.country}
                </Link>
              </li>
            </ul>
          </div>
        </div>
        <div className="pub-footer-bar">© {new Date().getFullYear()} {SITE.name}. Tous droits réservés.</div>
      </footer>
    </div>
  );
}
