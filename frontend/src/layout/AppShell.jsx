import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { BookOpen, ChevronDown, ExternalLink, LayoutDashboard, LogOut, Menu as MenuIcon, ScrollText, UserRound, Users } from "lucide-react";
import { ENDPOINTS, ROLES } from "../api/constants";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import Logo from "../components/brand/Logo";
import Avatar from "../components/ui/Avatar";
import { Menu, MenuItem, MenuSeparator } from "../components/ui/Menu";
import ThemeToggle from "../components/ui/ThemeToggle";
import { displayName } from "../utils/format";

const MAIN_NAV = [
  { to: "/app", label: "Tableau de bord", icon: LayoutDashboard, end: true },
  { to: "/app/profile", label: "Mon profil", icon: UserRound },
];
const ADMIN_NAV = [
  { to: "/app/admin/users", label: "Utilisateurs", icon: Users },
  { to: "/app/admin/audit", label: "Journal d'audit", icon: ScrollText },
];
const TITLES = {
  "/app": "Tableau de bord",
  "/app/profile": "Mon profil",
  "/app/admin/users": "Utilisateurs",
  "/app/admin/audit": "Journal d'audit",
};

export default function AppShell() {
  const { user, isAdmin, logout } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);

  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [pathname]);

  const onLogout = async () => {
    await logout();
    toast.info("À bientôt", "Vous êtes déconnecté.");
    navigate("/", { replace: true });
  };

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Navigation principale">
        <Logo to="/app" />
        <nav className="nav">
          {MAIN_NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <Icon size={20} aria-hidden="true" />
              {label}
            </NavLink>
          ))}

          {isAdmin && (
            <>
              <div className="nav-title">Administration</div>
              {ADMIN_NAV.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
                  <Icon size={20} aria-hidden="true" />
                  {label}
                </NavLink>
              ))}
              <a className="nav-link" href={ENDPOINTS.docs} target="_blank" rel="noreferrer">
                <BookOpen size={20} aria-hidden="true" />
                Documentation API
                <ExternalLink size={15} className="ext" aria-hidden="true" />
              </a>
            </>
          )}
        </nav>

        <div className="sidebar-foot">
          <div className="me-card">
            <Avatar user={user} />
            <div className="who">
              <strong className="truncate">{displayName(user)}</strong>
              <span>{ROLES[user.role]?.label || user.role}</span>
            </div>
            <button className="icon-btn" onClick={onLogout} aria-label="Se déconnecter" title="Se déconnecter">
              <LogOut size={19} />
            </button>
          </div>
        </div>
      </aside>
      <div className={`scrim ${open ? "open" : ""}`} onClick={() => setOpen(false)} aria-hidden="true" />

      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-btn menu-toggle" onClick={() => setOpen(true)} aria-label="Ouvrir le menu">
              <MenuIcon size={22} />
            </button>
            <span className="crumb">
              Phishing Multimodal <span className="faint">/</span> <b>{TITLES[pathname] || "Page"}</b>
            </span>
          </div>
          <div className="topbar-right">
            <ThemeToggle />
            <Menu
              trigger={
                <button className="user-trigger" aria-label="Menu du compte">
                  <Avatar user={user} size="sm" />
                  <span className="name truncate">{displayName(user)}</span>
                  <ChevronDown size={16} className="faint" aria-hidden="true" />
                </button>
              }
            >
              <div style={{ padding: "8px 10px 10px" }}>
                <strong style={{ display: "block", fontSize: "var(--fs-sm)" }}>{displayName(user)}</strong>
                <span className="faint" style={{ fontSize: "var(--fs-xs)" }}>
                  {user.email}
                </span>
              </div>
              <MenuSeparator />
              <MenuItem icon={UserRound} onClick={() => navigate("/app/profile")}>
                Mon profil
              </MenuItem>
              <MenuItem icon={LogOut} danger onClick={onLogout}>
                Se déconnecter
              </MenuItem>
            </Menu>
          </div>
        </header>
        <main className="page" id="contenu">
          <div key={pathname} className="page-in">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
