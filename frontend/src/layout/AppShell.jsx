import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { Activity, BadgeCheck, Bell, BookOpen, ChevronDown, Cpu, ExternalLink, Inbox, KeyRound, LayoutDashboard, LogOut, Menu as MenuIcon, ScrollText, ShieldBan, SlidersHorizontal, UserRound, Users } from "lucide-react";
import { ENDPOINTS, ROLES } from "../api/constants";
import { listNotifications } from "../api/notifications";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import Logo from "../components/brand/Logo";
import Avatar from "../components/ui/Avatar";
import { Menu, MenuItem, MenuSeparator } from "../components/ui/Menu";
import ThemeToggle from "../components/ui/ThemeToggle";
import { displayName } from "../utils/format";

const MAIN_NAV = [
  { to: "/app", label: "Tableau de bord", icon: LayoutDashboard, end: true },
  { to: "/notifications", label: "Notifications", icon: Bell },
  { to: "/app/profile", label: "Mon profil", icon: UserRound },
];
const ANALYST_NAV = [
  { to: "/review", label: "File de revue", icon: Inbox },
  { to: "/blocklist", label: "Blocklist", icon: ShieldBan },
];
const ADMIN_NAV = [
  { to: "/app/admin/users", label: "Utilisateurs", icon: Users },
  { to: "/app/admin/models", label: "Versions du modèle", icon: Cpu },
  { to: "/app/admin/settings", label: "Réglages de détection", icon: SlidersHorizontal },
  { to: "/app/admin/health", label: "Santé du système", icon: Activity },
  { to: "/app/admin/api-keys", label: "Clés API", icon: KeyRound },
  { to: "/admin/brands", label: "Marques protégées", icon: BadgeCheck },
  { to: "/app/admin/audit", label: "Journal d'audit", icon: ScrollText },
];
const TITLES = {
  "/app": "Tableau de bord",
  "/app/profile": "Mon profil",
  "/notifications": "Notifications",
  "/review": "File de revue",
  "/blocklist": "Blocklist",
  "/app/admin/users": "Utilisateurs",
  "/app/admin/models": "Versions du modèle",
  "/app/admin/settings": "Réglages de détection",
  "/app/admin/health": "Santé du système",
  "/app/admin/api-keys": "Clés API",
  "/admin/brands": "Marques protégées",
  "/app/admin/audit": "Journal d'audit",
};

function titleFor(pathname) {
  if (TITLES[pathname]) return TITLES[pathname];
  if (pathname.startsWith("/review/")) return "Examen du cas";
  if (pathname.startsWith("/scans/")) return "Détail du scan";
  return "Page";
}

export default function AppShell() {
  const { user, isAdmin, isAnalystOrAdmin, logout } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);

  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [pathname]);
  useEffect(() => {
    let active = true;
    const load = () => {
      listNotifications({ page_size: 1 })
        .then((data) => {
          if (active) setUnread(data?.unread_count || 0);
        })
        .catch(() => {});
    };
    load();
    window.addEventListener("pm:notifications-changed", load);
    return () => {
      active = false;
      window.removeEventListener("pm:notifications-changed", load);
    };
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

          {isAnalystOrAdmin && (
            <>
              <div className="nav-title">Analyse</div>
              {ANALYST_NAV.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
                  <Icon size={20} aria-hidden="true" />
                  {label}
                </NavLink>
              ))}
            </>
          )}

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
              Phishing Multimodal <span className="faint">/</span> <b>{titleFor(pathname)}</b>
            </span>
          </div>
          <div className="topbar-right">
            <Link
              to="/notifications"
              className="icon-btn notif-btn"
              aria-label={unread ? `Notifications, ${unread} non lue${unread > 1 ? "s" : ""}` : "Notifications"}
            >
              <Bell size={20} aria-hidden="true" />
              {unread > 0 && (
                <span className="notif-dot" aria-hidden="true">
                  {unread > 9 ? "9+" : unread}
                </span>
              )}
            </Link>
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
