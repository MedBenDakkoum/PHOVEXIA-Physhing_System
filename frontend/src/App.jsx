import { Route, Routes } from "react-router-dom";
import AppShell from "./layout/AppShell";
import { PublicOnly, RequireAuth, RequireRole } from "./layout/Guards";
import PublicLayout from "./layout/PublicLayout";
import AuditLogs from "./pages/AuditLogs";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import Profile from "./pages/Profile";
import Register from "./pages/Register";
import Users from "./pages/Users";
import About from "./pages/public/About";
import Contact from "./pages/public/Contact";
import Home from "./pages/public/Home";
import Location from "./pages/public/Location";

export default function App() {
  return (
    <Routes>
      {/* Site public : la page d'accueil s'ouvre en premier */}
      <Route element={<PublicLayout />}>
        <Route index element={<Home />} />
        <Route path="about" element={<About />} />
        <Route path="location" element={<Location />} />
        <Route path="contact" element={<Contact />} />
      </Route>

      {/* Connexion / inscription (inaccessibles une fois connecté) */}
      <Route element={<PublicOnly />}>
        <Route path="login" element={<Login />} />
        <Route path="register" element={<Register />} />
      </Route>

      {/* Application (utilisateurs connectés) */}
      <Route path="app" element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="profile" element={<Profile />} />
          <Route element={<RequireRole roles={["admin"]} />}>
            <Route path="admin/users" element={<Users />} />
            <Route path="admin/audit" element={<AuditLogs />} />
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
