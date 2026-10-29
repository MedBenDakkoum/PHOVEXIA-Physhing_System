import { Route, Routes } from "react-router-dom";
import AppShell from "./layout/AppShell";
import { PublicOnly, RequireAuth, RequireRole } from "./layout/Guards";
import PublicLayout from "./layout/PublicLayout";
import AdminApiKeys from "./pages/AdminApiKeys";
import AdminHealth from "./pages/AdminHealth";
import AdminModels from "./pages/AdminModels";
import AdminSettings from "./pages/AdminSettings";
import AuditLogs from "./pages/AuditLogs";
import Blocklist from "./pages/Blocklist";
import Brands from "./pages/Brands";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import Notifications from "./pages/Notifications";
import Profile from "./pages/Profile";
import Register from "./pages/Register";
import ReviewDetail from "./pages/ReviewDetail";
import ReviewQueue from "./pages/ReviewQueue";
import ScanDetail from "./pages/ScanDetail";
import ScanNew from "./pages/ScanNew";
import ScansHistory from "./pages/ScansHistory";
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
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route path="app" element={<Dashboard />} />
          <Route path="app/profile" element={<Profile />} />
          <Route path="scans" element={<ScansHistory />} />
          <Route path="scans/new" element={<ScanNew />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="notifications" element={<Notifications />} />

          <Route element={<RequireRole roles={["admin", "analyst"]} />}>
            <Route path="review" element={<ReviewQueue />} />
            <Route path="review/:id" element={<ReviewDetail />} />
            <Route path="blocklist" element={<Blocklist />} />
          </Route>

          <Route element={<RequireRole roles={["admin"]} />}>
            <Route path="app/admin/users" element={<Users />} />
            <Route path="app/admin/models" element={<AdminModels />} />
            <Route path="app/admin/settings" element={<AdminSettings />} />
            <Route path="app/admin/health" element={<AdminHealth />} />
            <Route path="app/admin/api-keys" element={<AdminApiKeys />} />
            <Route path="app/admin/audit" element={<AuditLogs />} />
            <Route path="admin/brands" element={<Brands />} />
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
