import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { CircleAlert, Info, LogIn, Mail, Lock } from "lucide-react";
import { ApiError } from "../api/errors";
import { useAuth } from "../context/AuthContext";
import AuthLayout from "../layout/AuthLayout";
import Button from "../components/ui/Button";
import { PasswordField, TextField } from "../components/ui/Fields";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function Login() {
  useDocumentTitle("Connexion");
  const { login } = useAuth();
  const location = useLocation();
  const [form, setForm] = useState({ email: "", password: "" });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [loading, setLoading] = useState(false);

  const set = (k) => (e) => {
    setForm((f) => ({ ...f, [k]: e.target.value }));
    setErrors((er) => ({ ...er, [k]: undefined }));
  };

  const submit = async (e) => {
    e.preventDefault();
    const next = {};
    if (!form.email.trim()) next.email = "Saisissez votre adresse e-mail.";
    else if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) next.email = "Saisissez une adresse e-mail valide.";
    if (!form.password) next.password = "Saisissez votre mot de passe.";
    setErrors(next);
    setFormError("");
    if (Object.keys(next).length) return;

    setLoading(true);
    try {
      await login(form); // PublicOnly redirige ensuite vers la page demandée
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setErrors(err.fieldErrors);
      setFormError(err.message);
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <div>
        <h1 className="auth-title">Connexion</h1>
        <p className="auth-sub">Reprenez votre poste de commandement.</p>
      </div>

      {location.state?.from && !formError && (
        <div className="alert alert-info" role="status">
          <Info size={18} />
          <span>Connectez-vous pour accéder à cette page.</span>
        </div>
      )}
      {formError && (
        <div className="alert alert-error" role="alert">
          <CircleAlert size={18} />
          <span>{formError}</span>
        </div>
      )}

      <form className="auth-form" onSubmit={submit} noValidate>
        <TextField
          label="Adresse e-mail"
          type="email"
          name="email"
          autoComplete="email"
          autoFocus
          icon={Mail}
          placeholder="vous@entreprise.com"
          value={form.email}
          onChange={set("email")}
          error={errors.email}
        />
        <PasswordField
          label="Mot de passe"
          name="password"
          autoComplete="current-password"
          icon={Lock}
          placeholder="Votre mot de passe"
          value={form.password}
          onChange={set("password")}
          error={errors.password}
        />
        <Button type="submit" variant="gold" size="lg" block loading={loading} icon={LogIn}>
          Se connecter
        </Button>
      </form>

      <p className="auth-foot">
        Pas encore de compte ? <Link to="/register">Créer un compte</Link>
      </p>
    </AuthLayout>
  );
}
