import { useState } from "react";
import { Link } from "react-router-dom";
import { CircleAlert, Info, Lock, Mail, UserPlus, UserRound } from "lucide-react";
import { ApiError } from "../api/errors";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import AuthLayout from "../layout/AuthLayout";
import Button from "../components/ui/Button";
import { PasswordField, TextField } from "../components/ui/Fields";
import PasswordMeter from "../components/ui/PasswordMeter";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { passwordChecks } from "../utils/password";

export default function Register() {
  useDocumentTitle("Créer un compte");
  const { register } = useAuth();
  const toast = useToast();
  const [form, setForm] = useState({ first_name: "", last_name: "", email: "", password: "", confirm: "" });
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
    if (!passwordChecks(form.password, form.email).every((c) => c.ok)) next.password = "Ce mot de passe ne respecte pas les critères.";
    if (form.confirm !== form.password) next.confirm = "Les mots de passe ne correspondent pas.";
    setErrors(next);
    setFormError("");
    if (Object.keys(next).length) return;

    setLoading(true);
    try {
      const me = await register({
        email: form.email,
        password: form.password,
        first_name: form.first_name.trim(),
        last_name: form.last_name.trim(),
      });
      toast.success("Compte créé", `Bienvenue, ${me.first_name || me.email}.`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        setErrors(err.fieldErrors);
        setFormError("Vérifiez les champs signalés.");
      } else {
        setFormError(err.message);
      }
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <div>
        <h1 className="auth-title">Créer un compte</h1>
        <p className="auth-sub">Rejoignez la plateforme en quelques secondes.</p>
      </div>

      <div className="alert alert-gold">
        <Info size={18} />
        <span>Votre compte est créé avec le rôle Lecteur. Un administrateur peut ensuite modifier votre rôle.</span>
      </div>
      {formError && (
        <div className="alert alert-error" role="alert">
          <CircleAlert size={18} />
          <span>{formError}</span>
        </div>
      )}

      <form className="auth-form" onSubmit={submit} noValidate>
        <div className="row2">
          <TextField
            label="Prénom"
            name="first_name"
            autoComplete="given-name"
            icon={UserRound}
            value={form.first_name}
            onChange={set("first_name")}
            error={errors.first_name}
          />
          <TextField
            label="Nom"
            name="last_name"
            autoComplete="family-name"
            value={form.last_name}
            onChange={set("last_name")}
            error={errors.last_name}
          />
        </div>
        <TextField
          label="Adresse e-mail"
          type="email"
          name="email"
          autoComplete="email"
          icon={Mail}
          placeholder="vous@entreprise.com"
          value={form.email}
          onChange={set("email")}
          error={errors.email}
        />
        <PasswordField
          label="Mot de passe"
          name="password"
          autoComplete="new-password"
          icon={Lock}
          value={form.password}
          onChange={set("password")}
          error={errors.password}
        />
        {form.password && <PasswordMeter password={form.password} email={form.email} />}
        <PasswordField
          label="Confirmer le mot de passe"
          name="confirm"
          autoComplete="new-password"
          icon={Lock}
          value={form.confirm}
          onChange={set("confirm")}
          error={errors.confirm}
        />
        <Button type="submit" variant="gold" size="lg" block loading={loading} icon={UserPlus}>
          Créer mon compte
        </Button>
      </form>

      <p className="auth-foot">
        Déjà inscrit ? <Link to="/login">Se connecter</Link>
      </p>
    </AuthLayout>
  );
}
