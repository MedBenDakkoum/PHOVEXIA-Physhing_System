import { useEffect, useState } from "react";
import { CircleAlert, Lock, LogOut, Save, ShieldCheck } from "lucide-react";
import { changePassword } from "../api/auth";
import { ROLES } from "../api/constants";
import { ApiError } from "../api/errors";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import Avatar from "../components/ui/Avatar";
import { RoleBadge, ROLE_META } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { PasswordField, TextField } from "../components/ui/Fields";
import PageHeader from "../components/ui/PageHeader";
import PasswordMeter from "../components/ui/PasswordMeter";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { displayName, formatDate } from "../utils/format";
import { passwordChecks } from "../utils/password";

function InfoForm() {
  const { user, updateProfile } = useAuth();
  const toast = useToast();
  const [form, setForm] = useState({ first_name: user.first_name || "", last_name: user.last_name || "" });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setForm({ first_name: user.first_name || "", last_name: user.last_name || "" });
  }, [user.first_name, user.last_name]);

  const dirty = form.first_name !== (user.first_name || "") || form.last_name !== (user.last_name || "");

  const submit = async (e) => {
    e.preventDefault();
    setErrors({});
    setFormError("");
    setSaving(true);
    try {
      await updateProfile({ first_name: form.first_name.trim(), last_name: form.last_name.trim() });
      toast.success("Profil mis à jour");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setErrors(err.fieldErrors);
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="card card-pad" onSubmit={submit} noValidate>
      <div className="card-head">
        <div>
          <h2 className="card-title">Informations personnelles</h2>
          <p className="card-sub">Ces informations sont visibles par les administrateurs.</p>
        </div>
      </div>
      {formError && (
        <div className="alert alert-error" role="alert" style={{ marginBottom: 16 }}>
          <CircleAlert size={18} />
          <span>{formError}</span>
        </div>
      )}
      <div className="form-grid">
        <TextField
          label="Prénom"
          autoComplete="given-name"
          value={form.first_name}
          onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))}
          error={errors.first_name}
        />
        <TextField
          label="Nom"
          autoComplete="family-name"
          value={form.last_name}
          onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))}
          error={errors.last_name}
        />
        <div className="full">
          <TextField label="Adresse e-mail" value={user.email} disabled readOnly />
          <span className="lock-note" style={{ marginTop: 6 }}>
            <Lock size={13} /> L'adresse e-mail ne peut pas être modifiée.
          </span>
        </div>
        <div className="field full">
          <span className="field-label">Rôle</span>
          <div>
            <RoleBadge role={user.role} />
          </div>
          <span className="lock-note">
            <Lock size={13} /> Seul un administrateur peut modifier votre rôle.
          </span>
        </div>
      </div>
      <div className="form-actions">
        <Button
          variant="ghost"
          disabled={!dirty || saving}
          onClick={() => setForm({ first_name: user.first_name || "", last_name: user.last_name || "" })}
        >
          Annuler
        </Button>
        <Button type="submit" variant="gold" icon={Save} loading={saving} disabled={!dirty}>
          Enregistrer
        </Button>
      </div>
    </form>
  );
}

function PasswordForm() {
  const { user } = useAuth();
  const toast = useToast();
  const empty = { old_password: "", new_password: "", confirm: "" };
  const [form, setForm] = useState(empty);
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const set = (k) => (e) => {
    setForm((f) => ({ ...f, [k]: e.target.value }));
    setErrors((er) => ({ ...er, [k]: undefined }));
  };

  const submit = async (e) => {
    e.preventDefault();
    const next = {};
    if (!form.old_password) next.old_password = "Saisissez votre mot de passe actuel.";
    if (!passwordChecks(form.new_password, user.email).every((c) => c.ok)) next.new_password = "Ce mot de passe ne respecte pas les critères.";
    if (form.confirm !== form.new_password) next.confirm = "Les mots de passe ne correspondent pas.";
    setErrors(next);
    setFormError("");
    if (Object.keys(next).length) return;

    setSaving(true);
    try {
      await changePassword({ old_password: form.old_password, new_password: form.new_password });
      setForm(empty);
      toast.success("Mot de passe modifié", "Utilisez-le dès votre prochaine connexion.");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        const fe = err.fieldErrors;
        setErrors(fe);
        setFormError("Vérifiez les champs signalés.");
      } else {
        setFormError(err.message);
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="card card-pad" onSubmit={submit} noValidate>
      <div className="card-head">
        <div>
          <h2 className="card-title">Mot de passe</h2>
          <p className="card-sub">Choisissez un mot de passe unique que vous n'utilisez nulle part ailleurs.</p>
        </div>
      </div>
      {formError && (
        <div className="alert alert-error" role="alert" style={{ marginBottom: 16 }}>
          <CircleAlert size={18} />
          <span>{formError}</span>
        </div>
      )}
      <div className="form-grid">
        <div className="full">
          <PasswordField
            label="Mot de passe actuel"
            autoComplete="current-password"
            value={form.old_password}
            onChange={set("old_password")}
            error={errors.old_password}
          />
        </div>
        <PasswordField
          label="Nouveau mot de passe"
          autoComplete="new-password"
          value={form.new_password}
          onChange={set("new_password")}
          error={errors.new_password}
        />
        <PasswordField
          label="Confirmer le nouveau mot de passe"
          autoComplete="new-password"
          value={form.confirm}
          onChange={set("confirm")}
          error={errors.confirm}
        />
        {form.new_password && (
          <div className="full">
            <PasswordMeter password={form.new_password} email={user.email} />
          </div>
        )}
      </div>
      <div className="form-actions">
        <Button type="submit" variant="gold" icon={ShieldCheck} loading={saving}>
          Changer le mot de passe
        </Button>
      </div>
    </form>
  );
}

export default function Profile() {
  useDocumentTitle("Mon profil");
  const { user, logout } = useAuth();
  const toast = useToast();
  const [leaving, setLeaving] = useState(false);

  const onLogout = async () => {
    setLeaving(true);
    await logout();
    toast.info("À bientôt", "Vous êtes déconnecté.");
  };

  return (
    <>
      <PageHeader title="Mon profil" description="Gérez vos informations et la sécurité de votre compte." />
      <div className="profile-grid">
        <aside className="card identity">
          <Avatar user={user} size="lg" />
          <h2>{displayName(user)}</h2>
          <p className="email">{user.email}</p>
          <RoleBadge role={user.role} />
          <p className="muted" style={{ fontSize: "var(--fs-sm)", marginTop: 6 }}>
            {ROLE_META[user.role]?.desc}
          </p>
          <dl className="kv">
            <dt>Rôle</dt>
            <dd>{ROLES[user.role]}</dd>
            <dt>Membre depuis</dt>
            <dd>{formatDate(user.date_joined)}</dd>
            <dt>Identifiant</dt>
            <dd className="mono">#{user.id}</dd>
          </dl>
          <Button variant="danger" block icon={LogOut} onClick={onLogout} loading={leaving} style={{ marginTop: 10 }}>
            Se déconnecter
          </Button>
        </aside>

        <div className="stack">
          <InfoForm />
          <PasswordForm />
        </div>
      </div>
    </>
  );
}
