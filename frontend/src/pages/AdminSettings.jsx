import { useEffect, useState } from "react";
import { CircleAlert, RotateCcw, Save, SlidersHorizontal } from "lucide-react";
import { getAdminSettings, updateAdminSettings } from "../api/admin";
import { ApiError } from "../api/errors";
import { useToast } from "../context/ToastContext";
import Button from "../components/ui/Button";
import { TextField } from "../components/ui/Fields";
import { ConfirmDialog } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import { ErrorState, Skeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatDateTime, formatNumber } from "../utils/format";

const FIELDS = ["phishing_threshold", "uncertain_lower", "daily_scan_quota", "quick_check_hourly_limit"];

function toForm(data) {
  return {
    phishing_threshold: String(data.phishing_threshold),
    uncertain_lower: String(data.uncertain_lower),
    daily_scan_quota: String(data.daily_scan_quota),
    quick_check_hourly_limit: String(data.quick_check_hourly_limit),
  };
}

function toPayload(form) {
  return {
    phishing_threshold: Number(form.phishing_threshold),
    uncertain_lower: Number(form.uncertain_lower),
    daily_scan_quota: Number(form.daily_scan_quota),
    quick_check_hourly_limit: Number(form.quick_check_hourly_limit),
  };
}

function validate(values) {
  const errors = {};
  const threshold = values.phishing_threshold;
  const lower = values.uncertain_lower;
  if (!Number.isFinite(threshold) || !Number.isFinite(lower) || !(0 < lower && lower < threshold && threshold <= 1)) {
    const message = "La règle 0 < seuil incertain < seuil phishing ≤ 1 doit être respectée.";
    errors.uncertain_lower = message;
    errors.phishing_threshold = message;
  }
  if (!Number.isInteger(values.daily_scan_quota) || values.daily_scan_quota < 1 || values.daily_scan_quota > 10000) {
    errors.daily_scan_quota = "Quota entier entre 1 et 10 000.";
  }
  if (
    !Number.isInteger(values.quick_check_hourly_limit) ||
    values.quick_check_hourly_limit < 1 ||
    values.quick_check_hourly_limit > 1000
  ) {
    errors.quick_check_hourly_limit = "Limite entière entre 1 et 1 000.";
  }
  return errors;
}

function Scale({ lower, threshold }) {
  const safeLower = Math.min(100, Math.max(0, (lower || 0) * 100));
  const safeThreshold = Math.min(100, Math.max(0, (threshold || 0) * 100));
  return (
    <div className="threshold-scale" aria-label="Zone de décision">
      <span className="threshold-seg legit" style={{ width: `${safeLower}%` }}>
        Légitime
      </span>
      <span className="threshold-seg uncertain" style={{ width: `${Math.max(0, safeThreshold - safeLower)}%` }}>
        Incertain
      </span>
      <span className="threshold-seg phishing" style={{ width: `${Math.max(0, 100 - safeThreshold)}%` }}>
        Phishing
      </span>
      <span className="threshold-marker" style={{ left: `${safeLower}%` }} title={`Seuil légitime : ${lower}`} />
      <span className="threshold-marker strong" style={{ left: `${safeThreshold}%` }} title={`Seuil phishing : ${threshold}`} />
    </div>
  );
}

export default function AdminSettings() {
  useDocumentTitle("Réglages de détection");
  const toast = useToast();
  const { data, error, loading, reload } = useAsync((signal) => getAdminSettings(signal), []);
  const [form, setForm] = useState(null);
  const [baseline, setBaseline] = useState(null);
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!data) return;
    const next = toForm(data);
    setForm(next);
    setBaseline(next);
  }, [data]);

  if (error) {
    return (
      <div className="card">
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  }
  if (loading || !data || !form) {
    return (
      <div className="card card-pad stack">
        <Skeleton h={18} w="35%" />
        <Skeleton h={64} r={12} />
        <Skeleton h={64} r={12} />
        <Skeleton h={64} r={12} />
      </div>
    );
  }

  const dirty = FIELDS.some((field) => form[field] !== baseline[field]);
  const values = toPayload(form);

  const reset = () => {
    setForm(baseline);
    setErrors({});
    setFormError("");
  };

  const submit = (event) => {
    event.preventDefault();
    const nextErrors = validate(values);
    setErrors(nextErrors);
    setFormError("");
    if (Object.keys(nextErrors).length) return;
    setConfirming(true);
  };

  const save = async () => {
    const payload = {};
    FIELDS.forEach((field) => {
      if (form[field] !== baseline[field]) payload[field] = values[field];
    });
    setSaving(true);
    try {
      const updated = await updateAdminSettings(payload);
      const next = toForm(updated);
      setForm(next);
      setBaseline(next);
      setConfirming(false);
      toast.success("Réglages enregistrés", "La modification a été inscrite au journal d’audit.");
      reload();
    } catch (err) {
      if (err instanceof ApiError && err.data?.errors) {
        const nextErrors = {};
        Object.entries(err.data.errors).forEach(([key, value]) => {
          nextErrors[key] = Array.isArray(value) ? value[0] : String(value);
        });
        setErrors(nextErrors);
      }
      setFormError(err.message);
      setConfirming(false);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Réglages de détection"
        description="Ajustez les seuils de verdict et les quotas. Chaque changement est validé, mis en cache puis audité."
        actions={
          <div className="toolbar-actions">
            <Button variant="ghost" icon={RotateCcw} onClick={reset} disabled={!dirty || saving}>
              Annuler
            </Button>
            <Button
              variant="gold"
              type="submit"
              form="settings-form"
              icon={Save}
              loading={saving}
              disabled={!dirty}
            >
              Enregistrer
            </Button>
          </div>
        }
      />

      <div className="settings-grid">
        <form id="settings-form" onSubmit={submit} className="card card-pad stack" noValidate>
          <div className="card-head">
            <div>
              <h2 className="card-title">Seuils de décision</h2>
              <p className="card-sub">Le score est comparé à ces deux seuils après fusion des quatre branches.</p>
            </div>
            <SlidersHorizontal size={20} className="faint" aria-hidden="true" />
          </div>

          {formError && (
            <div className="alert alert-error" role="alert">
              <CircleAlert size={18} />
              <span>{formError}</span>
            </div>
          )}

          <div className="form-grid">
            <TextField
              label="Seuil phishing"
              type="number"
              min="0"
              max="1"
              step="0.01"
              value={form.phishing_threshold}
              onChange={(event) => setForm((current) => ({ ...current, phishing_threshold: event.target.value }))}
              error={errors.phishing_threshold}
              hint="Score supérieur ou égal : phishing."
              required
            />
            <TextField
              label="Seuil incertain"
              type="number"
              min="0"
              max="1"
              step="0.01"
              value={form.uncertain_lower}
              onChange={(event) => setForm((current) => ({ ...current, uncertain_lower: event.target.value }))}
              error={errors.uncertain_lower}
              hint="Score inférieur ou égal : légitime."
              required
            />
          </div>

          <Scale lower={values.uncertain_lower} threshold={values.phishing_threshold} />

          <div className="alert alert-info">
            <SlidersHorizontal size={18} />
            <span>
              Entre les deux seuils, le verdict est <strong>incertain</strong> et le scan rejoint la file de revue analyste.
            </span>
          </div>

          <div className="card-head">
            <div>
              <h2 className="card-title">Quotas</h2>
              <p className="card-sub">Limites appliquées par utilisateur et par adresse IP.</p>
            </div>
          </div>

          <div className="form-grid">
            <TextField
              label="Scans par jour et par utilisateur"
              type="number"
              min="1"
              max="10000"
              step="1"
              value={form.daily_scan_quota}
              onChange={(event) => setForm((current) => ({ ...current, daily_scan_quota: event.target.value }))}
              error={errors.daily_scan_quota}
              hint={`Valeur actuelle : ${formatNumber(data.daily_scan_quota)}.`}
              required
            />
            <TextField
              label="Quick checks par heure et par IP"
              type="number"
              min="1"
              max="1000"
              step="1"
              value={form.quick_check_hourly_limit}
              onChange={(event) =>
                setForm((current) => ({ ...current, quick_check_hourly_limit: event.target.value }))
              }
              error={errors.quick_check_hourly_limit}
              hint={`Valeur actuelle : ${formatNumber(data.quick_check_hourly_limit)}.`}
              required
            />
          </div>
        </form>

        <aside className="card card-pad stack">
          <div className="card-head">
            <div>
              <h2 className="card-title">Traçabilité</h2>
              <p className="card-sub">Les réglages sont un singleton partagé par tous les workers.</p>
            </div>
          </div>
          <dl className="kv">
            <dt>Dernière modification</dt>
            <dd>{data.updated_at ? formatDateTime(data.updated_at) : "Valeurs par défaut (environnement)"}</dd>
            <dt>Modifié par</dt>
            <dd>{data.updated_by_email || "—"}</dd>
            <dt>Seuil actuel</dt>
            <dd>
              Légitime ≤ <b>{Math.round(data.uncertain_lower * 100)} %</b> · Phishing ≥{" "}
              <b>{Math.round(data.phishing_threshold * 100)} %</b>
            </dd>
          </dl>
          <div className="alert alert-gold">
            <CircleAlert size={18} />
            <span>
              Un réglage trop bas peut augmenter les faux positifs ; un réglage trop haut peut laisser passer du phishing.
            </span>
          </div>
          <Button variant="quiet" to="/app/admin/audit?action=settings_changed" icon={Save}>
            Voir l’historique d’audit
          </Button>
        </aside>
      </div>

      <ConfirmDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        onConfirm={save}
        loading={saving}
        tone="gold"
        title="Enregistrer ces réglages ?"
        confirmLabel="Enregistrer"
        message={
          <>
            Les nouveaux seuils et quotas seront appliqués immédiatement. L’ancienne et la nouvelle valeur seront
            inscrites au journal d’audit.
          </>
        }
      />
    </>
  );
}
