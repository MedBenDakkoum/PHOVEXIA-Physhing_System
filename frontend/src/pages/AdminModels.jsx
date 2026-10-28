import { useState } from "react";
import { ArrowLeftRight, Check, Cpu, Plus, RotateCcw, Sparkles } from "lucide-react";
import {
  activateAdminModel,
  compareAdminModels,
  createAdminModel,
  listAdminModels,
  rollbackAdminModel,
} from "../api/admin";
import { ApiError } from "../api/errors";
import { MODEL_VERSION_KIND, MODEL_VERSION_KIND_VALUES } from "../api/constants";
import { useToast } from "../context/ToastContext";
import Button from "../components/ui/Button";
import { SelectField, TextAreaField, TextField } from "../components/ui/Fields";
import { ConfirmDialog, Modal } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatDateTime, formatNumber } from "../utils/format";

const PAGE_SIZE = 20;

function metricValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "number") {
    return Number.isInteger(value) ? formatNumber(value) : value.toLocaleString("fr-FR", { maximumFractionDigits: 4 });
  }
  return String(value);
}

function metricChips(metrics) {
  if (!metrics || typeof metrics !== "object") return [];
  return Object.entries(metrics)
    .filter(([, value]) => ["string", "number"].includes(typeof value))
    .slice(0, 4);
}

function CreateModelModal({ onClose, onCreated }) {
  const toast = useToast();
  const [form, setForm] = useState({
    name: "",
    version: "",
    kind: "MOCK",
    file_path: "",
    notes: "",
  });
  const [metricsText, setMetricsText] = useState("{}");
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setFormError("");
    setErrors({});

    let metrics;
    try {
      metrics = metricsText.trim() ? JSON.parse(metricsText) : {};
    } catch {
      setFormError("Les métriques doivent être un objet JSON valide.");
      return;
    }
    if (!metrics || typeof metrics !== "object" || Array.isArray(metrics)) {
      setFormError("Les métriques doivent être un objet JSON.");
      return;
    }
    if (form.kind === "ONNX" && !form.file_path.trim()) {
      setErrors({ file_path: "Le chemin du fichier est obligatoire pour un modèle ONNX." });
      return;
    }

    setSaving(true);
    try {
      const created = await createAdminModel({
        ...form,
        name: form.name.trim(),
        version: form.version.trim(),
        file_path: form.file_path.trim(),
        notes: form.notes.trim(),
        metrics,
      });
      toast.success("Version enregistrée", `${created.name} ${created.version}`);
      onCreated(created);
    } catch (err) {
      if (err instanceof ApiError) setErrors(err.fieldErrors);
      setFormError(err.message);
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      closeDisabled={saving}
      title="Enregistrer une version"
      description="Métadonnées uniquement : aucun fichier n’est envoyé par le navigateur."
      width={720}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="gold" type="submit" form="create-model-form" loading={saving}>
            Enregistrer
          </Button>
        </>
      }
    >
      <form id="create-model-form" onSubmit={submit} className="stack" noValidate>
        {formError && (
          <div className="alert alert-error" role="alert">
            <span>{formError}</span>
          </div>
        )}
        <div className="form-grid">
          <TextField
            label="Nom"
            value={form.name}
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
            error={errors.name}
            required
            data-autofocus
          />
          <TextField
            label="Version"
            value={form.version}
            onChange={(event) => setForm((current) => ({ ...current, version: event.target.value }))}
            error={errors.version}
            placeholder="ex. 1.2.0"
            required
          />
        </div>
        <SelectField
          label="Type"
          value={form.kind}
          onChange={(event) => setForm((current) => ({ ...current, kind: event.target.value }))}
          error={errors.kind}
        >
          {MODEL_VERSION_KIND_VALUES.map((kind) => (
            <option key={kind} value={kind}>
              {MODEL_VERSION_KIND[kind] || kind}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Chemin du fichier"
          value={form.file_path}
          onChange={(event) => setForm((current) => ({ ...current, file_path: event.target.value }))}
          error={errors.file_path}
          hint="Relatif à MODELS_DIR. Obligatoire pour ONNX, facultatif pour les autres types."
          placeholder="fused/model.onnx"
        />
        <TextAreaField
          label="Métriques (JSON)"
          value={metricsText}
          onChange={(event) => setMetricsText(event.target.value)}
          error={errors.metrics}
          hint='Objet JSON, par exemple {"precision": 0.94, "recall": 0.91}.'
          rows={5}
          className="mono-input"
        />
        <TextAreaField
          label="Notes"
          value={form.notes}
          onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
          error={errors.notes}
          rows={3}
        />
      </form>
    </Modal>
  );
}

function CompareModal({ comparison, onClose }) {
  return (
    <Modal
      open
      onClose={onClose}
      title="Comparer les versions"
      description="Métriques côte à côte ; les écarts sont calculés par rapport à la première version sélectionnée."
      width={1040}
      footer={<Button variant="ghost" onClick={onClose}>Fermer</Button>}
    >
      {comparison && (
        <div className="table-wrap">
          <table className="tbl compare-table">
            <thead>
              <tr>
                <th>Métrique</th>
                {comparison.models.map((model) => (
                  <th key={model.id}>
                    <span className="compare-model">
                      {model.name} <b>{model.version}</b>
                      {model.is_active && <span className="badge badge-success">Active</span>}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {comparison.metrics.map((row) => (
                <tr key={row.metric}>
                  <th scope="row">{row.metric}</th>
                  {row.values.map((value, index) => (
                    <td key={`${row.metric}-${comparison.models[index].id}`}>
                      <b>{metricValue(value)}</b>
                      {row.delta_vs_baseline[index] !== null && row.delta_vs_baseline[index] !== undefined && index > 0 && (
                        <span className={`compare-delta ${row.delta_vs_baseline[index] >= 0 ? "up" : "down"}`}>
                          {row.delta_vs_baseline[index] >= 0 ? "+" : ""}
                          {row.delta_vs_baseline[index].toLocaleString("fr-FR", { maximumFractionDigits: 4 })}
                        </span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

export default function AdminModels() {
  useDocumentTitle("Versions du modèle");
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [compareError, setCompareError] = useState("");
  const [comparing, setComparing] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);

  const { data, error, loading, reload } = useAsync(
    (signal) => listAdminModels({ page, page_size: PAGE_SIZE }, signal),
    [page]
  );

  const models = data?.results || [];
  const total = data?.count || 0;

  const toggle = (id) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id]
    );
  };

  const compare = async () => {
    setCompareError("");
    setComparing(true);
    try {
      const result = await compareAdminModels(selected);
      setComparison(result);
    } catch (err) {
      setCompareError(err.message);
      toast.error("Comparaison impossible", err.message);
    } finally {
      setComparing(false);
    }
  };

  const runConfirm = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      if (confirm.kind === "activate") {
        const activated = await activateAdminModel(confirm.model.id);
        toast.success("Version activée", `${activated.name} ${activated.version}`);
      } else {
        const rolledBack = await rollbackAdminModel();
        toast.success("Version précédente réactivée", `${rolledBack.name} ${rolledBack.version}`);
      }
      setConfirm(null);
      setSelected([]);
      reload();
    } catch (err) {
      toast.error("Action impossible", err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Versions du modèle"
        description="Enregistrez les métadonnées, comparez les versions et activez une seule version à la fois (BR-11)."
        actions={
          <div className="toolbar-actions">
            <Button variant="ghost" icon={RotateCcw} onClick={() => setConfirm({ kind: "rollback" })}>
              Revenir à la précédente
            </Button>
            <Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>
              Enregistrer une version
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Versions du modèle">
        <div className="toolbar">
          <div className="stat-pills">
            <span className="stat-pill">
              <b>{formatNumber(total)}</b> version(s)
            </span>
            <span className="stat-pill">
              <b>{formatNumber(models.filter((model) => model.is_active).length)}</b> active(s) sur cette page
            </span>
          </div>
          <div className="toolbar-actions">
            {compareError && <span className="field-error">{compareError}</span>}
            <Button
              variant="quiet"
              size="sm"
              icon={ArrowLeftRight}
              onClick={compare}
              loading={comparing}
              disabled={selected.length < 2}
            >
              Comparer ({selected.length})
            </Button>
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={5} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : models.length === 0 ? (
          <EmptyState
            icon={Cpu}
            title="Aucune version enregistrée"
            action={<Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>Enregistrer la première version</Button>}
          >
            Ajoutez les métadonnées d’un modèle pour pouvoir l’activer.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th><span className="sr-only">Comparer</span></th>
                    <th>Version</th>
                    <th>Type</th>
                    <th>Métriques</th>
                    <th>Créée le</th>
                    <th>Activée le</th>
                    <th>État</th>
                    <th><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {models.map((model) => {
                    const chips = metricChips(model.metrics);
                    return (
                      <tr key={model.id} className={model.is_active ? "row-active" : ""}>
                        <td>
                          <input
                            type="checkbox"
                            className="compare-check"
                            aria-label={`Comparer ${model.name} ${model.version}`}
                            checked={selected.includes(model.id)}
                            onChange={() => toggle(model.id)}
                          />
                        </td>
                        <td data-label="Version">
                          <div className="target" style={{ textAlign: "inherit" }}>
                            <strong>{model.name}</strong>
                            <small className="mono">{model.version}</small>
                          </div>
                        </td>
                        <td data-label="Type">
                          <span className="badge">{MODEL_VERSION_KIND[model.kind] || model.kind}</span>
                        </td>
                        <td data-label="Métriques">
                          {chips.length ? (
                            <div className="metric-chips">
                              {chips.map(([key, value]) => (
                                <span key={key} className="metric-chip" title={key}>
                                  {key}: <b>{metricValue(value)}</b>
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="faint">—</span>
                          )}
                        </td>
                        <td data-label="Créée le" className="muted">{formatDateTime(model.created_at)}</td>
                        <td data-label="Activée le" className="muted">{model.activated_at ? formatDateTime(model.activated_at) : "—"}</td>
                        <td data-label="État">
                          {model.is_active ? (
                            <span className="badge badge-success"><Check size={13} /> Active</span>
                          ) : (
                            <span className="badge">Inactive</span>
                          )}
                        </td>
                        <td className="col-actions">
                          {!model.is_active && (
                            <Button
                              variant="quiet"
                              size="sm"
                              icon={Sparkles}
                              onClick={() => setConfirm({ kind: "activate", model })}
                            >
                              Activer
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
          </>
        )}
      </section>

      {creating && (
        <CreateModelModal
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            setPage(1);
            reload();
          }}
        />
      )}

      {comparison && <CompareModal comparison={comparison} onClose={() => setComparison(null)} />}

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={runConfirm}
        loading={busy}
        tone="gold"
        title={confirm?.kind === "activate" ? "Activer cette version ?" : "Revenir à la version précédente ?"}
        confirmLabel={confirm?.kind === "activate" ? "Activer" : "Revenir"}
        message={
          confirm?.kind === "activate" ? (
            <>
              La version <strong style={{ color: "var(--text)" }}>{confirm.model.name} {confirm.model.version}</strong> deviendra
              l’unique version active. La version actuelle sera désactivée et l’action sera inscrite au journal d’audit.
            </>
          ) : (
            <>La dernière version active précédente sera réactivée. Si aucune version précédente n’existe, l’opération sera refusée.</>
          )
        }
      />
    </>
  );
}
