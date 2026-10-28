import { useState } from "react";
import { BadgeCheck, Pencil, Plus, Power, XCircle } from "lucide-react";
import { createBrand, listBrands, updateBrand } from "../api/brands";
import { ApiError } from "../api/errors";
import Button from "../components/ui/Button";
import { StatusBadge } from "../components/ui/Badges";
import { SelectField, Switch, TextField } from "../components/ui/Fields";
import { ConfirmDialog, Modal } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import SafeUrl from "../components/ui/SafeUrl";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useToast } from "../context/ToastContext";
import { formatDate, formatNumber } from "../utils/format";

const PAGE_SIZE = 20;
const ORDERING = [
  { value: "name", label: "Nom (A–Z)" },
  { value: "-created_at", label: "Ajout récent" },
];

const firstError = (value) => (Array.isArray(value) ? value[0] : value);

function BrandModal({ target, onClose, onSaved }) {
  const toast = useToast();
  const isEdit = Boolean(target);
  const [form, setForm] = useState({
    name: target?.name || "",
    domain: target?.domain || "",
    is_active: target?.is_active ?? true,
  });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setErrors({});
    setFormError("");
    const payload = {
      name: form.name.trim(),
      domain: form.domain.trim(),
      is_active: form.is_active,
    };
    try {
      const saved = isEdit ? await updateBrand(target.id, payload) : await createBrand(payload);
      toast.success(isEdit ? "Marque mise à jour" : "Marque ajoutée", saved.name);
      onSaved();
    } catch (err) {
      if (err instanceof ApiError) {
        const fieldErrors = err.data?.errors || {};
        setErrors({
          name: firstError(fieldErrors.name),
          domain: firstError(fieldErrors.domain),
        });
        if (err.status === 409) setFormError("Une marque avec ce domaine existe déjà.");
        else setFormError(err.message);
      } else {
        setFormError(err.message);
      }
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      closeDisabled={saving}
      title={isEdit ? "Modifier la marque" : "Ajouter une marque protégée"}
      description="Les domaines protégés servent à repérer les imitations lors de l'analyse."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="gold" type="submit" form="brand-form" loading={saving}>
            {isEdit ? "Enregistrer" : "Ajouter la marque"}
          </Button>
        </>
      }
    >
      <form id="brand-form" onSubmit={submit} className="stack-sm" noValidate>
        {formError && (
          <div className="alert alert-error" role="alert">
            <XCircle size={18} />
            <span>{formError}</span>
          </div>
        )}
        <TextField
          label="Nom de la marque"
          value={form.name}
          onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
          error={errors.name}
          placeholder="Nom affiché"
          required
          data-autofocus
        />
        <TextField
          label="Domaine officiel"
          value={form.domain}
          onChange={(event) => setForm((current) => ({ ...current, domain: event.target.value }))}
          error={errors.domain}
          hint="Sans http:// ni chemin. Le domaine est normalisé et unique."
          placeholder="marque.com"
          required
        />
        <Switch
          checked={form.is_active}
          onChange={(value) => setForm((current) => ({ ...current, is_active: value }))}
          label={form.is_active ? "Marque active" : "Marque inactive"}
          description={
            form.is_active
              ? "Le domaine est comparé aux URL analysées."
              : "Le domaine est conservé mais n'est plus comparé."
          }
        />
      </form>
    </Modal>
  );
}

export default function Brands() {
  useDocumentTitle("Marques protégées");
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [ordering, setOrdering] = useState("name");
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);

  const { data, error, loading, reload } = useAsync(
    (signal) => listBrands({ page, page_size: PAGE_SIZE, ordering }, signal),
    [page, ordering]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;
  const activeCount = results.filter((brand) => brand.is_active).length;
  const inactiveCount = results.length - activeCount;

  const runConfirm = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      const active = confirm.action === "reactivate";
      await updateBrand(confirm.brand.id, { is_active: active });
      toast.success(active ? "Marque réactivée" : "Marque désactivée", confirm.brand.name);
      setConfirm(null);
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
        title="Marques protégées"
        description="Déclarez les domaines officiels de vos marques pour détecter les imitations."
        actions={
          <div className="toolbar-actions">
            <div className="stat-pills" aria-label="Résumé de la page">
              <div className="stat-pill">
                <b>{formatNumber(total)}</b> marques
              </div>
              <div className="stat-pill">
                <b>{formatNumber(activeCount)}</b> actives sur la page
              </div>
              <div className="stat-pill">
                <b>{formatNumber(inactiveCount)}</b> inactives sur la page
              </div>
            </div>
            <Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>
              Ajouter une marque
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Marques protégées">
        <div className="toolbar">
          <div className="grow">
            <SelectField size="sm" label="Trier" value={ordering} onChange={(event) => setOrdering(event.target.value)}>
              {ORDERING.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectField>
          </div>
          <Button variant="quiet" size="sm" onClick={() => setPage(1)} disabled={page === 1}>
            Première page
          </Button>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={6} cols={5} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState
            icon={BadgeCheck}
            title="Aucune marque protégée"
            action={
              <Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>
                Ajouter une marque
              </Button>
            }
          >
            Ajoutez le domaine officiel d'une marque pour détecter les sites qui l'imitent.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Marque</th>
                    <th>Domaine</th>
                    <th>Statut</th>
                    <th>Créée par</th>
                    <th>Date</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((brand) => (
                    <tr key={brand.id} className={brand.is_active ? "" : "row-muted brand-inactive"}>
                      <td data-label="Marque">
                        <strong>{brand.name}</strong>
                      </td>
                      <td data-label="Domaine">
                        <SafeUrl value={brand.domain} />
                      </td>
                      <td data-label="Statut">
                        <StatusBadge active={brand.is_active} />
                      </td>
                      <td data-label="Créée par" className="truncate" style={{ maxWidth: 220 }}>
                        {brand.created_by_email || "—"}
                      </td>
                      <td data-label="Date" className="muted">
                        {formatDate(brand.created_at)}
                      </td>
                      <td className="col-actions">
                        <div className="inline-actions" style={{ justifyContent: "flex-end" }}>
                          <Button variant="quiet" size="sm" icon={Pencil} onClick={() => setEditing(brand)}>
                            Modifier
                          </Button>
                          {brand.is_active ? (
                            <Button
                              variant="quiet"
                              size="sm"
                              icon={Power}
                              onClick={() => setConfirm({ brand, action: "deactivate" })}
                            >
                              Désactiver
                            </Button>
                          ) : (
                            <Button
                              variant="quiet"
                              size="sm"
                              icon={Power}
                              onClick={() => setConfirm({ brand, action: "reactivate" })}
                            >
                              Réactiver
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
          </>
        )}
      </section>

      {creating && (
        <BrandModal
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            reload();
          }}
        />
      )}

      {editing && (
        <BrandModal
          target={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reload();
          }}
        />
      )}

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={runConfirm}
        loading={busy}
        tone={confirm?.action === "deactivate" ? "danger" : "gold"}
        title={confirm?.action === "deactivate" ? "Désactiver cette marque ?" : "Réactiver cette marque ?"}
        confirmLabel={confirm?.action === "deactivate" ? "Désactiver" : "Réactiver"}
        message={
          confirm && (
            <>
              <strong style={{ color: "var(--text)" }}>{confirm.brand.name}</strong>{" "}
              {confirm.action === "deactivate"
                ? "ne sera plus comparée aux URL analysées. La marque est conservée et peut être réactivée."
                : "sera de nouveau comparée aux URL analysées pour détecter les imitations."}
            </>
          )
        }
      />
    </>
  );
}
