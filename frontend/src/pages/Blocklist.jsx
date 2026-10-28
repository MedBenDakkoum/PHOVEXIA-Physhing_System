import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, Plus, Search, ShieldBan, Trash2, X, XCircle } from "lucide-react";
import { addBlocklistEntry, exportBlocklistCsv, listBlocklist, removeBlocklistEntry } from "../api/blocklist";
import { BLOCKLIST_REASON, BLOCKLIST_REASON_VALUES } from "../api/constants";
import { ApiError } from "../api/errors";
import Button from "../components/ui/Button";
import { SelectField, TextAreaField, TextField } from "../components/ui/Fields";
import { Modal } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import SafeUrl from "../components/ui/SafeUrl";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDebounce } from "../hooks/useDebounce";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useToast } from "../context/ToastContext";
import { downloadBlob } from "../utils/csv";
import { formatDate, formatNumber } from "../utils/format";

const PAGE_SIZE = 20;
const REASON_TONE = { confirmed_phishing: "badge-danger", campaign: "badge-gold", manual: "badge-info" };
const ORDERING = [
  { value: "-created_at", label: "Ajout récent" },
  { value: "domain", label: "Domaine (A–Z)" },
  { value: "reason", label: "Raison" },
];

const firstError = (value) => (Array.isArray(value) ? value[0] : value);

function AddEntryModal({ onClose, onCreated }) {
  const toast = useToast();
  const [form, setForm] = useState({ domain: "", reason: "manual", note: "" });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setErrors({});
    setFormError("");
    try {
      const entry = await addBlocklistEntry({
        domain: form.domain.trim(),
        reason: form.reason,
        note: form.note.trim(),
      });
      toast.success("Domaine bloqué", entry.domain);
      onCreated();
    } catch (err) {
      if (err instanceof ApiError) {
        const fieldErrors = err.data?.errors || {};
        setErrors({
          domain: firstError(fieldErrors.domain),
          reason: firstError(fieldErrors.reason),
          note: firstError(fieldErrors.note),
        });
        if (err.status === 409) setFormError("Ce domaine est déjà actif dans la blocklist.");
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
      title="Ajouter un domaine à la blocklist"
      description="Les scans de ce domaine recevront immédiatement un verdict Phishing."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="danger-solid" type="submit" form="add-blocklist-form" loading={saving}>
            Bloquer le domaine
          </Button>
        </>
      }
    >
      <form id="add-blocklist-form" onSubmit={submit} className="stack-sm" noValidate>
        {formError && (
          <div className="alert alert-error" role="alert">
            <XCircle size={18} />
            <span>{formError}</span>
          </div>
        )}
        <TextField
          label="Domaine"
          value={form.domain}
          onChange={(event) => setForm((current) => ({ ...current, domain: event.target.value }))}
          error={errors.domain}
          hint="Sans http:// ni chemin. Les adresses IP sont refusées."
          placeholder="exemple.com"
          required
          data-autofocus
        />
        <SelectField
          label="Raison"
          value={form.reason}
          onChange={(event) => setForm((current) => ({ ...current, reason: event.target.value }))}
          error={errors.reason}
        >
          {BLOCKLIST_REASON_VALUES.map((value) => (
            <option key={value} value={value}>
              {BLOCKLIST_REASON[value]}
            </option>
          ))}
        </SelectField>
        <TextAreaField
          label="Note (optionnel)"
          value={form.note}
          onChange={(event) => setForm((current) => ({ ...current, note: event.target.value }))}
          rows={3}
          maxLength={1000}
          error={errors.note}
          placeholder="Contexte, campagne identifiée, source…"
          hint="1000 caractères maximum."
        />
      </form>
    </Modal>
  );
}

function RemoveEntryModal({ entry, onClose, onRemoved }) {
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    if (!reason.trim()) {
      setError("La raison du retrait est obligatoire.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      await removeBlocklistEntry(entry.id, reason.trim());
      toast.success("Domaine retiré", entry.domain);
      onRemoved();
    } catch (err) {
      setError(err.message);
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      closeDisabled={saving}
      title="Retirer ce domaine ?"
      description={entry.domain}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="danger-solid" type="submit" form="remove-blocklist-form" loading={saving}>
            Retirer de la blocklist
          </Button>
        </>
      }
    >
      <form id="remove-blocklist-form" onSubmit={submit} className="stack-sm" noValidate>
        <div className="alert alert-gold" role="status">
          <ShieldBan size={18} />
          <span>Le retrait est journalisé. Les scans suivants de ce domaine seront de nouveau analysés normalement.</span>
        </div>
        {error && (
          <div className="alert alert-error" role="alert">
            <XCircle size={18} />
            <span>{error}</span>
          </div>
        )}
        <TextAreaField
          label="Raison du retrait"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          rows={3}
          maxLength={1000}
          placeholder="Faux positif, domaine racheté, demande de l'équipe…"
          hint="Obligatoire, 1000 caractères maximum."
          required
          data-autofocus
        />
      </form>
    </Modal>
  );
}

export default function Blocklist() {
  useDocumentTitle("Blocklist");
  const toast = useToast();
  const [search, setSearch] = useState("");
  const q = useDebounce(search.trim(), 350);
  const [reason, setReason] = useState("");
  const [ordering, setOrdering] = useState("-created_at");
  const [page, setPage] = useState(1);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => setPage(1), [q, reason, ordering]);

  const { data, error, loading, reload } = useAsync(
    (signal) => listBlocklist({ page, page_size: PAGE_SIZE, q, reason, ordering }, signal),
    [q, reason, ordering, page]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;
  const hasFilters = Boolean(q || reason);
  const confirmedCount = results.filter((entry) => entry.reason === "confirmed_phishing").length;
  const campaignCount = results.filter((entry) => entry.reason === "campaign").length;

  const reset = () => {
    setSearch("");
    setReason("");
    setOrdering("-created_at");
  };

  const onExport = async () => {
    setExporting(true);
    try {
      const blob = await exportBlocklistCsv();
      downloadBlob("blocklist.csv", blob);
      toast.success("Export généré", "Le fichier CSV de la blocklist a été téléchargé.");
    } catch (err) {
      toast.error("Export impossible", err.message);
    } finally {
      setExporting(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Blocklist"
        description="Les domaines bloqués reçoivent un verdict Phishing immédiat, sans analyse du contenu."
        actions={
          <div className="toolbar-actions">
            <Button variant="ghost" icon={Download} onClick={onExport} loading={exporting}>
              Exporter CSV
            </Button>
            <Button variant="gold" icon={Plus} onClick={() => setAdding(true)}>
              Ajouter un domaine
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Domaines bloqués">
        <div className="toolbar">
          <div className="grow">
            <TextField
              size="sm"
              icon={Search}
              type="search"
              placeholder="Rechercher un domaine ou une note"
              aria-label="Rechercher dans la blocklist"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <div className="group">
            <div className="stat-pills" aria-label="Résumé de la page">
              <div className="stat-pill">
                <b>{formatNumber(total)}</b> domaines
              </div>
              <div className="stat-pill">
                <b>{formatNumber(confirmedCount)}</b> phishing confirmé
              </div>
              <div className="stat-pill">
                <b>{formatNumber(campaignCount)}</b> campagne
              </div>
            </div>
            <SelectField size="sm" label="Raison" value={reason} onChange={(event) => setReason(event.target.value)}>
              <option value="">Toutes les raisons</option>
              {BLOCKLIST_REASON_VALUES.map((value) => (
                <option key={value} value={value}>
                  {BLOCKLIST_REASON[value]}
                </option>
              ))}
            </SelectField>
            <SelectField size="sm" label="Trier" value={ordering} onChange={(event) => setOrdering(event.target.value)}>
              {ORDERING.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectField>
            <Button variant="quiet" size="sm" icon={X} onClick={reset} disabled={!hasFilters && ordering === "-created_at"}>
              Réinitialiser
            </Button>
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={7} cols={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState
            icon={ShieldBan}
            title="Aucun domaine bloqué"
            action={
              hasFilters && (
                <Button variant="ghost" onClick={reset}>
                  Réinitialiser les filtres
                </Button>
              )
            }
          >
            {hasFilters
              ? "Aucun domaine ne correspond à ces filtres."
              : "Ajoutez un domaine pour bloquer immédiatement les scans suivants."}
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Domaine</th>
                    <th>Raison</th>
                    <th>Note</th>
                    <th>Ajouté par</th>
                    <th>Date</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((entry) => (
                    <tr key={entry.id}>
                      <td data-label="Domaine">
                        <div className="target">
                          <strong>
                            <SafeUrl value={entry.domain} />
                          </strong>
                          {entry.source_scan && (
                            <small>
                              Scan source :{" "}
                              <Link to={`/scans/${entry.source_scan}`} style={{ color: "var(--accent-text)" }}>
                                ouvrir
                              </Link>
                            </small>
                          )}
                        </div>
                      </td>
                      <td data-label="Raison">
                        <span className={`badge ${REASON_TONE[entry.reason] || ""}`}>
                          {BLOCKLIST_REASON[entry.reason] || entry.reason}
                        </span>
                      </td>
                      <td data-label="Note" className="muted" style={{ maxWidth: 300 }}>
                        <span className="truncate" title={entry.note || ""}>
                          {entry.note || "—"}
                        </span>
                      </td>
                      <td data-label="Ajouté par" className="truncate" style={{ maxWidth: 220 }}>
                        {entry.added_by_email || "—"}
                      </td>
                      <td data-label="Date" className="muted">
                        {formatDate(entry.created_at)}
                      </td>
                      <td className="col-actions">
                        <Button
                          variant="quiet"
                          size="sm"
                          icon={Trash2}
                          onClick={() => setRemoving(entry)}
                          aria-label={`Retirer ${entry.domain} de la blocklist`}
                        >
                          Retirer
                        </Button>
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

      {adding && (
        <AddEntryModal
          onClose={() => setAdding(false)}
          onCreated={() => {
            setAdding(false);
            reload();
          }}
        />
      )}

      {removing && (
        <RemoveEntryModal
          entry={removing}
          onClose={() => setRemoving(null)}
          onRemoved={() => {
            setRemoving(null);
            reload();
          }}
        />
      )}
    </>
  );
}
