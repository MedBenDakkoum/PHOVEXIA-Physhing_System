import { useState } from "react";
import { Ban, Copy, KeyRound, Plus, ShieldCheck } from "lucide-react";
import { createAdminApiKey, listAdminApiKeys, revokeAdminApiKey } from "../api/admin";
import { ApiError } from "../api/errors";
import { SCOPE } from "../api/constants";
import { useToast } from "../context/ToastContext";
import Button from "../components/ui/Button";
import { Checkbox, TextField } from "../components/ui/Fields";
import { ConfirmDialog, Modal } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatDateTime } from "../utils/format";

const PAGE_SIZE = 20;
const SCOPE_VALUES = Object.keys(SCOPE);

function isExpired(value) {
  return Boolean(value && new Date(value).getTime() < Date.now());
}

function CreateKeyModal({ onClose, onCreated }) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState(["scan:create"]);
  const [expiresAt, setExpiresAt] = useState("");
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const toggleScope = (scope, checked) => {
    setScopes((current) => (checked ? [...current, scope] : current.filter((item) => item !== scope)));
  };

  const submit = async (event) => {
    event.preventDefault();
    setErrors({});
    setFormError("");
    if (!scopes.length) {
      setFormError("Sélectionnez au moins une portée.");
      return;
    }
    let expires = null;
    if (expiresAt) {
      const parsed = new Date(expiresAt);
      if (Number.isNaN(parsed.getTime())) {
        setErrors({ expires_at: "Date d’expiration invalide." });
        return;
      }
      expires = parsed.toISOString();
    }
    setSaving(true);
    try {
      const created = await createAdminApiKey({ name: name.trim(), scopes, expires_at: expires });
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
      title="Créer une clé API"
      description="Le secret ne sera affiché qu’une seule fois, juste après la création."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="gold" type="submit" form="create-key-form" loading={saving}>
            Créer la clé
          </Button>
        </>
      }
    >
      <form id="create-key-form" onSubmit={submit} className="stack" noValidate>
        {formError && (
          <div className="alert alert-error" role="alert">
            <span>{formError}</span>
          </div>
        )}
        <TextField
          label="Nom"
          value={name}
          onChange={(event) => setName(event.target.value)}
          error={errors.name}
          placeholder="Intégration SIEM"
          required
          data-autofocus
        />
        <div className="field">
          <span className="field-label">Portées</span>
          <div className="stack-sm">
            {SCOPE_VALUES.map((scope) => (
              <Checkbox
                key={scope}
                label={SCOPE[scope]}
                description={scope}
                checked={scopes.includes(scope)}
                onChange={(checked) => toggleScope(scope, checked)}
              />
            ))}
          </div>
          {errors.scopes && <span className="field-error">{errors.scopes}</span>}
        </div>
        <TextField
          label="Expiration (optionnel)"
          type="datetime-local"
          value={expiresAt}
          onChange={(event) => setExpiresAt(event.target.value)}
          error={errors.expires_at}
          hint="Laissez vide pour une clé sans expiration."
        />
      </form>
    </Modal>
  );
}

function CreatedKeyModal({ created, onClose }) {
  const toast = useToast();

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.secret);
      toast.success("Secret copié", "Conservez-le dans un gestionnaire de secrets.");
    } catch {
      toast.error("Copie impossible", "Sélectionnez le secret puis copiez-le manuellement.");
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Clé API créée"
      description="Cette valeur ne pourra plus être affichée. Copiez-la maintenant."
      width={720}
      footer={<Button variant="gold" onClick={onClose}>J’ai copié le secret</Button>}
    >
      <div className="stack">
        <div className="alert alert-gold">
          <ShieldCheck size={18} />
          <span>
            Le secret est stocké sous forme de hash côté serveur. Si vous le perdez, révoquez la clé et créez-en une
            nouvelle.
          </span>
        </div>
        <div className="secret-box">
          <code>{created.secret}</code>
          <Button variant="quiet" size="sm" icon={Copy} onClick={copy}>
            Copier
          </Button>
        </div>
        <dl className="kv">
          <dt>Nom</dt>
          <dd>{created.name}</dd>
          <dt>Préfixe</dt>
          <dd className="mono">{created.key_prefix}</dd>
          <dt>Portées</dt>
          <dd>{created.scopes?.map((scope) => SCOPE[scope] || scope).join(", ") || "—"}</dd>
          <dt>Expiration</dt>
          <dd>{created.expires_at ? formatDateTime(created.expires_at) : "Aucune"}</dd>
        </dl>
      </div>
    </Modal>
  );
}

export default function AdminApiKeys() {
  useDocumentTitle("Clés API");
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(null);
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);

  const { data, error, loading, reload } = useAsync(
    (signal) => listAdminApiKeys({ page, page_size: PAGE_SIZE }, signal),
    [page]
  );

  const keys = data?.results || [];
  const total = data?.count || 0;

  const revoke = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      await revokeAdminApiKey(confirm.id);
      toast.success("Clé révoquée", confirm.name);
      setConfirm(null);
      reload();
    } catch (err) {
      toast.error("Révocation impossible", err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Clés API"
        description="Donnez un accès machine limité aux scans. Le secret n’est jamais réaffiché après sa création."
        actions={
          <Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>
            Créer une clé
          </Button>
        }
      />

      <section className="card list-card" aria-label="Clés API">
        <div className="toolbar">
          <div className="stat-pills">
            <span className="stat-pill">
              <b>{total}</b> clé(s)
            </span>
            <span className="stat-pill">
              <b>{keys.filter((key) => key.is_active && !isExpired(key.expires_at)).length}</b> active(s) sur cette page
            </span>
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={5} cols={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : keys.length === 0 ? (
          <EmptyState
            icon={KeyRound}
            title="Aucune clé API"
            action={<Button variant="gold" icon={Plus} onClick={() => setCreating(true)}>Créer la première clé</Button>}
          >
            Les intégrations machine pourront créer et lire des scans avec une clé dédiée.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Nom</th>
                    <th>Préfixe</th>
                    <th>Portées</th>
                    <th>Créée le</th>
                    <th>Expire le</th>
                    <th>Dernier usage</th>
                    <th>État</th>
                    <th><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((key) => {
                    const expired = isExpired(key.expires_at);
                    return (
                      <tr key={key.id} className={!key.is_active ? "row-muted" : ""}>
                        <td data-label="Nom">
                          <strong>{key.name}</strong>
                          <div className="faint" style={{ fontSize: "var(--fs-xs)" }}>{key.owner_email}</div>
                        </td>
                        <td data-label="Préfixe" className="mono">{key.key_prefix}…</td>
                        <td data-label="Portées">
                          <div className="metric-chips">
                            {key.scopes?.map((scope) => (
                              <span className="metric-chip" key={scope}>{SCOPE[scope] || scope}</span>
                            ))}
                          </div>
                        </td>
                        <td data-label="Créée le" className="muted">{formatDateTime(key.created_at)}</td>
                        <td data-label="Expire le" className="muted">
                          {key.expires_at ? formatDateTime(key.expires_at) : "Jamais"}
                        </td>
                        <td data-label="Dernier usage" className="muted">
                          {key.last_used_at ? formatDateTime(key.last_used_at) : "Jamais"}
                        </td>
                        <td data-label="État">
                          {key.is_active && !expired ? (
                            <span className="badge badge-success">Active</span>
                          ) : expired ? (
                            <span className="badge badge-gold">Expirée</span>
                          ) : (
                            <span className="badge">Révoquée</span>
                          )}
                        </td>
                        <td className="col-actions">
                          {key.is_active && (
                            <Button variant="danger" size="sm" icon={Ban} onClick={() => setConfirm(key)}>
                              Révoquer
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
        <CreateKeyModal
          onClose={() => setCreating(false)}
          onCreated={(key) => {
            setCreating(false);
            setCreated(key);
            setPage(1);
            reload();
          }}
        />
      )}

      {created && <CreatedKeyModal created={created} onClose={() => setCreated(null)} />}

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={revoke}
        loading={busy}
        title="Révoquer cette clé ?"
        confirmLabel="Révoquer"
        message={
          confirm && (
            <>
              La clé <strong style={{ color: "var(--text)" }}>{confirm.name}</strong> ne pourra plus authentifier de
              requête. La ligne est conservée et l’action sera auditée.
            </>
          )
        }
      />
    </>
  );
}
