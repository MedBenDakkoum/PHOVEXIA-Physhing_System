import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, Download, ScrollText, Search, X } from "lucide-react";
import { listAuditLogs } from "../api/audit";
import { AUDIT_ACTIONS, AUDIT_ACTION_VALUES, AUDIT_DEFAULT_PAGE_SIZE, AUDIT_PAGE_SIZES } from "../api/constants";
import { ActionBadge, ACTION_META, RoleBadge } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { SelectField, TextField } from "../components/ui/Fields";
import { Drawer } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDebounce } from "../hooks/useDebounce";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { downloadCsv } from "../utils/csv";
import { formatDateTime, formatFull, formatNumber, relativeTime } from "../utils/format";

const QUICK = [
  { action: "", label: "Toutes les actions" },
  { action: "login_failed", label: "Connexions échouées" },
  { action: "role_change", label: "Changements de rôle" },
  { action: "user_suspend", label: "Suspensions" },
  { action: "register", label: "Inscriptions" },
];

/* ------------------------------------------------------------------ détail */
function RoleDiff({ metadata }) {
  if (!metadata?.old && !metadata?.new) return null;
  return (
    <div className="role-diff">
      {metadata.old && <RoleBadge role={metadata.old} />}
      <ArrowRight size={16} className="faint" aria-label="devient" />
      {metadata.new && <RoleBadge role={metadata.new} />}
    </div>
  );
}

function EntryDrawer({ entry, onClose }) {
  const meta = ACTION_META[entry.action];
  const hasMeta = entry.metadata && Object.keys(entry.metadata).length > 0;
  return (
    <Drawer open onClose={onClose} title="Détail de l'événement" description={`Entrée n°${entry.id}`}>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <span className={`feed-ico tone-${meta?.tone || "neutral"}-i`} style={{ width: 48, height: 48 }}>
          {meta && <meta.icon size={22} />}
        </span>
        <div>
          <ActionBadge action={entry.action} label={entry.action_label} />
          <div className="muted" style={{ fontSize: "var(--fs-sm)", marginTop: 4 }}>
            {formatFull(entry.created_at)}
          </div>
        </div>
      </div>

      <hr className="divider" />

      <dl className="kv">
        <dt>Acteur</dt>
        <dd>
          {entry.user_email || <span className="faint">Aucun (anonyme)</span>}
          {entry.user && (
            <>
              {" "}
              <Link to={`/app/admin/audit?user=${entry.user}`} onClick={onClose} style={{ fontSize: "var(--fs-xs)" }}>
                (compte n°{entry.user})
              </Link>
            </>
          )}
        </dd>
        <dt>Action</dt>
        <dd>
          {entry.action_label} <code className="faint">{entry.action}</code>
        </dd>
        <dt>Cible</dt>
        <dd>
          {entry.target_type ? (
            <>
              {entry.target_repr || "—"}
              <div className="faint" style={{ fontSize: "var(--fs-xs)" }}>
                {entry.target_type} · n°{entry.target_id}
              </div>
            </>
          ) : (
            <span className="faint">Aucune</span>
          )}
        </dd>
        <dt>Adresse IP</dt>
        <dd className="mono">{entry.ip_address || "—"}</dd>
      </dl>

      {entry.action === "role_change" && (
        <>
          <hr className="divider" />
          <div className="field">
            <span className="field-label">Changement de rôle</span>
            <RoleDiff metadata={entry.metadata} />
          </div>
        </>
      )}

      {hasMeta && (
        <div className="field">
          <span className="field-label">Métadonnées</span>
          <pre className="codeblock">{JSON.stringify(entry.metadata, null, 2)}</pre>
        </div>
      )}

      <div className="alert alert-info">
        <ScrollText size={18} />
        <span>Les entrées du journal sont en lecture seule : elles ne peuvent être ni modifiées ni supprimées.</span>
      </div>
    </Drawer>
  );
}

/* -------------------------------------------------------------------- page */
export default function AuditLogs() {
  useDocumentTitle("Journal d'audit");
  const [sp, setSp] = useSearchParams();

  const filters = {
    user: sp.get("user") || "",
    user_email: sp.get("user_email") || "",
    action: sp.get("action") || "",
    date_from: sp.get("date_from") || "",
    date_to: sp.get("date_to") || "",
  };
  const page = Math.max(1, Number(sp.get("page")) || 1);
  const pageSize = AUDIT_PAGE_SIZES.includes(Number(sp.get("page_size"))) ? Number(sp.get("page_size")) : AUDIT_DEFAULT_PAGE_SIZE;

  const update = (patch) => {
    const next = new URLSearchParams(sp);
    Object.entries(patch).forEach(([k, v]) => (v === "" || v == null ? next.delete(k) : next.set(k, String(v))));
    if (!("page" in patch)) next.delete("page");
    setSp(next, { replace: true });
  };

  // Saisie de l'e-mail : état local + debounce vers l'URL
  const [emailText, setEmailText] = useState(filters.user_email);
  const debouncedEmail = useDebounce(emailText.trim(), 400);
  useEffect(() => {
    if (debouncedEmail !== filters.user_email) update({ user_email: debouncedEmail });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedEmail]);

  const [selected, setSelected] = useState(null);

  const { data, error, loading, reload } = useAsync(
    (signal) => listAuditLogs({ page, page_size: pageSize, ...filters }, signal),
    [sp.toString()]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;
  const hasFilters = Object.values(filters).some(Boolean);

  const reset = () => {
    setEmailText("");
    setSp(new URLSearchParams(), { replace: true });
  };

  const exportCsv = () =>
    downloadCsv(`journal-audit-page-${page}.csv`, [
      { label: "id", value: (r) => r.id },
      { label: "created_at", value: (r) => r.created_at },
      { label: "user", value: (r) => r.user },
      { label: "user_email", value: (r) => r.user_email },
      { label: "action", value: (r) => r.action },
      { label: "action_label", value: (r) => r.action_label },
      { label: "target_type", value: (r) => r.target_type },
      { label: "target_id", value: (r) => r.target_id },
      { label: "target_repr", value: (r) => r.target_repr },
      { label: "ip_address", value: (r) => r.ip_address },
      { label: "metadata", value: (r) => r.metadata },
    ], results);

  return (
    <>
      <PageHeader
        title="Journal d'audit"
        description="Historique infalsifiable des connexions, changements de rôle et suspensions. Les entrées sont en lecture seule."
        actions={
          <Button variant="ghost" icon={Download} onClick={exportCsv} disabled={!results.length}>
            Exporter la page en CSV
          </Button>
        }
      />

      <section className="card list-card" aria-label="Événements du journal d'audit">
        <div className="quick" role="group" aria-label="Filtres rapides">
          {QUICK.map((qk) => (
            <button key={qk.action} className="pill-btn" aria-pressed={filters.action === qk.action} onClick={() => update({ action: qk.action })}>
              {qk.label}
            </button>
          ))}
          {filters.user && (
            <span className="chip" style={{ marginLeft: "auto" }}>
              Compte n°{filters.user}
              <button aria-label="Retirer le filtre utilisateur" onClick={() => update({ user: "" })}>
                <X size={14} />
              </button>
            </span>
          )}
        </div>

        <div className="filters">
          <TextField
            size="sm"
            label="Utilisateur (e-mail)"
            icon={Search}
            type="search"
            placeholder="Contient…"
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
          />
          <SelectField size="sm" label="Action" value={filters.action} onChange={(e) => update({ action: e.target.value })}>
            <option value="">Toutes</option>
            {AUDIT_ACTION_VALUES.map((a) => (
              <option key={a} value={a}>
                {AUDIT_ACTIONS[a]}
              </option>
            ))}
          </SelectField>
          <TextField size="sm" label="Du" type="date" value={filters.date_from} max={filters.date_to || undefined} onChange={(e) => update({ date_from: e.target.value })} />
          <TextField size="sm" label="Au" type="date" value={filters.date_to} min={filters.date_from || undefined} onChange={(e) => update({ date_to: e.target.value })} />
          <div className="field" style={{ alignContent: "end" }}>
            <Button variant="quiet" size="sm" onClick={reset} disabled={!hasFilters} icon={X} style={{ height: 38 }}>
              Réinitialiser
            </Button>
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={8} cols={5} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState
            icon={ScrollText}
            title="Aucun événement"
            action={
              hasFilters && (
                <Button variant="ghost" onClick={reset}>
                  Réinitialiser les filtres
                </Button>
              )
            }
          >
            {hasFilters ? "Aucune entrée du journal ne correspond à ces filtres." : "Le journal est vide pour le moment."}
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Acteur</th>
                    <th>Action</th>
                    <th>Cible</th>
                    <th>Adresse IP</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r) => (
                    <tr
                      key={r.id}
                      className={`row-click ${r.action === "login_failed" ? "row-alert" : ""}`}
                      tabIndex={0}
                      onClick={() => setSelected(r)}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSelected(r))}
                      aria-label={`${r.action_label}, ${formatDateTime(r.created_at)}. Ouvrir le détail.`}
                    >
                      <td data-label="Date">
                        <div className="target" style={{ textAlign: "inherit" }}>
                          <span>{formatDateTime(r.created_at)}</span>
                          <small>{relativeTime(r.created_at)}</small>
                        </div>
                      </td>
                      <td data-label="Acteur" className="truncate" style={{ maxWidth: 260 }}>
                        {r.user_email || <span className="faint">—</span>}
                      </td>
                      <td data-label="Action">
                        <ActionBadge action={r.action} label={r.action_label} />
                      </td>
                      <td data-label="Cible">
                        {r.target_type ? (
                          <div className="target" style={{ textAlign: "inherit" }}>
                            <span className="truncate" style={{ maxWidth: 240 }}>
                              {r.target_repr || "—"}
                            </span>
                            <small>{r.target_type}</small>
                          </div>
                        ) : (
                          <span className="faint">—</span>
                        )}
                      </td>
                      <td data-label="Adresse IP" className="mono muted">
                        {r.ip_address || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={pageSize} total={total} onPage={(p) => update({ page: p })}>
              <label className="sr-only" htmlFor="page-size">
                Lignes par page
              </label>
              <select
                id="page-size"
                className="select select-sm"
                style={{ width: 118 }}
                value={pageSize}
                onChange={(e) => update({ page_size: e.target.value })}
              >
                {AUDIT_PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>
                    {n} par page
                  </option>
                ))}
              </select>
            </Pagination>
          </>
        )}
      </section>

      {selected && <EntryDrawer entry={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
