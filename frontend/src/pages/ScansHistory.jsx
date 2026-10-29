import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, History, RefreshCw, Search } from "lucide-react";
import { getScanQuota, listScans } from "../api/scans";
import { SCAN_STATUS, SCAN_STATUS_VALUES, VERDICT, VERDICT_VALUES } from "../api/constants";
import {
  DetectionBadge,
  ReportBadge,
  ScanStatusBadge,
  VerdictBadge,
} from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { SelectField, TextField } from "../components/ui/Fields";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import SafeUrl from "../components/ui/SafeUrl";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatNumber, relativeTime } from "../utils/format";

const PAGE_SIZE = 20;
const ORDERING = [
  { value: "-created_at", label: "Plus récents" },
  { value: "created_at", label: "Plus anciens" },
  { value: "-score", label: "Score décroissant" },
  { value: "score", label: "Score croissant" },
];
const scoreText = (value) => (typeof value === "number" ? value.toFixed(3) : "—");

export default function ScansHistory() {
  useDocumentTitle("Historique des scans");
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") || "");
  const [quota, setQuota] = useState(null);

  const page = Math.max(1, Number(sp.get("page")) || 1);
  const verdict = sp.get("verdict") || "";
  const status = sp.get("status") || "";
  const ordering = sp.get("ordering") || "-created_at";
  const createdAfter = sp.get("created_after") || "";
  const createdBefore = sp.get("created_before") || "";
  const hasFilters = Boolean(q || verdict || status || createdAfter || createdBefore);

  useEffect(() => {
    const controller = new AbortController();
    getScanQuota(controller.signal).then(setQuota).catch(() => {});
    return () => controller.abort();
  }, []);

  useEffect(() => {
    setQ(sp.get("q") || "");
  }, [sp]);

  const update = (patch) => {
    const next = new URLSearchParams(sp);
    Object.entries(patch).forEach(([key, value]) => {
      if (value === "" || value == null) next.delete(key);
      else next.set(key, String(value));
    });
    if (!("page" in patch)) next.delete("page");
    setSp(next, { replace: true });
  };

  const { data, error, loading, reload } = useAsync(
    (signal) =>
      listScans(
        {
          page,
          page_size: PAGE_SIZE,
          q: sp.get("q") || "",
          verdict,
          status,
          created_after: createdAfter,
          created_before: createdBefore,
          ordering,
        },
        signal
      ),
    [sp.toString()]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;

  const reset = () => {
    setQ("");
    setSp(new URLSearchParams(), { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Mes scans"
        description="Retrouvez vos analyses, filtrez par verdict ou statut, puis ouvrez un résultat pour voir le détail."
        actions={
          <div className="toolbar-actions">
            {quota && (
              <span className="stat-pill">
                <b>{formatNumber(quota.remaining)}</b> restant{quota.remaining === 1 ? "" : "s"}
              </span>
            )}
            <Button variant="ghost" icon={RefreshCw} onClick={reload} loading={loading}>
              Rafraîchir
            </Button>
            <Button variant="gold" to="/scans/new" icon={ArrowRight}>
              Nouveau scan
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Historique de mes scans">
        <div className="toolbar scan-toolbar">
          <form
            className="grow"
            onSubmit={(event) => {
              event.preventDefault();
              update({ q });
            }}
          >
            <TextField
              size="sm"
              label="Rechercher"
              placeholder="URL ou domaine"
              value={q}
              onChange={(event) => setQ(event.target.value)}
              icon={Search}
              name="q"
              data-testid="scan-search"
            />
          </form>
          <div className="group">
            <SelectField
              size="sm"
              label="Verdict"
              value={verdict}
              onChange={(event) => update({ verdict: event.target.value })}
              data-testid="scan-filter-verdict"
            >
              <option value="">Tous les verdicts</option>
              {VERDICT_VALUES.map((value) => (
                <option key={value} value={value}>
                  {VERDICT[value]?.label || value}
                </option>
              ))}
            </SelectField>
            <SelectField
              size="sm"
              label="Statut"
              value={status}
              onChange={(event) => update({ status: event.target.value })}
              data-testid="scan-filter-status"
            >
              <option value="">Tous les statuts</option>
              {SCAN_STATUS_VALUES.map((value) => (
                <option key={value} value={value}>
                  {SCAN_STATUS[value]?.label || value}
                </option>
              ))}
            </SelectField>
            <SelectField
              size="sm"
              label="Trier"
              value={ordering}
              onChange={(event) => update({ ordering: event.target.value })}
            >
              {ORDERING.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </SelectField>
          </div>
        </div>

        <div className="toolbar scan-toolbar scan-toolbar-dates">
          <TextField
            size="sm"
            type="date"
            label="Après le"
            value={createdAfter}
            onChange={(event) => update({ created_after: event.target.value })}
            data-testid="scan-filter-after"
          />
          <TextField
            size="sm"
            type="date"
            label="Avant le"
            value={createdBefore}
            onChange={(event) => update({ created_before: event.target.value })}
            data-testid="scan-filter-before"
          />
          <Button variant="quiet" size="sm" onClick={reset} disabled={!hasFilters}>
            Réinitialiser les filtres
          </Button>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={7} cols={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState
            icon={History}
            title={hasFilters ? "Aucun scan ne correspond" : "Aucun scan pour le moment"}
            action={
              hasFilters ? (
                <Button variant="ghost" onClick={reset}>
                  Réinitialiser les filtres
                </Button>
              ) : (
                <Button variant="gold" to="/scans/new">
                  Lancer mon premier scan
                </Button>
              )
            }
          >
            {hasFilters
              ? "Modifiez la recherche ou les filtres pour retrouver un scan."
              : "Soumettez une adresse pour lancer votre première analyse."}
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Site</th>
                    <th>Statut</th>
                    <th>Verdict</th>
                    <th>Score</th>
                    <th>Signalement</th>
                    <th>Reçu</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((scan) => (
                    <tr key={scan.id} data-testid="scan-row">
                      <td data-label="Site">
                        <div className="target">
                          <strong className="truncate" style={{ maxWidth: 330 }}>
                            <SafeUrl value={scan.domain} />
                          </strong>
                          <small className="truncate" style={{ maxWidth: 380 }}>
                            {scan.url}
                          </small>
                          <span style={{ marginTop: 4 }}>
                            <DetectionBadge source={scan.detection_source} />
                          </span>
                        </div>
                      </td>
                      <td data-label="Statut">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td data-label="Verdict">
                        <VerdictBadge verdict={scan.verdict} />
                      </td>
                      <td data-label="Score" className="tabular">
                        {scoreText(scan.score)}
                      </td>
                      <td data-label="Signalement">
                        <ReportBadge reported={scan.has_report} />
                      </td>
                      <td data-label="Reçu" className="muted" title={scan.created_at}>
                        {relativeTime(scan.created_at)}
                      </td>
                      <td data-label="Action">
                        <Link to={`/scans/${scan.id}`} className="btn btn-quiet btn-sm">
                          Ouvrir <ArrowRight size={16} aria-hidden="true" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              total={total}
              onPage={(next) => update({ page: next })}
            />
          </>
        )}
      </section>
    </>
  );
}
