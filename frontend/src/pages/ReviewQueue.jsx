import { useSearchParams } from "react-router-dom";
import { ArrowRight, Inbox, RefreshCw } from "lucide-react";
import { listReviewQueue } from "../api/review";
import { REVIEW_SOURCE, VERDICT, VERDICT_VALUES } from "../api/constants";
import { DetectionBadge, ReportBadge, ScanStatusBadge, VerdictBadge } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { Segmented, SelectField } from "../components/ui/Fields";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import SafeUrl from "../components/ui/SafeUrl";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatNumber, relativeTime } from "../utils/format";

const PAGE_SIZE = 20;
const ORDERING = [
  { value: "created_at", label: "Plus anciens" },
  { value: "uncertainty", label: "Plus incertains" },
];

const scoreText = (value) => (typeof value === "number" ? value.toFixed(3) : "—");

export default function ReviewQueue() {
  useDocumentTitle("File de revue");
  const [sp, setSp] = useSearchParams();

  const source = sp.get("source") || "";
  const verdict = sp.get("verdict") || "";
  const ordering = sp.get("ordering") || "created_at";
  const page = Math.max(1, Number(sp.get("page")) || 1);

  const update = (patch) => {
    const next = new URLSearchParams(sp);
    Object.entries(patch).forEach(([key, value]) => (value === "" || value == null ? next.delete(key) : next.set(key, String(value))));
    if (!("page" in patch)) next.delete("page");
    setSp(next, { replace: true });
  };

  const { data, error, loading, reload } = useAsync(
    (signal) => listReviewQueue({ page, page_size: PAGE_SIZE, source, verdict, ordering }, signal),
    [sp.toString()]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;
  const hasFilters = Boolean(source || verdict);
  const reportedCount = results.filter((row) => row.reported).length;
  const uncertainCount = results.filter((row) => row.verdict === "uncertain").length;

  const reset = () => {
    setSp(new URLSearchParams(), { replace: true });
  };

  return (
    <>
      <PageHeader
        title="File de revue"
        description="Les scans incertains et les signalements en attente de décision. Ouvrez un cas pour l'examiner."
        actions={
          <div className="toolbar-actions">
            <div className="stat-pills" aria-label="Résumé de la file">
              <div className="stat-pill">
                <b>{formatNumber(total)}</b> en attente
              </div>
              <div className="stat-pill">
                <b>{formatNumber(reportedCount)}</b> signalés sur la page
              </div>
              <div className="stat-pill">
                <b>{formatNumber(uncertainCount)}</b> incertains sur la page
              </div>
            </div>
            <Button variant="ghost" icon={RefreshCw} onClick={reload} loading={loading}>
              Rafraîchir
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Cas en attente de revue">
        <div className="toolbar">
          <div className="grow">
            <Segmented
              label="Filtrer par origine"
              value={source}
              onChange={(value) => update({ source: value })}
              options={[
                { value: "", label: "Toutes les origines" },
                ...Object.entries(REVIEW_SOURCE).map(([value, label]) => ({ value, label })),
              ]}
            />
          </div>
          <div className="group">
            <SelectField size="sm" label="Verdict" value={verdict} onChange={(event) => update({ verdict: event.target.value })}>
              <option value="">Tous les verdicts</option>
              {VERDICT_VALUES.map((value) => (
                <option key={value} value={value}>
                  {VERDICT[value]?.label || value}
                </option>
              ))}
            </SelectField>
            <Segmented
              label="Trier les cas"
              value={ordering}
              onChange={(value) => update({ ordering: value })}
              options={ORDERING}
            />
            <Button variant="quiet" size="sm" onClick={reset} disabled={!hasFilters}>
              Réinitialiser
            </Button>
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={7} cols={7} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="Aucun cas en attente"
            action={
              hasFilters && (
                <Button variant="ghost" onClick={reset}>
                  Réinitialiser les filtres
                </Button>
              )
            }
          >
            {hasFilters
              ? "Aucun cas ne correspond à ces filtres."
              : "La file est vide : tous les scans incertains et signalements ont été traités."}
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
                    <th>Signalement</th>
                    <th>Score</th>
                    <th>Reçu</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((row) => (
                    <tr key={row.id}>
                      <td data-label="Site">
                        <div className="target">
                          <strong className="truncate" style={{ maxWidth: 300 }}>
                            <SafeUrl value={row.domain} />
                          </strong>
                          <small className="truncate" style={{ maxWidth: 340 }}>
                            {row.url}
                          </small>
                          <span style={{ marginTop: 4 }}>
                            <DetectionBadge source={row.detection_source} />
                          </span>
                        </div>
                      </td>
                      <td data-label="Statut">
                        <ScanStatusBadge status={row.status} />
                      </td>
                      <td data-label="Verdict">
                        <VerdictBadge verdict={row.verdict} />
                      </td>
                      <td data-label="Signalement">
                        <ReportBadge reported={row.reported} claimedLabel={row.claimed_label} />
                      </td>
                      <td data-label="Score" className="tabular">
                        {scoreText(row.score)}
                      </td>
                      <td data-label="Reçu" className="muted" title={row.created_at}>
                        {relativeTime(row.created_at)}
                      </td>
                      <td className="col-actions">
                        <Button variant="quiet" size="sm" to={`/review/${row.id}`} iconRight={ArrowRight}>
                          Examiner
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onPage={(next) => update({ page: next })} />
          </>
        )}
      </section>
    </>
  );
}
