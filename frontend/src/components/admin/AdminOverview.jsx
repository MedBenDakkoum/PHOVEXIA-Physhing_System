import { useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Clock,
  Cpu,
  Globe2,
  Inbox,
  Percent,
  RefreshCw,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import { getAdminDashboard } from "../../api/admin";
import { DETECTION_SOURCE, ROLES, SCAN_STATUS, VERDICT } from "../../api/constants";
import Donut from "../charts/Donut";
import StackedBars from "../charts/StackedBars";
import Button from "../ui/Button";
import { Segmented } from "../ui/Fields";
import { EmptyState, ErrorState, Skeleton } from "../ui/States";
import { useAsync } from "../../hooks/useAsync";
import { formatNumber } from "../../utils/format";

const PERIODS = [
  { value: "7d", label: "7 jours" },
  { value: "30d", label: "30 jours" },
  { value: "90d", label: "90 jours" },
];

const VERDICT_COLORS = {
  phishing: "var(--danger)",
  legitimate: "var(--success)",
  uncertain: "var(--gold)",
  none: "var(--text-3)",
};

const ROLE_ORDER = ["admin", "analyst", "end_user"];

const dayMonth = new Intl.DateTimeFormat("fr-FR", { day: "2-digit", month: "short" });
const weekday = new Intl.DateTimeFormat("fr-FR", { weekday: "short" });
const fullDay = new Intl.DateTimeFormat("fr-FR", { weekday: "long", day: "numeric", month: "long" });

function percent(value) {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %`;
}

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  const digits = seconds < 10 ? 1 : 0;
  return `${seconds.toLocaleString("fr-FR", { maximumFractionDigits: digits })} s`;
}

function parseDay(value) {
  return new Date(`${value}T00:00:00`);
}

function chartRows(rows, period) {
  if (period !== "90d") {
    return rows.map((row) => {
      const date = parseDay(row.date);
      return {
        label: period === "7d" ? weekday.format(date).replace(".", "") : String(date.getDate()),
        title: fullDay.format(date),
        values: { scans: row.count },
      };
    });
  }
  const weeks = new Map();
  rows.forEach((row) => {
    const date = parseDay(row.date);
    const weekStart = new Date(date);
    weekStart.setDate(date.getDate() - ((date.getDay() + 6) % 7));
    const key = weekStart.toISOString().slice(0, 10);
    if (!weeks.has(key)) {
      weeks.set(key, {
        label: dayMonth.format(weekStart).replace(".", ""),
        title: `Semaine du ${fullDay.format(weekStart)}`,
        values: { scans: 0 },
      });
    }
    weeks.get(key).values.scans += row.count;
  });
  return [...weeks.values()];
}

function Kpi({ icon: Icon, label, value, foot, tone = "" }) {
  return (
    <div className={`kpi ${tone}`}>
      <div className="kpi-top">
        <span>{label}</span>
        <span className="kpi-ico">
          <Icon size={18} />
        </span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-foot">{foot}</div>
    </div>
  );
}

function BarList({ rows, empty, formatLabel }) {
  if (!rows.length) return <EmptyState icon={Activity} title={empty} />;
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <ul className="admin-list">
      {rows.map((row) => (
        <li key={row.key} className="admin-list-row">
          <div className="admin-list-head">
            <span>{formatLabel(row.key)}</span>
            <b>{formatNumber(row.count)}</b>
          </div>
          <span className="admin-track" aria-hidden="true">
            <i style={{ width: `${Math.max(3, (row.count / max) * 100)}%` }} />
          </span>
        </li>
      ))}
    </ul>
  );
}

export default function AdminOverview() {
  const [period, setPeriod] = useState("30d");
  const { data, error, loading, reload } = useAsync(
    (signal) => getAdminDashboard({ period }, signal),
    [period]
  );

  if (error) {
    return (
      <div className="card">
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  }
  if (loading || !data) {
    return (
      <>
        <div className="kpis">
          {[0, 1, 2, 3].map((i) => (
            <div className="kpi" key={i}>
              <Skeleton h={14} w="55%" />
              <Skeleton h={38} w="40%" style={{ marginTop: 16 }} />
              <Skeleton h={12} w="70%" style={{ marginTop: 14 }} />
            </div>
          ))}
        </div>
        <div className="dash-grid">
          <div className="card card-pad">
            <Skeleton h={260} r={14} />
          </div>
          <div className="card card-pad">
            <Skeleton h={260} r={14} />
          </div>
        </div>
      </>
    );
  }

  const phishingCount = data.scans_by_verdict?.phishing || 0;
  const confirmed = data.scans_by_status?.confirmed || 0;
  const falsePositives = data.scans_by_status?.false_positive || 0;
  const decisionCount = confirmed + falsePositives;
  const days = chartRows(data.scans_per_day || [], period);
  const verdictSlices = Object.entries(VERDICT)
    .map(([key]) => ({
      label: VERDICT[key].label,
      value: data.scans_by_verdict?.[key] || 0,
      color: VERDICT_COLORS[key],
    }))
    .filter((slice) => slice.value > 0);
  const statusRows = Object.entries(data.scans_by_status || {})
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);
  const roleRows = ROLE_ORDER.map((key) => ({ key, count: data.users_by_role?.[key] || 0 }));
  const sourceRows = Object.entries(data.scans_by_detection_source || {}).map(([key, count]) => ({
    key,
    count,
  }));
  const maxDomain = Math.max(...(data.top_phishing_domains || []).map((item) => item.count), 1);

  return (
    <>
      <div className="admin-toolbar">
        <div>
          <h2 className="card-title">Vue d’ensemble</h2>
          <p className="card-sub">
            Indicateurs agrégés du {data.period?.from ? dayMonth.format(new Date(data.period.from)) : "—"} au{" "}
            {data.period?.to ? dayMonth.format(new Date(data.period.to)) : "—"}.
          </p>
        </div>
        <div className="toolbar-actions">
          <Segmented label="Période du tableau de bord" value={period} onChange={setPeriod} options={PERIODS} />
          <Button variant="quiet" size="sm" icon={RefreshCw} onClick={reload} loading={loading}>
            Rafraîchir
          </Button>
        </div>
      </div>

      <div className="kpis">
        <Kpi
          icon={ScanLine}
          label="Scans analysés"
          value={formatNumber(data.totals?.scans)}
          foot={`${formatNumber(data.quick_checks)} quick checks anonymes`}
        />
        <Kpi
          icon={ShieldAlert}
          tone={phishingCount ? "tone-danger" : ""}
          label="Taux de phishing"
          value={percent(data.phishing_rate)}
          foot={`${formatNumber(phishingCount)} scan(s) classé(s) phishing`}
        />
        <Kpi
          icon={Inbox}
          tone={data.pending_reviews ? "tone-gold" : ""}
          label="En attente de revue"
          value={formatNumber(data.pending_reviews)}
          foot="Cas à traiter par un analyste"
        />
        <Kpi
          icon={Percent}
          label="Taux de faux positifs"
          value={percent(data.false_positive_rate)}
          foot={decisionCount ? `Sur ${formatNumber(decisionCount)} décision(s)` : "Aucune décision encore"}
        />
      </div>

      <div className="admin-summary">
        <span className="stat-pill">
          <Clock size={15} /> Durée médiane : <b>{duration(data.median_scan_duration_seconds)}</b>
        </span>
        <span className="stat-pill">
          <Users size={15} /> Comptes : <b>{formatNumber(data.totals?.users)}</b>
        </span>
        <span className="stat-pill">
          <Activity size={15} /> Échantillon durée : <b>{formatNumber(data.median_sample_size)}</b>
        </span>
        <span className="admin-summary-links">
          <Button variant="quiet" size="sm" to="/review" iconRight={ArrowUpRight}>
            File de revue
          </Button>
          <Button variant="quiet" size="sm" to="/app/admin/models" icon={Cpu}>
            Modèles
          </Button>
          <Button variant="quiet" size="sm" to="/app/admin/settings" icon={SlidersHorizontal}>
            Réglages
          </Button>
        </span>
      </div>

      <div className="dash-grid">
        <section className="card card-pad" aria-label="Scans par jour">
          <div className="card-head">
            <div>
              <h2 className="card-title">Scans par jour</h2>
              <p className="card-sub">
                {period === "90d" ? "Regroupés par semaine." : "Volume quotidien sur la période sélectionnée."}
              </p>
            </div>
            <span className="badge badge-gold">{formatNumber(data.totals?.scans)} scans</span>
          </div>
          {days.length ? (
            <StackedBars
              data={days}
              series={[{ key: "scans", label: "Scans", color: "var(--info)" }]}
              ariaLabel="Nombre de scans par jour"
            />
          ) : (
            <EmptyState icon={Activity} title="Aucun scan sur la période">
              Les scans créés apparaîtront ici.
            </EmptyState>
          )}
        </section>

        <section className="card card-pad" aria-label="Répartition des verdicts">
          <div className="card-head">
            <div>
              <h2 className="card-title">Verdicts</h2>
              <p className="card-sub">Répartition des scans terminés.</p>
            </div>
          </div>
          {verdictSlices.length ? (
            <div className="donut-wrap">
              <Donut
                slices={verdictSlices}
                centerValue={formatNumber(data.totals?.scans)}
                centerLabel="scans"
                ariaLabel="Répartition des verdicts"
              />
              <ul className="donut-list">
                {verdictSlices.map((slice) => (
                  <li key={slice.label} style={{ "--c": slice.color }}>
                    <span className="lbl">
                      <i />
                      {slice.label}
                    </span>
                    <b className="tabular">{formatNumber(slice.value)}</b>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <EmptyState icon={ShieldCheck} title="Aucun verdict">
              Les verdicts apparaîtront après les premiers scans.
            </EmptyState>
          )}
        </section>
      </div>

      <div className="dash-grid even">
        <section className="card card-pad" aria-label="Principaux domaines phishing">
          <div className="card-head">
            <div>
              <h2 className="card-title">Top domaines phishing</h2>
              <p className="card-sub">Dix domaines les plus détectés sur la période.</p>
            </div>
            <Globe2 size={20} className="faint" aria-hidden="true" />
          </div>
          {(data.top_phishing_domains || []).length ? (
            <ol className="admin-domains">
              {data.top_phishing_domains.map((item, index) => (
                <li key={item.domain}>
                  <span className="admin-rank">{index + 1}</span>
                  <div>
                    <strong className="mono">{item.domain}</strong>
                    <span className="admin-track" aria-hidden="true">
                      <i style={{ width: `${Math.max(4, (item.count / maxDomain) * 100)}%` }} />
                    </span>
                  </div>
                  <b className="tabular">{formatNumber(item.count)}</b>
                </li>
              ))}
            </ol>
          ) : (
            <EmptyState icon={Globe2} title="Aucun domaine phishing">
              Aucun domaine n’a été classé phishing sur la période.
            </EmptyState>
          )}
        </section>

        <section className="card card-pad" aria-label="Statuts, sources et comptes">
          <div className="card-head">
            <div>
              <h2 className="card-title">Statuts et sources</h2>
              <p className="card-sub">État des scans et origine de la détection.</p>
            </div>
          </div>
          <BarList
            rows={statusRows}
            empty="Aucun scan sur la période"
            formatLabel={(key) => SCAN_STATUS[key]?.label || (key === "none" ? "Sans statut" : key)}
          />
          <hr className="divider" />
          <BarList
            rows={sourceRows}
            empty="Aucune détection"
            formatLabel={(key) => DETECTION_SOURCE[key] || key}
          />
          <hr className="divider" />
          <BarList
            rows={roleRows}
            empty="Aucun compte"
            formatLabel={(key) => ROLES[key]?.label || key}
          />
        </section>
      </div>
    </>
  );
}
