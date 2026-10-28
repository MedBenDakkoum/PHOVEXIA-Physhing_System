import { Activity, AlertTriangle, CheckCircle2, Clock3, Cpu, Database, RefreshCw, Server, Workflow, XCircle } from "lucide-react";
import { getAdminHealth } from "../api/admin";
import Button from "../components/ui/Button";
import PageHeader from "../components/ui/PageHeader";
import { ErrorState, Skeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatDateTime } from "../utils/format";

const CHECK_META = {
  database: { label: "Base de données", icon: Database },
  redis: { label: "Redis", icon: Server },
  celery: { label: "Workers Celery", icon: Workflow },
  queue_length: { label: "File Celery", icon: Activity },
  stuck_scans: { label: "Scans bloqués", icon: Clock3 },
  last_finished_scan: { label: "Dernier scan terminé", icon: Clock3 },
  active_model_version: { label: "Version active", icon: Cpu },
  active_model: { label: "Modèle servi", icon: Cpu },
};

const STATUS = {
  ok: { label: "Opérationnel", icon: CheckCircle2, className: "status-ok" },
  warning: { label: "Avertissement", icon: AlertTriangle, className: "status-warning" },
  degraded: { label: "Dégradé", icon: XCircle, className: "status-degraded" },
};

function checkValue(name, value) {
  if (value === null || value === undefined || value === "") return "—";
  if (name === "last_finished_scan") return formatDateTime(value);
  if (typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => `${key}: ${item}`)
      .join(" · ");
  }
  return String(value);
}

export default function AdminHealth() {
  useDocumentTitle("Santé du système");
  const { data, error, loading, reload } = useAsync((signal) => getAdminHealth(signal), []);

  if (error) {
    return (
      <div className="card">
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  }
  if (loading || !data) {
    return (
      <div className="health-grid">
        {[0, 1, 2, 3, 4, 5].map((item) => (
          <div className="card card-pad" key={item}>
            <Skeleton h={18} w="45%" />
            <Skeleton h={12} w="80%" style={{ marginTop: 16 }} />
            <Skeleton h={12} w="60%" style={{ marginTop: 8 }} />
          </div>
        ))}
      </div>
    );
  }

  const status = STATUS[data.status] || STATUS.degraded;
  const StatusIcon = status.icon;
  const checks = Object.entries(data.checks || {});

  return (
    <>
      <PageHeader
        title="Santé du système"
        description="Contrôles indépendants de la base, du broker, des workers et du modèle actif."
        actions={
          <Button variant="quiet" icon={RefreshCw} onClick={reload} loading={loading}>
            Revérifier
          </Button>
        }
      />

      <section className={`health-banner ${status.className}`} aria-live="polite">
        <span className="health-banner-icon">
          <StatusIcon size={28} />
        </span>
        <div>
          <h2>{status.label}</h2>
          <p>
            Vérification du {formatDateTime(data.checked_at)}. Chaque contrôle est exécuté séparément : une panne
            partielle ne bloque pas le reste du diagnostic.
          </p>
        </div>
      </section>

      <div className="health-grid">
        {checks.map(([name, check]) => {
          const meta = CHECK_META[name] || { label: name, icon: Activity };
          const Icon = meta.icon;
          return (
            <article className={`card card-pad health-card ${check.ok ? "is-ok" : "is-bad"}`} key={name}>
              <div className="health-card-head">
                <span className="health-icon">
                  <Icon size={20} />
                </span>
                <span className={`badge ${check.ok ? "badge-success" : "badge-danger"}`}>
                  {check.ok ? "OK" : "Échec"}
                </span>
              </div>
              <h3>{meta.label}</h3>
              <p className="health-message">{check.message}</p>
              <dl className="kv health-kv">
                <dt>Valeur</dt>
                <dd className="mono">{checkValue(name, check.value)}</dd>
              </dl>
            </article>
          );
        })}
      </div>

      <div className="alert alert-info">
        <Activity size={18} />
        <span>
          Le diagnostic ne renvoie jamais de secret ni de pile d’appels. Un état « avertissement » signifie que le
          modèle actif est un MOCK, pas le bundle de production.
        </span>
      </div>
    </>
  );
}
