import { RefreshCw, ServerCrash } from "lucide-react";
import { errorMessage } from "../../api/errors";
import Button from "./Button";

export function EmptyState({ icon: Icon, title, children, action }) {
  return (
    <div className="state">
      {Icon && (
        <span className="state-ico">
          <Icon size={30} />
        </span>
      )}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = "Impossible de charger les données" }) {
  return (
    <div className="state" role="alert">
      <span className="state-ico danger">
        <ServerCrash size={30} />
      </span>
      <h3>{title}</h3>
      <p>{errorMessage(error)}</p>
      {onRetry && (
        <Button variant="ghost" icon={RefreshCw} onClick={onRetry}>
          Réessayer
        </Button>
      )}
    </div>
  );
}

export function Skeleton({ w = "100%", h = 14, r, style }) {
  return <span className="skeleton" style={{ width: w, height: h, borderRadius: r, ...style }} aria-hidden="true" />;
}

export function TableSkeleton({ rows = 6, cols = 5 }) {
  return (
    <div role="status" aria-label="Chargement" style={{ padding: "8px 18px 18px" }}>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          style={{
            display: "grid",
            gridTemplateColumns: `1.6fr repeat(${cols - 1}, 1fr)`,
            gap: 18,
            padding: "16px 0",
            borderBottom: "1px solid var(--line)",
            alignItems: "center",
          }}
        >
          <Skeleton h={16} w={`${60 + ((i * 13) % 30)}%`} />
          {Array.from({ length: cols - 1 }, (_, j) => (
            <Skeleton key={j} h={14} w={`${50 + ((i + j) * 11) % 40}%`} />
          ))}
        </div>
      ))}
      <span className="sr-only">Chargement en cours…</span>
    </div>
  );
}
