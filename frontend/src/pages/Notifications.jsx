import { useState } from "react";
import { Bell, CheckCheck, ExternalLink, RefreshCw } from "lucide-react";
import { listNotifications, markNotificationRead } from "../api/notifications";
import { NOTIFICATION_KIND } from "../api/constants";
import Button from "../components/ui/Button";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useToast } from "../context/ToastContext";
import { formatDateTime, formatNumber, relativeTime } from "../utils/format";

const PAGE_SIZE = 20;

export default function Notifications() {
  useDocumentTitle("Notifications");
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [busyId, setBusyId] = useState(null);

  const { data, error, loading, reload } = useAsync(
    (signal) => listNotifications({ page, page_size: PAGE_SIZE }, signal),
    [page]
  );

  const results = data?.results || [];
  const total = data?.count ?? 0;
  const unread = data?.unread_count ?? 0;

  const markRead = async (notification) => {
    setBusyId(notification.id);
    try {
      await markNotificationRead(notification.id);
      toast.success("Notification lue", "Le compteur a été mis à jour.");
      window.dispatchEvent(new Event("pm:notifications-changed"));
      reload();
    } catch (err) {
      toast.error("Action impossible", err.message);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Les décisions prises sur vos signalements apparaissent ici."
        actions={
          <div className="toolbar-actions">
            <div className="stat-pills" aria-label="Résumé">
              <div className="stat-pill">
                <b>{formatNumber(unread)}</b> non lues
              </div>
              <div className="stat-pill">
                <b>{formatNumber(total)}</b> au total
              </div>
            </div>
            <Button variant="ghost" icon={RefreshCw} onClick={reload} loading={loading}>
              Rafraîchir
            </Button>
          </div>
        }
      />

      <section className="card list-card" aria-label="Mes notifications">
        {loading && !data ? (
          <TableSkeleton rows={6} cols={3} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : results.length === 0 ? (
          <EmptyState icon={Bell} title="Aucune notification">
            Vous serez notifié lorsqu'un analyste aura traité l'un de vos signalements.
          </EmptyState>
        ) : (
          <>
            <div className="notif-list" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              {results.map((notification) => {
                const isUnread = !notification.read_at;
                return (
                  <article className={`notif-item ${isUnread ? "unread" : ""}`} key={notification.id}>
                    <span className="notif-ico" aria-hidden="true">
                      <Bell size={19} />
                    </span>
                    <div className="notif-main">
                      <div className="notif-meta">
                        <span className="badge badge-gold">
                          {NOTIFICATION_KIND[notification.kind] || notification.kind}
                        </span>
                        {isUnread && <span className="badge badge-danger">Non lue</span>}
                        <span title={formatDateTime(notification.created_at)}>{relativeTime(notification.created_at)}</span>
                      </div>
                      <p>{notification.message}</p>
                      <div className="inline-actions">
                        {notification.scan && (
                          <Button variant="quiet" size="sm" to={`/scans/${notification.scan}`} iconRight={ExternalLink}>
                            Voir le scan
                          </Button>
                        )}
                        {isUnread && (
                          <Button
                            variant="ghost"
                            size="sm"
                            icon={CheckCheck}
                            loading={busyId === notification.id}
                            onClick={() => markRead(notification)}
                          >
                            Marquer comme lue
                          </Button>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
          </>
        )}
      </section>
    </>
  );
}
