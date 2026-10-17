import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { CheckCircle2, Info, TriangleAlert, X, XCircle } from "lucide-react";

const ToastContext = createContext(null);
const ICONS = { success: CheckCircle2, error: XCircle, info: Info, warning: TriangleAlert };

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const seq = useRef(0);

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const push = useCallback(
    (type, title, message) => {
      const id = ++seq.current;
      setToasts((t) => [...t.slice(-3), { id, type, title, message }]);
      setTimeout(() => dismiss(id), type === "error" ? 7000 : 4500);
    },
    [dismiss]
  );

  const api = useMemo(
    () => ({
      success: (title, message) => push("success", title, message),
      error: (title, message) => push("error", title, message),
      info: (title, message) => push("info", title, message),
      warning: (title, message) => push("warning", title, message),
    }),
    [push]
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts" role="region" aria-label="Notifications" aria-live="polite">
        {toasts.map((t) => {
          const Icon = ICONS[t.type];
          return (
            <div key={t.id} className={`toast toast-${t.type}`} role={t.type === "error" ? "alert" : "status"}>
              <Icon size={20} className="toast-icon" aria-hidden="true" />
              <div className="toast-body">
                <strong>{t.title}</strong>
                {t.message && <span>{t.message}</span>}
              </div>
              <button className="toast-close" onClick={() => dismiss(t.id)} aria-label="Fermer la notification">
                <X size={16} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
