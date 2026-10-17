import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { TriangleAlert, X } from "lucide-react";
import { useEscape } from "../../hooks/useEscape";
import Button from "./Button";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

function useDialogBehavior(open, onClose, panelRef) {
  useEscape(() => onClose?.(), open);
  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const panel = panelRef.current;
    const first = panel?.querySelector("[data-autofocus]") || panel?.querySelector(FOCUSABLE);
    (first || panel)?.focus();

    const trap = (e) => {
      if (e.key !== "Tab" || !panel) return;
      const items = [...panel.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      if (!items.length) return;
      const [a, z] = [items[0], items[items.length - 1]];
      if (e.shiftKey && document.activeElement === a) {
        e.preventDefault();
        z.focus();
      } else if (!e.shiftKey && document.activeElement === z) {
        e.preventDefault();
        a.focus();
      }
    };
    document.addEventListener("keydown", trap);
    return () => {
      document.removeEventListener("keydown", trap);
      document.body.style.overflow = prevOverflow;
      previous?.focus?.();
    };
  }, [open, panelRef]);
}

function Frame({ open, onClose, title, description, children, footer, drawer, width, closeDisabled }) {
  const panelRef = useRef(null);
  useDialogBehavior(open, closeDisabled ? undefined : onClose, panelRef);
  if (!open) return null;

  const onOverlayDown = (e) => {
    if (e.target === e.currentTarget && !closeDisabled) onClose?.();
  };

  return createPortal(
    <div className={`overlay ${drawer ? "overlay-drawer" : ""}`} onMouseDown={onOverlayDown}>
      <div
        ref={panelRef}
        className={drawer ? "drawer" : "modal"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        style={width ? { width: `min(${width}px, 100%)` } : undefined}
      >
        <div className="modal-head">
          <div>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Fermer" disabled={closeDisabled}>
            <X size={20} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body
  );
}

export const Modal = (props) => <Frame {...props} />;
export const Drawer = (props) => <Frame {...props} drawer />;

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = "Confirmer",
  tone = "danger",
  loading = false,
}) {
  return (
    <Frame
      open={open}
      onClose={onClose}
      title={title}
      closeDisabled={loading}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={loading}>
            Annuler
          </Button>
          <Button variant={tone === "danger" ? "danger-solid" : "gold"} onClick={onConfirm} loading={loading} data-autofocus>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
        <span className={`confirm-ico ${tone === "danger" ? "" : "gold"}`}>
          <TriangleAlert size={24} />
        </span>
        <div className="muted" style={{ paddingTop: 2 }}>
          {message}
        </div>
      </div>
    </Frame>
  );
}
