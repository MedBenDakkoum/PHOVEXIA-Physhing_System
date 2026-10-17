import { cloneElement, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

/** Menu déroulant rendu dans <body> : jamais coupé par un conteneur à défilement. */
export function Menu({ trigger, children, width = 232 }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ left: 0, top: "auto", bottom: "auto" });
  const btnRef = useRef(null);
  const menuRef = useRef(null);

  const close = useCallback(() => setOpen(false), []);

  const toggle = () => {
    if (!open) {
      const r = btnRef.current.getBoundingClientRect();
      const left = Math.max(12, Math.min(window.innerWidth - width - 12, r.right - width));
      const roomBelow = window.innerHeight - r.bottom;
      setPos(
        roomBelow < 280
          ? { left, top: "auto", bottom: window.innerHeight - r.top + 6 }
          : { left, top: r.bottom + 6, bottom: "auto" }
      );
    }
    setOpen((o) => !o);
  };

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (menuRef.current?.contains(e.target) || btnRef.current?.contains(e.target)) return;
      close();
    };
    const onKey = (e) => {
      if (e.key === "Escape") {
        close();
        btnRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    menuRef.current?.querySelector("button:not([disabled]),a")?.focus();
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [open, close]);

  return (
    <>
      {cloneElement(trigger, { ref: btnRef, onClick: toggle, "aria-haspopup": "menu", "aria-expanded": open })}
      {open &&
        createPortal(
          <div
            ref={menuRef}
            className="menu"
            role="menu"
            style={{ position: "fixed", right: "auto", width, ...pos }}
            onClick={close}
          >
            {children}
          </div>,
          document.body
        )}
    </>
  );
}

export function MenuItem({ icon: Icon, danger, children, ...rest }) {
  return (
    <button type="button" role="menuitem" className={`menu-item ${danger ? "danger" : ""}`} {...rest}>
      {Icon && <Icon size={17} aria-hidden="true" />}
      {children}
    </button>
  );
}

export const MenuSeparator = () => <div className="menu-sep" role="separator" />;
