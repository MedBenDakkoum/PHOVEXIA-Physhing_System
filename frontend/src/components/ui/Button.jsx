import { Link } from "react-router-dom";

/**
 * variant : gold | ghost | quiet | danger | danger-solid
 * size    : sm | md | lg
 */
export default function Button({
  variant = "ghost",
  size = "md",
  loading = false,
  icon: Icon,
  iconRight: IconRight,
  block = false,
  iconOnly = false,
  to,
  href,
  children,
  className = "",
  disabled,
  type = "button",
  ...rest
}) {
  const cls = [
    "btn",
    `btn-${variant}`,
    size !== "md" && `btn-${size}`,
    block && "btn-block",
    iconOnly && "btn-icon",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const inner = (
    <>
      {loading ? <span className="spinner" aria-hidden="true" /> : Icon && <Icon size={size === "sm" ? 16 : 18} aria-hidden="true" />}
      {children}
      {!loading && IconRight && <IconRight size={size === "sm" ? 16 : 18} aria-hidden="true" />}
    </>
  );

  if (href && !disabled) {
    return (
      <a href={href} className={cls} target="_blank" rel="noreferrer" {...rest}>
        {inner}
      </a>
    );
  }
  if (to && !disabled) {
    return (
      <Link to={to} className={cls} {...rest}>
        {inner}
      </Link>
    );
  }
  return (
    <button type={type} className={cls} disabled={disabled || loading} aria-busy={loading || undefined} {...rest}>
      {inner}
    </button>
  );
}
