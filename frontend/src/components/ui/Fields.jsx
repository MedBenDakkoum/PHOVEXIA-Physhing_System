import { forwardRef, useId, useState } from "react";
import { CircleAlert, Eye, EyeOff } from "lucide-react";

export const TextField = forwardRef(function TextField(
  { label, error, hint, icon: Icon, trailing, className = "", inputClassName = "", id: idProp, size, ...rest },
  ref
) {
  const auto = useId();
  const id = idProp || auto;
  const describedBy = [error && `${id}-err`, hint && `${id}-hint`].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`field ${className}`}>
      {label && <label htmlFor={id}>{label}</label>}
      <div className="input-wrap">
        {Icon && (
          <span className="lead">
            <Icon size={18} aria-hidden="true" />
          </span>
        )}
        <input
          ref={ref}
          id={id}
          className={`input ${size === "sm" ? "input-sm" : ""} ${inputClassName}`}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={describedBy}
          {...rest}
        />
        {trailing && <span className="trail">{trailing}</span>}
      </div>
      {hint && !error && (
        <span id={`${id}-hint`} className="field-hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-err`} className="field-error" role="alert">
          <CircleAlert size={14} style={{ marginTop: 2, flex: "none" }} aria-hidden="true" />
          {error}
        </span>
      )}
    </div>
  );
});

export const PasswordField = forwardRef(function PasswordField(props, ref) {
  const [show, setShow] = useState(false);
  return (
    <TextField
      ref={ref}
      {...props}
      type={show ? "text" : "password"}
      trailing={
        <button
          type="button"
          className="icon-btn"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? "Masquer le mot de passe" : "Afficher le mot de passe"}
          aria-pressed={show}
        >
          {show ? <EyeOff size={18} /> : <Eye size={18} />}
        </button>
      }
    />
  );
});

export function SelectField({ label, error, hint, className = "", id: idProp, children, size, ...rest }) {
  const auto = useId();
  const id = idProp || auto;
  return (
    <div className={`field ${className}`}>
      {label && <label htmlFor={id}>{label}</label>}
      <select id={id} className={`select ${size === "sm" ? "select-sm" : ""}`} aria-invalid={error ? "true" : undefined} {...rest}>
        {children}
      </select>
      {hint && !error && <span className="field-hint">{hint}</span>}
      {error && (
        <span className="field-error" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

export const TextAreaField = forwardRef(function TextAreaField(
  { label, error, hint, className = "", id: idProp, rows = 4, ...rest },
  ref
) {
  const auto = useId();
  const id = idProp || auto;
  const describedBy = [error && `${id}-err`, hint && `${id}-hint`].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`field ${className}`}>
      {label && <label htmlFor={id}>{label}</label>}
      <textarea
        ref={ref}
        id={id}
        className="textarea"
        rows={rows}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={describedBy}
        {...rest}
      />
      {hint && !error && (
        <span id={`${id}-hint`} className="field-hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-err`} className="field-error" role="alert">
          <CircleAlert size={14} style={{ marginTop: 2, flex: "none" }} aria-hidden="true" />
          {error}
        </span>
      )}
    </div>
  );
});

export function Checkbox({ label, description, checked, onChange, disabled, id: idProp }) {
  const auto = useId();
  const id = idProp || auto;
  return (
    <label className={`checkbox-row ${disabled ? "is-disabled" : ""}`} htmlFor={id}>
      <input
        id={id}
        type="checkbox"
        className="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <strong>{label}</strong>
        {description && <span>{description}</span>}
      </span>
    </label>
  );
}

export function Switch({ checked, onChange, label, description, disabled }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className="switch"
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="switch-track" aria-hidden="true" />
      <span className="switch-text">
        <strong>{label}</strong>
        {description && <span>{description}</span>}
      </span>
    </button>
  );
}

export function Segmented({ value, onChange, options, label }) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={String(o.value)} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}
