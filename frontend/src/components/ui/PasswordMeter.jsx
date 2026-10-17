import { Check, Circle } from "lucide-react";
import { passwordChecks, passwordStrength } from "../../utils/password";

export default function PasswordMeter({ password, email }) {
  const s = passwordStrength(password);
  const checks = passwordChecks(password, email);
  return (
    <div className="pw-meter" aria-live="polite">
      <div className="pw-head">
        <span>Robustesse</span>
        <b style={{ color: "var(--text)" }}>{password ? s.label : "—"}</b>
      </div>
      <div className="pw-bars" data-tone={s.tone}>
        {[1, 2, 3, 4, 5].map((n) => (
          <i key={n} className={password && s.score >= n ? "on" : ""} />
        ))}
      </div>
      <ul className="pw-checks">
        {checks.map((c) => (
          <li key={c.id} className={c.ok ? "ok" : ""}>
            {c.ok ? <Check size={14} /> : <Circle size={14} />}
            {c.label}
          </li>
        ))}
      </ul>
    </div>
  );
}
