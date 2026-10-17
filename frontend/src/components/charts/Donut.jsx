/** Anneau de répartition. slices : [{ label, value, color }] */
export default function Donut({ slices, size = 170, thickness = 20, centerValue, centerLabel, ariaLabel }) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const total = slices.reduce((s, x) => s + x.value, 0);
  const gap = slices.filter((s) => s.value > 0).length > 1 ? 3 : 0;
  let offset = 0;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={ariaLabel}>
      <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness} style={{ stroke: "var(--line)" }} />
        {total > 0 &&
          slices.map((s) => {
            if (!s.value) return null;
            const len = (s.value / total) * c;
            const el = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                strokeWidth={thickness}
                strokeLinecap="butt"
                strokeDasharray={`${Math.max(len - gap, 0.5)} ${c}`}
                strokeDashoffset={-offset}
                style={{ stroke: s.color }}
              />
            );
            offset += len;
            return el;
          })}
      </g>
      <text
        x="50%"
        y="50%"
        textAnchor="middle"
        className="donut-center"
        style={{ fill: "var(--text)", fontSize: size * 0.21 }}
        dy="0.05em"
      >
        {centerValue}
      </text>
      <text x="50%" y="50%" textAnchor="middle" dy={size * 0.17} style={{ fill: "var(--text-3)", fontSize: 12 }}>
        {centerLabel}
      </text>
    </svg>
  );
}
