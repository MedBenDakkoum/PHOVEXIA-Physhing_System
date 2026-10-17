import { useState } from "react";

const W = 640;
const H = 236;
const M = { top: 14, right: 8, bottom: 30, left: 34 };

function niceMax(v) {
  if (v <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(v));
  const n = v / pow;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return step * pow;
}

/**
 * Histogramme empilé. data : [{ label, title, values: { cle: nombre } }]
 * series : [{ key, label, color }]
 */
export default function StackedBars({ data, series, ariaLabel }) {
  const [hover, setHover] = useState(null);
  const plotW = W - M.left - M.right;
  const plotH = H - M.top - M.bottom;
  const totals = data.map((d) => series.reduce((s, x) => s + (d.values[x.key] || 0), 0));
  const max = niceMax(Math.max(0, ...totals));
  const ticks = [0, 1, 2, 3, 4].map((i) => (max / 4) * i);
  const gw = plotW / data.length;
  const bw = Math.min(46, gw * 0.56);
  const y = (v) => M.top + plotH - (v / max) * plotH;

  const active = hover !== null ? data[hover] : null;
  const tipLeft = hover !== null ? ((M.left + gw * hover + gw / 2) / W) * 100 : 0;

  return (
    <div className="chart" data-hover={hover !== null ? "" : undefined}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={ariaLabel} style={{ width: "100%", height: "auto" }}>
        {ticks.map((t) => (
          <g key={t}>
            <line className="grid-line" x1={M.left} x2={W - M.right} y1={y(t)} y2={y(t)} />
            <text x={M.left - 8} y={y(t) + 4} textAnchor="end">
              {Math.round(t)}
            </text>
          </g>
        ))}
        {data.map((d, i) => {
          const cx = M.left + gw * i + gw / 2;
          let acc = 0;
          return (
            <g key={d.label} className={`bar ${hover === i ? "hover" : ""}`}>
              {series.map((s) => {
                const v = d.values[s.key] || 0;
                if (!v) return null;
                const h = (v / max) * plotH;
                const top = y(acc + v);
                acc += v;
                return (
                  <rect
                    key={s.key}
                    x={cx - bw / 2}
                    y={top}
                    width={bw}
                    height={Math.max(h - 1.5, 1)}
                    rx="3"
                    style={{ fill: s.color }}
                  />
                );
              })}
              <text x={cx} y={H - 8} textAnchor="middle">
                {d.label}
              </text>
              <rect
                x={M.left + gw * i}
                y={M.top}
                width={gw}
                height={plotH + 20}
                fill="transparent"
                tabIndex={0}
                aria-label={`${d.title} : ${totals[i]} événement${totals[i] > 1 ? "s" : ""}`}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
              />
            </g>
          );
        })}
      </svg>
      {active && (
        <div className="chart-tip" style={{ left: `${Math.min(86, Math.max(14, tipLeft))}%` }}>
          <b>{active.title}</b>
          {series.map((s) => (
            <div key={s.key}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                <i style={{ width: 8, height: 8, borderRadius: 2, background: s.color }} />
                {s.label}
              </span>
              <b style={{ margin: 0, fontSize: "inherit" }}>{active.values[s.key] || 0}</b>
            </div>
          ))}
        </div>
      )}
      <div className="legend">
        {series.map((s) => (
          <span key={s.key} style={{ "--c": s.color }}>
            <i />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}
