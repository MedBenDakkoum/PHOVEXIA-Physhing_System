import { useId } from "react";

const CX = 300;
const CY = 300;
const rad = (deg) => (deg * Math.PI) / 180;
const polar = (deg, r) => [CX + r * Math.sin(rad(deg)), CY - r * Math.cos(rad(deg))];
const fmt = (n) => n.toFixed(2);

// Icônes (grille 24×24, tracés Lucide) : les modalités analysées
const ICONS = {
  mail: (
    <>
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </>
  ),
  link: (
    <>
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </>
  ),
  image: (
    <>
      <rect width="18" height="18" x="3" y="3" rx="2" />
      <circle cx="9" cy="9" r="2" />
      <path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21" />
    </>
  ),
  text: (
    <>
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
      <path d="M13 8H7" />
      <path d="M17 12H7" />
    </>
  ),
};

const NODES = [
  { angle: 0, icon: "mail" },
  { angle: 90, icon: "link" },
  { angle: 180, icon: "image" },
  { angle: 270, icon: "text" },
];

// Menaces repérées par le faisceau (angle, rayon)
const BLIPS = [
  { angle: 38, r: 188 },
  { angle: 128, r: 238 },
  { angle: 214, r: 150 },
  { angle: 301, r: 232 },
  { angle: 338, r: 196 },
];
const BEAM_PERIOD = 8;

/**
 * Bouclier d'or entouré d'un radar : le faisceau balaie les modalités
 * (e-mail, lien, image, texte) et signale les menaces en rouge.
 */
export default function AegisEmblem({ className = "", animated = true, minimal = false }) {
  const id = useId().replace(/:/g, "");
  const ticks = Array.from({ length: 72 }, (_, i) => {
    const long = i % 6 === 0;
    const [x1, y1] = polar(i * 5, long ? 252 : 262);
    const [x2, y2] = polar(i * 5, 272);
    return <line key={i} x1={fmt(x1)} y1={fmt(y1)} x2={fmt(x2)} y2={fmt(y2)} strokeWidth={long ? 2 : 1} />;
  });

  // Traînée du faisceau : 16 secteurs de 4,5° à opacité croissante
  const SLICES = 16;
  const SPAN = 72;
  const R = 272;
  const trail = Array.from({ length: SLICES }, (_, i) => {
    const a0 = -SPAN + (i * SPAN) / SLICES;
    const a1 = -SPAN + ((i + 1) * SPAN) / SLICES;
    const [x0, y0] = polar(a0, R);
    const [x1, y1] = polar(a1, R);
    const o = 0.012 + Math.pow((i + 1) / SLICES, 2.2) * 0.3;
    return (
      <path
        key={i}
        d={`M${CX} ${CY} L${fmt(x0)} ${fmt(y0)} A${R} ${R} 0 0 1 ${fmt(x1)} ${fmt(y1)} Z`}
        fill="#ffdc8f"
        opacity={o.toFixed(3)}
      />
    );
  });

  return (
    <svg viewBox="0 0 600 600" className={`emblem ${className}`} role="img" aria-label="Bouclier d'or entouré d'un radar">
      <defs>
        <radialGradient id={`${id}glow`} cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#f2b84b" stopOpacity="0.38" />
          <stop offset="0.55" stopColor="#f2b84b" stopOpacity="0.08" />
          <stop offset="1" stopColor="#f2b84b" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}gold`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ffe3a3" />
          <stop offset="0.55" stopColor="#f2b84b" />
          <stop offset="1" stopColor="#bf7f14" />
        </linearGradient>
        <linearGradient id={`${id}navy`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#223183" />
          <stop offset="1" stopColor="#0a1236" />
        </linearGradient>
        <filter id={`${id}shadow`} x="-30%" y="-30%" width="160%" height="170%">
          <feDropShadow dx="0" dy="14" stdDeviation="16" floodColor="#000" floodOpacity="0.55" />
        </filter>
      </defs>

      <circle cx={CX} cy={CY} r="290" fill={`url(#${id}glow)`} />

      {/* Cadran extérieur */}
      <g className={animated ? "em-ring-a" : ""} stroke="#a9b8ea" strokeOpacity="0.4">
        <circle cx={CX} cy={CY} r="276" fill="none" strokeOpacity="0.2" />
        {ticks}
      </g>
      <g className={animated ? "em-ring-b" : ""} fill="none">
        <circle cx={CX} cy={CY} r="224" stroke="#a9b8ea" strokeOpacity="0.28" strokeDasharray="34 16" />
      </g>
      <circle cx={CX} cy={CY} r="176" fill="none" stroke="#f2b84b" strokeOpacity="0.28" />
      <circle cx={CX} cy={CY} r="128" fill="none" stroke="#a9b8ea" strokeOpacity="0.14" />

      {/* Faisceau de balayage */}
      {!minimal && (
        <g className={animated ? "em-beam" : ""} style={animated ? undefined : { transform: `rotate(40deg)`, transformOrigin: "300px 300px" }}>
          {trail}
          <line x1={CX} y1={CY} x2={CX} y2={CY - R} stroke="#ffe3a3" strokeWidth="2" strokeOpacity="0.9" />
        </g>
      )}

      {/* Menaces repérées */}
      {!minimal &&
        BLIPS.map((b, i) => {
          const [x, y] = polar(b.angle, b.r);
          const style = { "--d": `${((b.angle / 360) * BEAM_PERIOD).toFixed(2)}s` };
          return (
            <g key={i}>
              <circle cx={fmt(x)} cy={fmt(y)} r="9" fill="none" stroke="#ff6b78" strokeWidth="2" className={animated ? "em-blip-ring" : ""} style={style} opacity={animated ? undefined : 0.5} />
              <circle cx={fmt(x)} cy={fmt(y)} r="5" fill="#ff6b78" className={animated ? "em-blip" : ""} style={style} opacity={animated ? undefined : 0.9} />
            </g>
          );
        })}

      {/* Modalités en orbite */}
      <g className={animated ? "em-orbit" : ""}>
        {NODES.map((n) => {
          const [x, y] = polar(n.angle, 224);
          return (
            <g key={n.icon} transform={`translate(${fmt(x)} ${fmt(y)})`}>
              <g className={animated ? "em-counter" : ""}>
                <circle r="31" fill="#0b1338" stroke={`url(#${id}gold)`} strokeWidth="2.2" />
                <circle r="38" fill="none" stroke="#f2b84b" strokeOpacity="0.2" />
                <g
                  transform="translate(-14.4 -14.4) scale(1.2)"
                  fill="none"
                  stroke="#ffe3a3"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  {ICONS[n.icon]}
                </g>
              </g>
            </g>
          );
        })}
      </g>

      {/* Le bouclier */}
      <g filter={`url(#${id}shadow)`}>
        <path
          d="M300 186 L400 221 V306 C400 364 357 401 300 428 C243 401 200 364 200 306 V221 Z"
          fill={`url(#${id}navy)`}
          stroke={`url(#${id}gold)`}
          strokeWidth="5"
          strokeLinejoin="round"
        />
        <path
          d="M300 186 L400 221 V306 C400 364 357 401 300 428 C243 401 200 364 200 306 V221 Z"
          fill="none"
          stroke="#ffe3a3"
          strokeOpacity="0.32"
          strokeWidth="1.5"
          transform="translate(300 306) scale(0.84) translate(-300 -306)"
        />
      </g>
      <path
        className={animated ? "em-core" : ""}
        d="M300 244 L315 290 L361 305 L315 320 L300 366 L285 320 L239 305 L285 290 Z"
        fill={`url(#${id}gold)`}
      />
      <circle cx={CX} cy="305" r="8" fill="#0b1338" stroke="#ffe3a3" strokeWidth="2" />
    </svg>
  );
}
