import { useId } from "react";

/** Écusson : bouclier d'or et étoile à quatre branches. */
export default function Crest({ size = 40, className = "" }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      className={className}
      role="img"
      aria-label="Phishing Multimodal"
      style={{ flex: "none" }}
    >
      <defs>
        <linearGradient id={`${id}g`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#FFDC8F" />
          <stop offset="1" stopColor="#D8921C" />
        </linearGradient>
        <linearGradient id={`${id}b`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#1B2770" />
          <stop offset="1" stopColor="#0B1233" />
        </linearGradient>
      </defs>
      <path
        d="M32 5 52 12.5V31c0 13-8.5 21.5-20 28C20.5 52.5 12 44 12 31V12.5z"
        fill={`url(#${id}b)`}
        stroke={`url(#${id}g)`}
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <path d="M32 19l4.8 9.2L46 32l-9.2 2.8L32 44l-4.8-9.2L18 32l9.2-2.8z" fill={`url(#${id}g)`} />
    </svg>
  );
}
