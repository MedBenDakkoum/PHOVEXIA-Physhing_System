export default function SafeUrl({ value, className = "" }) {
  if (!value) return <span className="faint">—</span>;
  return (
    <span className={`safe-url ${className}`} title={value}>
      {value}
    </span>
  );
}
