import { ChevronLeft, ChevronRight } from "lucide-react";
import { formatNumber } from "../../utils/format";

function pageList(page, total) {
  const set = new Set([1, total, page, page - 1, page + 1]);
  const pages = [...set].filter((p) => p >= 1 && p <= total).sort((a, b) => a - b);
  const out = [];
  pages.forEach((p, i) => {
    if (i > 0 && p - pages[i - 1] > 1) out.push("gap-" + p);
    out.push(p);
  });
  return out;
}

export default function Pagination({ page, pageSize, total, onPage, children }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="pager">
      <div className="count-line">
        {children}
        <span>
          <b>
            {formatNumber(from)}–{formatNumber(to)}
          </b>{" "}
          sur <b>{formatNumber(total)}</b>
        </span>
      </div>
      <nav className="pager-nav" aria-label="Pagination">
        <button onClick={() => onPage(page - 1)} disabled={page <= 1} aria-label="Page précédente">
          <ChevronLeft size={18} />
        </button>
        {pageList(page, totalPages).map((p) =>
          typeof p === "string" ? (
            <span key={p} className="pager-gap" aria-hidden="true">
              …
            </span>
          ) : (
            <button key={p} onClick={() => onPage(p)} aria-current={p === page ? "page" : undefined} aria-label={`Page ${p}`}>
              {p}
            </button>
          )
        )}
        <button onClick={() => onPage(page + 1)} disabled={page >= totalPages} aria-label="Page suivante">
          <ChevronRight size={18} />
        </button>
      </nav>
    </div>
  );
}
