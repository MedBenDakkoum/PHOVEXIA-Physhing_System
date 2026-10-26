import { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { apiFetch } from "../api/client";
import { ENDPOINTS, SCAN_STATUS, VERDICT } from "../api/constants";

export default function ScansHistory() {
  const [search, setSearch] = useSearchParams();
  const [items, setItems] = useState([]);
  const [quota, setQuota] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    apiFetch(ENDPOINTS.scans + "quota/").then(r => { if (r.ok && r.data) setQuota(r.data); });
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true); setError(null);
    const params = new URLSearchParams();
    for (const [k, v] of search.entries()) if (v) params.set(k, v);
    apiFetch(ENDPOINTS.scans + "?" + params.toString(), { signal: ctrl.signal }).then(r => {
      setLoading(false);
      if (!r.ok) setError({ msg: r.error?.message || "Erreur", code: r.error?.code || "ERROR" });
      else setItems(r.data?.results || []);
    }).catch(() => setLoading(false));
    return () => ctrl.abort();
  }, [search]);

  const filters = [
    { key: "q", label: "Recherche" },
    { key: "verdict", label: "Verdict", multi: true, opts: VERDICT_VALUES },
    { key: "status", label: "Statut", multi: true, opts: SCAN_STATUS_VALUES },
    { key: "created_after", label: "Après (date)" },
    { key: "created_before", label: "Avant (date)" },
    { key: "ordering", label: "Tri (created_at / -created_at)" },
  ];

  return (
    <div style={{ maxWidth: 960, margin: "0 auto", padding: 24 }}>
      <h1>Historique des scans</h1>
      {quota && <p>Quota : <strong>{quota.remaining}</strong> restants — réinitialisation {quota.reset_at ? new Date(quota.reset_at).toLocaleString("fr-FR") : "—"}</p>}
      <form onSubmit={e => { e.preventDefault(); }}> 
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {filters.map(f => (
            <div key={f.key}>
              <label>{f.label}</label>
              {f.opts ? (
                <select multiple value={search.getAll(f.key)} onChange={e => {
                  const vals = Array.from(e.target.selectedOptions, o => o.value);
                  const ns = new URLSearchParams(search); ns.delete(f.key); vals.forEach(v => ns.append(f.key, v)); setSearch(ns);
                }}>
                  {f.opts.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input type={f.key.includes("date") ? "date" : "text"} defaultValue={search.get(f.key) || ""} onBlur={e => {
                  const ns = new URLSearchParams(search); if (e.target.value) ns.set(f.key, e.target.value); else ns.delete(f.key); setSearch(ns);
                }} />
              )}
            </div>
          ))}
        </div>
      </form>
      {loading && <p>Chargement…</p>}
      {error && <div role="alert">{error.msg}</div>}
      {!loading && !error && items.length === 0 && <p>Aucun résultat — essayez d'autres filtres.</p>}
      <ul style={{ listStyle: "none", padding: 0 }}>
        {items.map(s => (
          <li key={s.id} style={{ margin: 8, padding: 12, background: "#111a40", borderRadius: 8 }}>
            <Link to={"/scans/" + s.id} style={{ color: "#f2b84b", textDecoration: "none", fontWeight: 600 }}>{s.url}</Link>
            <span style={{ marginLeft: 8 }}><strong>{VERDICT[s.verdict]?.label || s.verdict}</strong> — {s.status}</span>
            <span style={{ marginLeft: 8, fontSize: 12, color: "#7685b3" }}>{new Date(s.created_at).toLocaleString("fr-FR")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
