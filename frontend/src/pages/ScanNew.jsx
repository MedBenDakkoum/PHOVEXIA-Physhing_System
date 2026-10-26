import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiFetch } from "../api/client";
import { ENDPOINTS, SCAN_STATUS_VALUES } from "../api/constants";

function validateUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, msg: "Seuls http/https sont autorisés" };
    if (url.length > 2048) return { ok: false, msg: "URL trop longue (>2048)" };
    if (u.username || u.password) return { ok: false, msg: "Ne pas inclure d'identifiants" };
    return { ok: true };
  } catch {
    return { ok: false, msg: "URL invalide" };
  }
}

export default function ScanNew() {
  const [url, setUrl] = useState("");
  const [err, setErr] = useState(null);
  const [quota, setQuota] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const nav = useNavigate();

  // Load quota once
  useState(() => {
    apiFetch(ENDPOINTS.scans + "quota/").then(r => { if (r.ok && r.data) setQuota(r.data); });
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErr(null);
    const v = validateUrl(url);
    if (!v.ok) { setErr({ msg: v.msg, code: "INVALID_URL" }); return; }
    if (quota && quota.remaining <= 0) { setErr({ msg: "Quota épuisé — réessayez à " + quota.reset_at, code: "QUOTA_ZERO" }); return; }
    setSubmitting(true);
    const r = await apiFetch(ENDPOINTS.scans, { method: "POST", body: JSON.stringify({ url }) });
    setSubmitting(false);
    if (!r.ok) {
      if (r.status === 400) {
        const m = r.data?.code === "forbidden_address" ? "Adresse interdite (privée/loopback)" : r.data?.detail || "Requête invalide";
        setErr({ msg: m, code: r.data?.code || "BAD_REQUEST" });
      } else if (r.status === 429) {
        setErr({ msg: "Quota dépassé — attendez " + (r.retryAfter || 60) + "s", code: "TOO_MANY_REQUESTS", retryAfter: r.retryAfter });
      } else {
        setErr({ msg: r.error?.message || "Erreur", code: r.error?.code || "ERROR" });
      }
      return;
    }
    if (r.ok && r.data?.id) nav("/scans/" + r.data.id);
  };

  return (
    <div style={{ maxWidth: 640, margin: "0 auto", padding: 24 }}>
      <h1>Nouveau scan</h1>
      <form onSubmit={handleSubmit} aria-label="Formulaire de soumission d'URL">
        <label htmlFor="url">URL à analyser <span aria-label="requis">*</span></label>
        <input id="url" type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" required aria-required="true" style={{ width: "100%", padding: 8 }} />
        {quota && (
          <p>Quota restant : <strong>{quota.remaining}</strong> — réinitialisation : {quota.reset_at ? new Date(quota.reset_at).toLocaleString("fr-FR") : "—"}</p>
        )}
        <button type="submit" disabled={submitting || (quota && quota.remaining <= 0)} aria-disabled={submitting || (quota && quota.remaining <= 0)}>
          {submitting ? "Envoi…" : quota && quota.remaining <= 0 ? "Quota épuisé" : "Analyser"}
        </button>
      </form>
      {err && <div role="alert" aria-live="assertive" style={{ color: "#ff6b78", marginTop: 12 }}>{err.msg}</div>}
      <p style={{ fontSize: 12, color: "#7685b3" }}>Validation client uniquement ; le serveur vérifie toujours SSRF, format et quota.</p>
    </div>
  );
}
