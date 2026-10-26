import { useState, useEffect, useRef } from "react";
import { apiFetch } from "../api/client";
import { ENDPOINTS, VERDICT, SCAN_STATUS } from "../api/constants";

export default function QuickCheck() {
  const [url, setUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [res, setRes] = useState(null);
  const [polling, setPolling] = useState(false);
  const timer = useRef(null);
  const [countdown, setCountdown] = useState(0);

  useEffect(() => {
    if (polling && res && !res.status) {
      timer.current = setInterval(() => setCountdown(c => Math.max(c - 1, 0)), 1000);
      const tick = () => {
        apiFetch(ENDPOINTS.quickCheckDetail(res.id)).then(r => {
          if (r.ok && r.data) { setRes(r.data); if (["detected","failed","blocked","confirmed","false_positive"].includes(r.data.status)) { setPolling(false); clearInterval(timer.current); } }
        });
      };
      const pollingTimer = setInterval(tick, 3000);
      return () => { clearInterval(pollingTimer); clearInterval(timer.current); };
    }
  }, [polling, res]);

  const submit = async (e) => {
    e.preventDefault();
    setRunning(true); setRes(null); setPolling(false); setCountdown(0); clearInterval(timer.current);
    const r = await apiFetch(ENDPOINTS.quickCheck, { method: "POST", body: JSON.stringify({ url }) });
    setRunning(false);
    if (r.status === 429) { setCountdown(r.retryAfter || 60); return; }
    if (r.ok && r.data?.id) { setRes(r.data); if (r.data.status === "detected") { setPolling(false); } else { setPolling(true); } }
    else { setRes({ error: r.error?.message || "Erreur" }); }
  };

  return (
    <section aria-label="Vérification rapide anonyme">
      <h2>Vérifier un lien (anonyme)</h2>
      <form onSubmit={submit}>
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" required style={{ width: "100%", padding: 8 }} />
        <button type="submit" disabled={running}>Vérifier</button>
      </form>
      {countdown > 0 && <p>Quota atteint — réessayez dans {countdown} s.</p>}
      {res && !res.error && (
        <div>
          <p>Verdict : <strong>{VERDICT[res.verdict]?.label || res.verdict}</strong> — Score : {typeof res.score === "number" ? res.score.toFixed(3) : res.score}</p>
          {res.partial && <p>Partiel : {res.partial} — raison : {res.reason_code || "—"}</p>}
          <p style={{ fontSize: 12, color: "#7685b3" }}>Résultat limité (sans image ni signaux détaillés). Créez un compte pour une analyse complète.</p>
        </div>
      )}
      {res && res.error && <p style={{ color: "#ff6b78" }}>{res.error}</p>}
    </section>
  );
}
