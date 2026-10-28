import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { apiFetch, apiFetchBlob } from "../api/client";
import { ENDPOINTS, REASON_CODE } from "../api/constants";
import { ScanStatusBadge, VerdictBadge } from "../components/ui/Badges";

export default function ScanDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(true);
  const [screenshotUrl, setScreenshotUrl] = useState(null);
  const [reported, setReported] = useState(false);
  const [reportForm, setReportForm] = useState({ claimed_label: "phishing", comment: "" });
  const timerRef = useRef(null);
  const abortRef = useRef(null);
  const tabHiddenRef = useRef(false);

  // Visibility pause
  useEffect(() => {
    const onVis = () => { tabHiddenRef.current = document.hidden; };
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  // Load scan
  useEffect(() => {
    if (!id) { setError({ msg: "Identifiant manquant", code: "MISSING_ID" }); return; }
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();
    apiFetch(ENDPOINTS.scan(id)).then(r => {
      if (!r.ok) {
        if (r.status === 404) setError({ msg: "Scan introuvable — vérifiez l'identifiant UUID.", code: "NOT_FOUND" });
        else setError({ msg: r.error?.message || "Erreur chargement", code: r.error?.code || "ERROR" });
        setPolling(false);
        return;
      }
      setScan(r.data);
      const s = r.data?.status;
      if (["confirmed", "false_positive", "blocked", "failed", "detected"].includes(s)) setPolling(false);
      else setPolling(true);
    });
  }, [id]);

  // Poll with backoff
  useEffect(() => {
    if (!polling || !scan) return;
    let delay = 2000;
    const tick = () => {
      if (tabHiddenRef.current) { timerRef.current = setTimeout(tick, 2000); return; }
      apiFetch(ENDPOINTS.scan(id)).then(r => {
        if (r.ok && r.data) {
          setScan(r.data);
          const s = r.data.status;
          if (["confirmed", "false_positive", "blocked", "failed", "detected"].includes(s)) { setPolling(false); return; }
        }
        delay = Math.min(delay + 1000, 8000);
        timerRef.current = setTimeout(tick, delay);
      });
    };
    timerRef.current = setTimeout(tick, delay);
    return () => clearTimeout(timerRef.current);
  }, [polling, scan, id]);

  // Stop polling after 3 min with notice (simplified: after 6 iterations ~3 min)
  useEffect(() => {
    const limiter = setTimeout(() => { if (polling) setPolling(false); }, 180000);
    return () => clearTimeout(limiter);
  }, [polling]);

  // Screenshot blob with JWT, revoke on unmount
  useEffect(() => {
    if (!scan) return undefined;
    let active = true;
    let blobUrl = null;
    const ctrl = new AbortController();
    apiFetchBlob(ENDPOINTS.scanScreenshot(id), { signal: ctrl.signal })
      .then(async (r) => {
        if (!active || !r.ok) return;
        const b = await r.blob();
        blobUrl = URL.createObjectURL(b);
        setScreenshotUrl(blobUrl);
      })
      .catch(() => {});
    return () => {
      active = false;
      ctrl.abort();
      if (blobUrl) URL.revokeObjectURL(blobUrl);
    };
  }, [scan?.id, id]);

  // Report wrong verdict
  const handleReport = async (e) => {
    e.preventDefault();
    const r = await apiFetch(ENDPOINTS.scanReport(id), { method: "POST", body: JSON.stringify(reportForm) });
    if (!r.ok && r.status === 409) { setReported(true); return; }
    if (r.ok || r.data) { setReported(true); setScan(s => ({ ...s, has_report: true, report_status: "open" })); }
  };

  if (error) return <div role="alert" aria-live="assertive" style={{ padding: 24, color: "#ff6b78" }}>{error.msg}<br/><button onClick={() => nav("/scans")}>Retour</button></div>;
  if (!scan) return <div style={{ padding: 24 }}>Chargement…</div>;

  return (
    <div style={{ maxWidth: 900, margin: "0 auto", padding: 24 }}>
      <button onClick={() => nav(-1)}>← Retour</button>
      <h1>Scan <span style={{ fontFamily: "monospace" }}>{id}</span></h1>
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <VerdictBadge verdict={scan.verdict} />
        <ScanStatusBadge status={scan.status} />
        <span>Score : <strong>{typeof scan.score === "number" ? scan.score.toFixed(3) : scan.score}</strong></span>
      </div>
      <p><strong>URL :</strong> <span style={{ wordBreak: "break-all" }}>{scan.url}</span></p>
      {scan.partial && (
        <div role="alert" style={{ background: "#f2b84b22", padding: 12, borderRadius: 8, margin: "12px 0" }}>
          <strong>Résultat partiel — raison :</strong> {REASON_CODE[scan.reason_code] || scan.reason_code || "—"}
        </div>
      )}
      {scan.detection_source === "blocklist" && (
        <p aria-label="Source blocklist"><strong>Source :</strong> Blocklist (domaine bloqué immédiatement)</p>
      )}
      {scan.probabilities && (
        <div aria-label="Probabilités par modalité">
          <h3>Probabilités (modèle son sorties, non explication certifiée)</h3>
          {Object.entries(scan.probabilities).map(([k, v]) => (
            <div key={k} style={{ margin: 4 }}>
              <span style={{ textTransform: "capitalize", minWidth: 120, display: "inline-block" }}>{k}</span>
              <div style={{ height: 10, background: "#0a1130", borderRadius: 5, width: "100%", maxWidth: 400 }}>
                <div style={{ height: "100%", width: `${(v || 0) * 100}%`, background: "#f2b84b", borderRadius: 5 }} />
              </div>
              <span style={{ fontSize: 12 }}>{(v || 0).toFixed(3)}</span>
            </div>
          ))}
          <p style={{ fontSize: 12, color: "#7685b3" }}>Note honnête : ces barres sont les sorties du modèle, pas une explication certifiée du risque.</p>
        </div>
      )}
      {scan.signals && (
        <div>
          <h3>Signaux techniques</h3>
          <pre style={{ background: "#070c22", padding: 12, overflow: "auto" }}>{JSON.stringify(scan.signals, null, 2)}</pre>
        </div>
      )}
      {scan.final_url && <p><strong>URL finale :</strong> {scan.final_url}</p>}
      {screenshotUrl && (
        <figure style={{ margin: 12 }}>
          <img src={screenshotUrl} alt="Capture du site analysé" style={{ maxWidth: "100%", border: "1px solid #172254", borderRadius: 8 }} />
        </figure>
      )}
      {scan.verdict === "phishing" && (
        <div role="alert" aria-live="assertive" style={{ background: "#ff6b78", color: "#fff", padding: 12, borderRadius: 8, margin: "12px 0" }}>
          <strong>Attention — ne visitez pas ce site.</strong> Le verdict est Phishing.
        </div>
      )}
      <section aria-label="Signaler une erreur" style={{ marginTop: 24, padding: 12, background: "#111a40", borderRadius: 8 }}>
        <h3>Signaler une erreur (US31)</h3>
        {!scan.has_report && !reported ? (
          <form onSubmit={handleReport}>
            <label>Verdict supposé</label>
            <select value={reportForm.claimed_label} onChange={e => setReportForm({ ...reportForm, claimed_label: e.target.value })}>
              <option value="phishing">Phishing</option><option value="safe">Sûr</option>
            </select>
            <label>Commentaire</label>
            <textarea value={reportForm.comment} onChange={e => setReportForm({ ...reportForm, comment: e.target.value })} rows={3} style={{ width: "100%" }} />
            <button type="submit">Envoyer</button>
          </form>
        ) : (
          <p>Déjà signalé — décision : {scan.report_status || "en attente de revue"} (pas de nom d'analyste affiché).</p>
        )}
      </section>
      {polling && <p aria-live="polite">Mise à jour en cours… (arrêt automatique après 3 min)</p>}
    </div>
  );
}
