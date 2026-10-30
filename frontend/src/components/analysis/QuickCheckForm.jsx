import { useEffect, useState } from "react";
import { ArrowRight, Link2, ShieldAlert } from "lucide-react";
import { getQuickCheck, quickCheck } from "../../api/scans";
import {
  DETECTION_SOURCE,
  REASON_CODE,
  TERMINAL_SCAN_STATUSES,
  VERDICT,
} from "../../api/constants";
import Button from "../ui/Button";
import { TextField } from "../ui/Fields";
import { ScanStatusBadge, VerdictBadge } from "../ui/Badges";
import SafeUrl from "../ui/SafeUrl";

const isTerminal = (status) => TERMINAL_SCAN_STATUSES.includes(status);
const scoreText = (value) => (typeof value === "number" ? value.toFixed(3) : "—");

export default function QuickCheckForm() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);
  const [retryIn, setRetryIn] = useState(0);
  const [pollStopped, setPollStopped] = useState(false);

  useEffect(() => {
    if (retryIn <= 0) return undefined;
    const timer = setInterval(() => setRetryIn((value) => Math.max(0, value - 1)), 1000);
    return () => clearInterval(timer);
  }, [retryIn]);

  useEffect(() => {
    if (!result?.id || isTerminal(result.status)) return undefined;
    let cancelled = false;
    let timer = null;
    let delay = 2000;
    const limit = setTimeout(() => {
      if (!cancelled) {
        cancelled = true;
        clearTimeout(timer);
        setPollStopped(true);
      }
    }, 180000);

    const tick = async () => {
      try {
        const next = await getQuickCheck(result.id);
        if (cancelled) return;
        setResult((current) => ({ ...current, ...next }));
        if (isTerminal(next.status)) {
          clearTimeout(limit);
          return;
        }
      } catch (err) {
        if (cancelled) return;
        setError(err?.message || "Le suivi de l'analyse a échoué.");
        clearTimeout(limit);
        return;
      }
      delay = Math.min(delay + 1000, 8000);
      timer = setTimeout(tick, delay);
    };

    timer = setTimeout(tick, delay);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      clearTimeout(limit);
    };
    // Poll while the current quick check has not reached a terminal status.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result?.id]);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setPollStopped(false);
    setResult(null);
    if (retryIn > 0) return;
    const value = url.trim();
    if (!value) {
      setError("Saisissez une adresse URL à vérifier.");
      return;
    }
    setRunning(true);
    try {
      const created = await quickCheck(value);
      setResult(created);
    } catch (err) {
      if (err?.status === 429) {
        setRetryIn(err.retryAfter || 60);
        setError("Trop de vérifications depuis cette adresse. Patientez avant de réessayer.");
      } else {
        setError(err?.message || "Le service d'analyse est indisponible.");
      }
    } finally {
      setRunning(false);
    }
  };

  const terminal = result && isTerminal(result.status);
  const reason = result?.reason_code ? REASON_CODE[result.reason_code] || result.reason_code : null;

  return (
    <section className="card card-pad url-analysis" aria-labelledby="url-analysis-title">
      <div className="card-head">
        <div>
          <h2 id="url-analysis-title" className="card-title">Vérifier un lien sans compte</h2>
          <p className="card-sub">Analyse rapide et anonyme. Aucun compte n'est nécessaire.</p>
        </div>
        <span className="url-analysis-icon" aria-hidden="true"><Link2 size={20} /></span>
      </div>

      <form className="url-analysis-form" onSubmit={submit} noValidate data-testid="quick-check-form">
        <TextField
          label="URL à vérifier"
          type="url"
          inputMode="url"
          placeholder="https://exemple.com/page"
          value={url}
          onChange={(event) => {
            setUrl(event.target.value);
            setError("");
          }}
          error={error && !result ? error : ""}
          hint="L'adresse doit commencer par http:// ou https://."
          icon={Link2}
          autoComplete="url"
          name="url"
          data-testid="quick-check-url"
        />
        <Button
          variant="gold"
          type="submit"
          iconRight={ArrowRight}
          loading={running}
          disabled={retryIn > 0}
          data-testid="quick-check-submit"
        >
          Vérifier l'adresse
        </Button>
      </form>

      {retryIn > 0 && (
        <p className="alert alert-gold url-analysis-notice" role="status" data-testid="quick-check-countdown">
          <ShieldAlert size={18} />
          Limite anonyme atteinte. Nouvel essai possible dans {retryIn} s.
        </p>
      )}

      {result && (
        <div className="quick-result" data-testid="quick-check-result">
          <div className="quick-result-head">
            <div>
              <span className="field-label">Résultat</span>
              <div className="inline-actions" style={{ marginTop: 6 }}>
                <span data-testid="quick-check-verdict"><VerdictBadge verdict={result.verdict} /></span>
                <span data-testid="quick-check-status"><ScanStatusBadge status={result.status} /></span>
                <span className="muted">Probabilité de phishing (modèle) : <b className="tabular">{scoreText(result.score)}</b> <span style={{ fontSize: "0.8rem" }}>(0 = sûr, 1 = dangereux)</span></span>
              </div>
            </div>
            {result.detection_source && (
              <span className="badge badge-info">{DETECTION_SOURCE[result.detection_source] || result.detection_source}</span>
            )}
          </div>

          {result.verdict === "phishing" && (
            <div className="alert alert-error" role="alert">
              <ShieldAlert size={18} />
              <span>Ne visitez pas ce site. Le modèle le classe comme phishing.</span>
            </div>
          )}

          {result.partial && (
            <div className="alert alert-gold" role="status" data-testid="partial-banner">
              <ShieldAlert size={18} />
              <span>
                <strong>Résultat partiel — ce n'est pas un verdict.</strong>
                {reason ? ` Raison : ${reason}.` : ""} Certaines modalités n'ont pas pu être analysées.
              </span>
            </div>
          )}

          {(result.final_url || result.url) && (
            <div className="url-box">
              <small>Adresse analysée</small>
              <SafeUrl value={result.final_url || result.url} />
            </div>
          )}

          {terminal && !result.partial && (
            <p className="muted" style={{ margin: 0 }}>
              Verdict du modèle : {VERDICT[result.verdict]?.label || result.verdict || "non disponible"}.
            </p>
          )}

          {error && (
            <p className="alert alert-error" role="alert">
              <ShieldAlert size={18} />
              <span>{error}</span>
            </p>
          )}

          {!terminal && !pollStopped && (
            <p className="muted" role="status" aria-live="polite" style={{ margin: 0 }}>
              Analyse en cours… La page se met à jour automatiquement.
            </p>
          )}
          {pollStopped && !terminal && (
            <p className="alert alert-info" role="status">
              L'analyse prend plus de temps que prévu. Créez un compte pour suivre le résultat complet.
            </p>
          )}

          <p className="url-analysis-access">
            Résultat anonyme limité : les probabilités par modalité, les signaux détaillés et la capture
            restent visibles uniquement depuis un compte. Les barres, quand elles sont affichées, sont les
            sorties de chaque modèle, pas une explication certifiée.
          </p>
        </div>
      )}
    </section>
  );
}
