import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Camera,
  Clock,
  Gauge,
  History,
  Link2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { getScan, getScanScreenshot, reportScan } from "../api/scans";
import {
  CLAIMED_LABEL,
  MODALITY_LABEL,
  PROBABILITY_MODALITIES,
  REASON_CODE,
  TERMINAL_SCAN_STATUSES,
} from "../api/constants";
import {
  DetectionBadge,
  ReportBadge,
  ScanStatusBadge,
  VerdictBadge,
} from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { SelectField, TextAreaField } from "../components/ui/Fields";
import PageHeader from "../components/ui/PageHeader";
import SafeUrl from "../components/ui/SafeUrl";
import { ErrorState, Skeleton } from "../components/ui/States";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useToast } from "../context/ToastContext";
import { formatDateTime, relativeTime } from "../utils/format";

const isTerminal = (status) => TERMINAL_SCAN_STATUSES.includes(status);
const scoreText = (value) => (typeof value === "number" ? value.toFixed(3) : "—");
const signalValue = (value) => {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Oui" : "Non";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
};
const humanKey = (key) => key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

const STEP_INDEX = {
  submitted: 0,
  analyzing: 1,
  detected: 2,
  failed: 2,
  under_review: 3,
  confirmed: 3,
  false_positive: 3,
  blocked: 3,
};

function StatusTimeline({ status }) {
  const current = STEP_INDEX[status] ?? 0;
  const steps = [
    { key: "submitted", label: "Soumis" },
    { key: "analyzing", label: "Analyse" },
    { key: "verdict", label: "Verdict automatique" },
    { key: "review", label: "Revue ou décision" },
  ];
  return (
    <ol className="scan-timeline" aria-label="Progression du scan" data-testid="scan-timeline">
      {steps.map((step, index) => {
        const state = index < current ? "done" : index === current ? "current" : "pending";
        return (
          <li key={step.key} className={`scan-step is-${state} ${status === "failed" && index === 2 ? "is-error" : ""}`}>
            <span className="scan-step-dot" aria-hidden="true">{index + 1}</span>
            <span>{step.label}</span>
          </li>
        );
      })}
    </ol>
  );
}

function ProbabilityBars({ probabilities }) {
  const entries = useMemo(() => {
    const known = PROBABILITY_MODALITIES.map((key) => [key, probabilities?.[key]]);
    const extra = Object.entries(probabilities || {}).filter(([key]) => !PROBABILITY_MODALITIES.includes(key));
    return [...known, ...extra];
  }, [probabilities]);
  const available = entries.filter(([, value]) => typeof value === "number");

  return (
    <section className="card card-pad" aria-labelledby="probabilities-title" data-testid="probability-bars">
      <div className="card-head">
        <div>
          <h2 id="probabilities-title" className="card-title">Probabilités par modalité</h2>
          <p className="card-sub">
            <em>les barres sont les sorties de chaque modèle, pas une explication certifiée</em>.
          </p>
        </div>
      </div>
      {available.length === 0 ? (
        <p className="muted" style={{ margin: 0 }}>Aucune probabilité disponible pour ce scan.</p>
      ) : (
        <div className="prob-list">
          {entries.map(([key, value]) => (
            <div className="prob-row" key={key} data-modality={key}>
              <div className="prob-head">
                <span>{MODALITY_LABEL[key] || humanKey(key)}</span>
                <b>{typeof value === "number" ? value.toFixed(3) : "—"}</b>
              </div>
              <div className="prob-track" aria-hidden="true">
                <div
                  className="prob-fill"
                  style={{ width: `${typeof value === "number" ? Math.max(0, Math.min(1, value)) * 100 : 0}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default function ScanDetail() {
  useDocumentTitle("Détail du scan");
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pollStopped, setPollStopped] = useState(false);
  const [screenshotUrl, setScreenshotUrl] = useState(null);
  const [screenshotState, setScreenshotState] = useState("idle");
  const [claimedLabel, setClaimedLabel] = useState("safe");
  const [comment, setComment] = useState("");
  const [reportError, setReportError] = useState("");
  const [reporting, setReporting] = useState(false);

  useEffect(() => {
    let active = true;
    let timer = null;
    let delay = 2000;
    let terminal = false;
    const limit = setTimeout(() => {
      if (!active || terminal) return;
      active = false;
      clearTimeout(timer);
      setPollStopped(true);
    }, 180000);

    const load = async () => {
      try {
        const data = await getScan(id);
        if (!active) return;
        setScan(data);
        setLoading(false);
        setError(null);
        if (isTerminal(data.status)) {
          terminal = true;
          clearTimeout(limit);
          return;
        }
        delay = Math.min(delay + 1000, 8000);
        timer = setTimeout(load, delay);
      } catch (err) {
        if (!active) return;
        setLoading(false);
        setError(err);
        clearTimeout(limit);
      }
    };

    setLoading(true);
    setError(null);
    setPollStopped(false);
    setScan(null);
    load();

    return () => {
      active = false;
      clearTimeout(timer);
      clearTimeout(limit);
    };
  }, [id]);

  useEffect(() => {
    if (!scan?.id || !isTerminal(scan.status)) return undefined;
    // US20: never call the screenshot endpoint when the API says there is no
    // file (failed/partial scan) - that would only produce a 404 in console.
    if (!scan.has_screenshot) {
      setScreenshotState("missing");
      setScreenshotUrl(null);
      return undefined;
    }
    let active = true;
    let objectUrl = null;
    const controller = new AbortController();
    setScreenshotState("loading");
    setScreenshotUrl(null);
    getScanScreenshot(scan.id, controller.signal)
      .then((blob) => {
        if (!active) return;
        if (!blob) {
          setScreenshotState("missing");
          return;
        }
        objectUrl = URL.createObjectURL(blob);
        setScreenshotUrl(objectUrl);
        setScreenshotState("ready");
      })
      .catch((err) => {
        if (!active || err?.name === "AbortError") return;
        setScreenshotState("error");
      });
    return () => {
      active = false;
      controller.abort();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [scan?.id, scan?.status, scan?.has_screenshot]);

  const submitReport = async (event) => {
    event.preventDefault();
    setReportError("");
    setReporting(true);
    try {
      await reportScan(scan.id, { claimed_label: claimedLabel, comment });
      setScan((current) => ({
        ...current,
        has_report: true,
        report_status: "open",
        status: current.status === "detected" ? "under_review" : current.status,
      }));
      toast.success("Signalement envoyé", "Un analyste examinera le verdict de ce scan.");
    } catch (err) {
      if (err?.status === 409) {
        setScan((current) => ({ ...current, has_report: true, report_status: "open" }));
        setReportError("Ce scan a déjà été signalé. Un seul signalement est autorisé par scan.");
      } else {
        setReportError(err?.message || "Le signalement n'a pas pu être envoyé.");
      }
    } finally {
      setReporting(false);
    }
  };

  if (error) {
    return (
      <>
        <PageHeader title="Détail du scan" description="Le résultat demandé n'est pas accessible." />
        <ErrorState
          error={error}
          title={error.status === 404 ? "Scan introuvable" : "Impossible de charger le scan"}
        />
        <div className="inline-actions" style={{ marginTop: 14 }}>
          <Button variant="ghost" to="/scans" icon={History}>Retour à l'historique</Button>
        </div>
      </>
    );
  }

  if (loading && !scan) {
    return (
      <>
        <PageHeader title="Détail du scan" description="Chargement du résultat…" />
        <section className="card card-pad">
          <Skeleton h={28} w="48%" />
          <Skeleton h={16} w="78%" style={{ marginTop: 12 }} />
          <Skeleton h={220} r={14} style={{ marginTop: 24 }} />
        </section>
      </>
    );
  }

  if (!scan) return null;

  const reason = scan.reason_code ? REASON_CODE[scan.reason_code] || scan.reason_code : null;
  const signals = Object.entries(scan.signals || {});
  const canReport =
    !scan.has_report && ["detected", "under_review"].includes(scan.status) && scan.verdict != null;

  return (
    <>
      <PageHeader
        title="Détail du scan"
        description={`${scan.domain || scan.url} · reçu ${relativeTime(scan.created_at)}`}
        actions={
          <div className="toolbar-actions">
            <Button variant="ghost" to="/scans" icon={ArrowLeft}>
              Retour à l'historique
            </Button>
            <Button variant="gold" to="/scans/new" icon={Link2}>
              Nouveau scan
            </Button>
          </div>
        }
      />

      <section className="card review-summary scan-summary" aria-label="Résumé du scan">
        <div>
          <span className="field-label">Verdict</span>
          <div style={{ marginTop: 5 }} data-testid="scan-verdict"><VerdictBadge verdict={scan.verdict} /></div>
        </div>
        <div>
          <span className="field-label">Statut</span>
          <div style={{ marginTop: 5 }} data-testid="scan-status"><ScanStatusBadge status={scan.status} /></div>
        </div>
        <div>
          <span className="field-label">Score</span>
          <div style={{ marginTop: 5 }}><strong className="tabular" data-testid="scan-score">{scoreText(scan.score)}</strong></div>
        </div>
        <div>
          <span className="field-label">Source</span>
          <div style={{ marginTop: 5 }}><DetectionBadge source={scan.detection_source} /></div>
        </div>
        <div>
          <span className="field-label">Signalement</span>
          <div style={{ marginTop: 5 }}><ReportBadge reported={scan.has_report} /></div>
        </div>
        <div>
          <span className="field-label">Modèle</span>
          <div style={{ marginTop: 5 }} className="mono truncate" title={scan.model_version || ""}>
            {scan.model_version || <span className="faint">—</span>}
          </div>
        </div>
      </section>

      {scan.verdict === "phishing" && (
        <div className="alert alert-error" role="alert" style={{ marginTop: 18 }}>
          <ShieldAlert size={18} />
          <span><strong>Ne visitez pas ce site.</strong> Le verdict est Phishing.</span>
        </div>
      )}

      {scan.partial && (
        <div className="alert alert-gold" role="status" style={{ marginTop: 18 }} data-testid="partial-banner">
          <ShieldAlert size={18} />
          <span>
            <strong>Résultat partiel — ce n'est pas un verdict.</strong>
            {reason ? ` Raison : ${reason}.` : ""} Certaines modalités n'ont pas pu être analysées.
          </span>
        </div>
      )}

      {scan.status === "failed" && (
        <>
          <div className="alert alert-error" role="alert" style={{ marginTop: 18 }} data-testid="scan-failed-banner">
            <XCircle size={18} />
            <span>
              <strong>L'analyse a échoué.</strong>
              {reason ? ` Raison : ${reason}.` : ""} Vous pouvez relancer cette adresse.
            </span>
          </div>
          <div className="inline-actions" style={{ marginTop: 12 }}>
            <Button
              variant="gold"
              to={`/scans/new?url=${encodeURIComponent(scan.url)}`}
              icon={RefreshCw}
              data-testid="scan-relaunch"
            >
              Relancer cette adresse
            </Button>
            <span className="muted">Cette relance crée un nouveau scan et décompte 1 de votre quota.</span>
          </div>
        </>
      )}

      <div className="scan-detail-grid">
        <div className="scan-main">
          <section className="card card-pad" aria-labelledby="timeline-title">
            <div className="card-head">
              <div>
                <h2 id="timeline-title" className="card-title">Progression</h2>
                <p className="card-sub">Le suivi s'arrête dès que le scan atteint un statut final.</p>
              </div>
              {!isTerminal(scan.status) && !pollStopped && (
                <span className="badge badge-info" role="status">Mise à jour automatique</span>
              )}
            </div>
            <StatusTimeline status={scan.status} />
            {pollStopped && !isTerminal(scan.status) && (
              <p className="alert alert-info" role="status" style={{ marginTop: 16 }}>
                Le suivi automatique s'est arrêté après 3 minutes. Rechargez la page pour vérifier à nouveau.
              </p>
            )}
          </section>

          <section className="card card-pad" aria-labelledby="urls-title">
            <div className="card-head">
              <div>
                <h2 id="urls-title" className="card-title">Adresse analysée</h2>
                <p className="card-sub">Le site n'est jamais ouvert dans votre navigateur.</p>
              </div>
            </div>
            <div className="stack-sm">
              <div className="url-box">
                <small>URL soumise</small>
                <SafeUrl value={scan.url} />
              </div>
              {scan.final_url && scan.final_url !== scan.url && (
                <div className="url-box">
                  <small>URL finale après redirections</small>
                  <SafeUrl value={scan.final_url} />
                </div>
              )}
              {scan.detection_source === "blocklist" && (
                <p className="alert alert-gold" role="status" style={{ margin: 0 }}>
                  <ShieldCheck size={18} />
                  <span>Domaine déjà bloqué : le verdict a été appliqué immédiatement, sans exécuter le modèle.</span>
                </p>
              )}
            </div>
          </section>

          <section className="card card-pad" aria-labelledby="screenshot-title">
            <div className="card-head">
              <div>
                <h2 id="screenshot-title" className="card-title">Capture isolée</h2>
                <p className="card-sub">Image produite par le navigateur du bac à sable, sans accès à votre réseau.</p>
              </div>
              <Camera size={20} className="faint" aria-hidden="true" />
            </div>
            {screenshotState === "idle" && !isTerminal(scan.status) && (
              <p className="alert alert-info" role="status">
                <Camera size={18} />
                <span>La capture sera disponible dès que l'analyse sera terminée.</span>
              </p>
            )}
            {screenshotState === "loading" && <Skeleton h={240} r={14} />}
            {screenshotState === "ready" && screenshotUrl && (
              <figure className="screenshot-frame">
                <img src={screenshotUrl} alt="Capture isolée du site analysé" data-testid="scan-screenshot" />
                <figcaption>Capture du site au moment de l'analyse.</figcaption>
              </figure>
            )}
            {screenshotState === "missing" && (
              <p className="alert alert-info" role="status">
                <Camera size={18} />
                <span>Aucune capture n'est disponible pour ce scan.</span>
              </p>
            )}
            {screenshotState === "error" && (
              <p className="alert alert-error" role="alert">
                <XCircle size={18} />
                <span>La capture n'a pas pu être chargée.</span>
              </p>
            )}
          </section>

          <ProbabilityBars probabilities={scan.probabilities} />

          <section className="card card-pad" aria-labelledby="signals-title">
            <div className="card-head">
              <div>
                <h2 id="signals-title" className="card-title">Signaux techniques</h2>
                <p className="card-sub">Indices collectés pendant l'analyse, à interpréter avec le verdict.</p>
              </div>
            </div>
            {signals.length === 0 ? (
              <p className="muted" style={{ margin: 0 }}>Aucun signal technique disponible.</p>
            ) : (
              <dl className="kv">
                {signals.map(([key, value]) => (
                  <div key={key} style={{ display: "contents" }}>
                    <dt>{humanKey(key)}</dt>
                    <dd className="mono" style={{ overflowWrap: "anywhere" }}>{signalValue(value)}</dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
        </div>

        <aside className="scan-side">
          <section className="card card-pad" aria-labelledby="meta-title">
            <div className="card-head">
              <div>
                <h2 id="meta-title" className="card-title">Informations</h2>
                <p className="card-sub">Traçabilité du résultat.</p>
              </div>
            </div>
            <dl className="kv">
              <dt><Clock size={14} aria-hidden="true" /> Créé</dt>
              <dd>{formatDateTime(scan.created_at)}</dd>
              <dt><Clock size={14} aria-hidden="true" /> Terminé</dt>
              <dd>{scan.finished_at ? formatDateTime(scan.finished_at) : <span className="faint">—</span>}</dd>
              <dt><Gauge size={14} aria-hidden="true" /> Score</dt>
              <dd className="tabular">{scoreText(scan.score)}</dd>
            </dl>
          </section>

          <section className="card card-pad" aria-labelledby="report-title" data-testid="report-section">
            <div className="card-head">
              <div>
                <h2 id="report-title" className="card-title">Signaler une erreur</h2>
                <p className="card-sub">Un signalement est définitif et sera examiné par un analyste.</p>
              </div>
            </div>
            {scan.has_report ? (
              <div className="alert alert-info" role="status">
                <ShieldCheck size={18} />
                <span>
                  Signalement déjà enregistré{scan.report_status === "resolved" ? " et résolu" : ""}.
                  Un seul signalement est autorisé par scan.
                </span>
              </div>
            ) : canReport ? (
              <form onSubmit={submitReport} className="stack-sm">
                <SelectField
                  label="Verdict attendu"
                  value={claimedLabel}
                  onChange={(event) => setClaimedLabel(event.target.value)}
                  data-testid="report-claimed-label"
                >
                  {Object.entries(CLAIMED_LABEL).map(([value, label]) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </SelectField>
                <TextAreaField
                  label="Commentaire (optionnel)"
                  rows={3}
                  maxLength={1000}
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  data-testid="report-comment"
                />
                {reportError && (
                  <p className="alert alert-error" role="alert" data-testid="report-error">{reportError}</p>
                )}
                <Button variant="ghost" type="submit" loading={reporting} data-testid="report-submit">
                  Envoyer le signalement
                </Button>
              </form>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                {isTerminal(scan.status)
                  ? "Ce scan n'est plus signalable dans son état actuel."
                  : "Le signalement sera disponible une fois le verdict rendu."}
              </p>
            )}
            {reportError && scan.has_report && (
              <p className="alert alert-error" role="alert" style={{ marginTop: 12 }}>{reportError}</p>
            )}
          </section>
        </aside>
      </div>
    </>
  );
}
