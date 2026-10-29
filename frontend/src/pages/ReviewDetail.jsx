import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Camera,
  CheckCircle2,
  Gavel,
  MessageSquarePlus,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { addReviewNote, decideReview, getReview, rescanReview } from "../api/review";
import { getScan, getScanScreenshot } from "../api/scans";
import { CLAIMED_LABEL, DECISION, DECISION_VALUES, MODE, REASON_CODE, REPORT_STATUS } from "../api/constants";
import {
  DetectionBadge,
  ReportBadge,
  ScanStatusBadge,
  VerdictBadge,
} from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { Checkbox, Segmented, TextAreaField } from "../components/ui/Fields";
import { ConfirmDialog } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import SafeUrl from "../components/ui/SafeUrl";
import { ErrorState, Skeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useToast } from "../context/ToastContext";
import { formatDateTime, relativeTime } from "../utils/format";

const MODALITY_LABEL = {
  url: "URL",
  page_text: "Texte de la page",
  text: "Texte",
  screenshot: "Capture",
  metadata: "Métadonnées",
  signals: "Signaux",
  fusion: "Fusion",
};

const scoreText = (value) => (typeof value === "number" ? value.toFixed(3) : "—");

const signalValue = (value) => {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Oui" : "Non";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
};

const humanKey = (key) =>
  key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

function Stat({ label, children }) {
  return (
    <div>
      <span className="field-label">{label}</span>
      <div style={{ marginTop: 5 }}>{children}</div>
    </div>
  );
}

function DecisionSummary({ review }) {
  if (review.status === "under_review") {
    return <p className="muted">Aucune décision enregistrée pour le moment.</p>;
  }
  const confirmed = review.status === "confirmed" || review.status === "blocked";
  const blocked = review.status === "blocked";
  return (
    <div className="stack-sm">
      <div className={`alert ${confirmed ? "alert-error" : "alert-success"}`} role="status">
        {confirmed ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}
        <span>
          {confirmed
            ? blocked
              ? "Phishing confirmé et domaine ajouté à la blocklist."
              : "Phishing confirmé par un analyste."
            : "Faux positif confirmé : le site n'est pas considéré comme malveillant."}
        </span>
      </div>
      <dl className="kv">
        <dt>Analyste</dt>
        <dd>{review.reviewed_by_email || "—"}</dd>
        <dt>Date</dt>
        <dd>{formatDateTime(review.reviewed_at)}</dd>
        <dt>Commentaire</dt>
        <dd>{review.review_comment || <span className="faint">Aucun commentaire</span>}</dd>
      </dl>
    </div>
  );
}

export default function ReviewDetail() {
  useDocumentTitle("Examen du cas");
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();

  const [decision, setDecision] = useState("confirm_phishing");
  const [comment, setComment] = useState("");
  const [addToBlocklist, setAddToBlocklist] = useState(false);
  const [decisionError, setDecisionError] = useState("");
  const [confirmDecision, setConfirmDecision] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const [noteText, setNoteText] = useState("");
  const [noteError, setNoteError] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [rescanOpen, setRescanOpen] = useState(false);
  const [rescuing, setRescuing] = useState(false);
  const [screenshotUrl, setScreenshotUrl] = useState(null);
  const [screenshotState, setScreenshotState] = useState("loading");

  const { data, error, loading, reload } = useAsync(
    async (signal) => {
      const [review, scan] = await Promise.all([getReview(id, signal), getScan(id, signal)]);
      return { review, scan };
    },
    [id]
  );

  const review = data?.review;
  const scan = data?.scan;
  const canDecide = review?.status === "under_review";

  useEffect(() => {
    if (review?.status !== "under_review") return;
    setDecision("confirm_phishing");
    setComment("");
    setAddToBlocklist(false);
    setDecisionError("");
  }, [review?.id, review?.status]);

  useEffect(() => {
    if (!id || !review) return undefined;
    if (!scan?.has_screenshot) {
      setScreenshotState("missing");
      setScreenshotUrl(null);
      return undefined;
    }
    let active = true;
    let objectUrl = null;
    const controller = new AbortController();
    setScreenshotState("loading");
    setScreenshotUrl(null);
    getScanScreenshot(id, controller.signal)
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
  }, [id, review, scan?.has_screenshot]);

  const notes = useMemo(
    () => [...(review?.notes || [])].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)),
    [review?.notes]
  );
  const probabilities = Object.entries(scan?.probabilities || {}).filter(([, value]) => typeof value === "number");
  const signals = Object.entries(scan?.signals || {});

  const changeDecision = (value) => {
    setDecision(value);
    if (value !== "confirm_phishing") setAddToBlocklist(false);
  };

  const submitDecision = async () => {
    setDeciding(true);
    setDecisionError("");
    try {
      await decideReview(id, {
        decision,
        comment: comment.trim(),
        add_to_blocklist: decision === "confirm_phishing" && addToBlocklist,
      });
      setConfirmDecision(false);
      toast.success("Décision enregistrée", DECISION[decision] || decision);
      reload();
    } catch (err) {
      setConfirmDecision(false);
      setDecisionError(
        err?.status === 409
          ? "Ce cas a déjà été traité ou n'est plus en attente de revue."
          : err.message
      );
      if (err?.status === 409) reload();
    } finally {
      setDeciding(false);
    }
  };

  const submitNote = async (event) => {
    event.preventDefault();
    const text = noteText.trim();
    if (!text) return;
    setSavingNote(true);
    setNoteError("");
    try {
      await addReviewNote(id, text);
      setNoteText("");
      toast.success("Note ajoutée", "Elle est visible par les analystes et administrateurs.");
      reload();
    } catch (err) {
      setNoteError(err.message);
    } finally {
      setSavingNote(false);
    }
  };

  const runRescan = async () => {
    setRescuing(true);
    try {
      const created = await rescanReview(id);
      setRescanOpen(false);
      toast.success("Nouveau scan lancé", "Suivez son avancement sur la page du scan.");
      navigate(`/scans/${created.id}`);
    } catch (err) {
      setRescanOpen(false);
      toast.error(
        "Rescan impossible",
        err?.status === 429
          ? "Votre quota quotidien de scans est atteint. Réessayez après la réinitialisation."
          : err.message
      );
    } finally {
      setRescuing(false);
    }
  };

  if (error) {
    return (
      <>
        <PageHeader title="Examen du cas" description="Le cas demandé est introuvable ou inaccessible." />
        <section className="card">
          <ErrorState error={error} onRetry={reload} />
        </section>
      </>
    );
  }

  if (loading && !data) {
    return (
      <>
        <PageHeader title="Examen du cas" description="Chargement des informations du cas…" />
        <div className="card card-pad">
          <Skeleton h={28} w="45%" />
          <Skeleton h={16} w="80%" style={{ marginTop: 12 }} />
          <Skeleton h={220} r={14} style={{ marginTop: 24 }} />
        </div>
      </>
    );
  }

  if (!review) return null;

  return (
    <>
      <PageHeader
        title="Examen du cas"
        description={`${review.domain} · reçu ${relativeTime(review.created_at)}`}
        actions={
          <div className="toolbar-actions">
            <Button variant="ghost" to="/review" icon={ArrowLeft}>
              Retour à la file
            </Button>
            <Button variant="quiet" icon={RotateCw} onClick={() => setRescanOpen(true)}>
              Relancer un scan
            </Button>
          </div>
        }
      />

      <section className="card review-summary" aria-label="Résumé du cas">
        <Stat label="Verdict">
          <VerdictBadge verdict={review.verdict} />
        </Stat>
        <Stat label="Statut">
          <ScanStatusBadge status={review.status} />
        </Stat>
        <Stat label="Score">
          <strong className="tabular">{scoreText(review.score)}</strong>
        </Stat>
        <Stat label="Source">
          <DetectionBadge source={review.detection_source} />
        </Stat>
        <Stat label="Mode">
          <span>{MODE[review.mode] || review.mode}</span>
        </Stat>
        <Stat label="Signalement">
          <ReportBadge reported={review.reported} claimedLabel={review.claimed_label} />
        </Stat>
        <Stat label="Propriétaire">
          <span className="truncate" title={review.owner_email}>
            {review.owner_email}
          </span>
        </Stat>
        <Stat label="Analyste">
          <span className="truncate" title={review.reviewed_by_email || ""}>
            {review.reviewed_by_email || <span className="faint">—</span>}
          </span>
        </Stat>
      </section>

      <div className="review-grid">
        <div className="review-col">
          <section className="card card-pad" aria-label="Adresse analysée">
            <div className="card-head">
              <div>
                <h2 className="card-title">Adresse analysée</h2>
                <p className="card-sub">Le contenu du site n'est jamais ouvert dans votre navigateur.</p>
              </div>
            </div>
            <div className="stack-sm">
              <div className="url-box">
                <small>URL soumise</small>
                <SafeUrl value={review.url} />
              </div>
              {scan?.final_url && scan.final_url !== review.url && (
                <div className="url-box">
                  <small>URL finale après redirections</small>
                  <SafeUrl value={scan.final_url} />
                </div>
              )}
              {review.rescan_of && (
                <p className="muted" style={{ margin: 0 }}>
                  Rescan de{" "}
                  <Link to={`/scans/${review.rescan_of}`} style={{ color: "var(--accent-text)" }}>
                    ce scan
                  </Link>
                  .
                </p>
              )}
              {scan?.partial && (
                <div className="alert alert-gold" role="status">
                  <ShieldAlert size={18} />
                  <span>
                    Résultat partiel : {REASON_CODE[scan.reason_code] || scan.reason_code || "raison inconnue"}.
                    Certaines modalités n'ont pas pu être analysées.
                  </span>
                </div>
              )}
            </div>
          </section>

          <section className="card card-pad" aria-label="Capture du site analysé">
            <div className="card-head">
              <div>
                <h2 className="card-title">Capture isolée</h2>
                <p className="card-sub">Image produite par le navigateur du bac à sable, sans accès à votre réseau.</p>
              </div>
              <Camera size={20} className="faint" aria-hidden="true" />
            </div>
            {screenshotState === "loading" && <Skeleton h={240} r={14} />}
            {screenshotState === "ready" && screenshotUrl && (
              <figure className="screenshot-frame">
                <img src={screenshotUrl} alt="Capture isolée du site analysé" />
                <figcaption>Capture du site au moment de l'analyse.</figcaption>
              </figure>
            )}
            {screenshotState === "missing" && (
              <div className="alert alert-info" role="status">
                <Camera size={18} />
                <span>Aucune capture n'est disponible pour ce scan.</span>
              </div>
            )}
            {screenshotState === "error" && (
              <div className="alert alert-error" role="alert">
                <XCircle size={18} />
                <span>La capture n'a pas pu être chargée.</span>
              </div>
            )}
          </section>

          <section className="card card-pad" aria-label="Probabilités par modalité">
            <div className="card-head">
              <div>
                <h2 className="card-title">Probabilités par modalité</h2>
                <p className="card-sub">Sorties du modèle, pas une explication certifiée du risque.</p>
              </div>
            </div>
            {probabilities.length === 0 ? (
              <p className="muted" style={{ margin: 0 }}>
                Aucune probabilité disponible pour ce cas.
              </p>
            ) : (
              <div className="prob-list">
                {probabilities.map(([key, value]) => (
                  <div className="prob-row" key={key}>
                    <div className="prob-head">
                      <span>{MODALITY_LABEL[key] || key}</span>
                      <b>{value.toFixed(3)}</b>
                    </div>
                    <div className="prob-track" aria-hidden="true">
                      <div className="prob-fill" style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="card card-pad" aria-label="Signaux techniques">
            <div className="card-head">
              <div>
                <h2 className="card-title">Signaux techniques</h2>
                <p className="card-sub">Indices collectés pendant l'analyse, à interpréter avec le verdict.</p>
              </div>
            </div>
            {signals.length === 0 ? (
              <p className="muted" style={{ margin: 0 }}>
                Aucun signal technique disponible.
              </p>
            ) : (
              <dl className="kv">
                {signals.map(([key, value]) => (
                  <div key={key} style={{ display: "contents" }}>
                    <dt>{humanKey(key)}</dt>
                    <dd className="mono" style={{ overflowWrap: "anywhere" }}>
                      {signalValue(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </section>

          <section className="card card-pad" aria-label="Signalement utilisateur">
            <div className="card-head">
              <div>
                <h2 className="card-title">Signalement utilisateur</h2>
                <p className="card-sub">Le signalement est résolu automatiquement par votre décision.</p>
              </div>
            </div>
            {review.report ? (
              <dl className="kv">
                <dt>Signalé par</dt>
                <dd>{review.report.reporter_email || "—"}</dd>
                <dt>Verdict revendiqué</dt>
                <dd>{CLAIMED_LABEL[review.report.claimed_label] || review.report.claimed_label || "—"}</dd>
                <dt>Statut</dt>
                <dd>{REPORT_STATUS[review.report.status] || review.report.status || "—"}</dd>
                <dt>Commentaire</dt>
                <dd>{review.report.comment || <span className="faint">Aucun commentaire</span>}</dd>
                <dt>Date</dt>
                <dd>{formatDateTime(review.report.created_at)}</dd>
              </dl>
            ) : (
              <div className="alert alert-info" role="status">
                <ShieldAlert size={18} />
                <span>
                  Aucun signalement utilisateur : ce cas a été routé automatiquement parce que le verdict du modèle est incertain.
                </span>
              </div>
            )}
          </section>

          <section className="card card-pad" aria-label="Notes internes">
            <div className="card-head">
              <div>
                <h2 className="card-title">Notes internes</h2>
                <p className="card-sub">Visibles uniquement par les analystes et les administrateurs.</p>
              </div>
            </div>
            {notes.length === 0 ? (
              <p className="muted" style={{ margin: "0 0 16px" }}>
                Aucune note interne pour ce cas.
              </p>
            ) : (
              <div className="note-list" style={{ marginBottom: 18 }}>
                {notes.map((note) => (
                  <article className="note-item" key={`${note.author_email}-${note.created_at}`}>
                    <div className="note-head">
                      <strong>{note.author_email}</strong>
                      <span title={note.created_at}>{formatDateTime(note.created_at)}</span>
                    </div>
                    <div className="note-text">{note.text}</div>
                  </article>
                ))}
              </div>
            )}
            <form onSubmit={submitNote} className="stack-sm" noValidate>
              {noteError && (
                <div className="alert alert-error" role="alert">
                  <XCircle size={18} />
                  <span>{noteError}</span>
                </div>
              )}
              <TextAreaField
                label="Ajouter une note interne"
                value={noteText}
                onChange={(event) => setNoteText(event.target.value)}
                rows={3}
                maxLength={2000}
                placeholder="Hypothèse, vérification effectuée, contexte utile…"
                hint="2000 caractères maximum. Le texte de la note n'est jamais écrit dans le journal d'audit."
              />
              <div className="form-actions">
                <Button variant="gold" type="submit" icon={MessageSquarePlus} loading={savingNote} disabled={!noteText.trim()}>
                  Ajouter la note
                </Button>
              </div>
            </form>
          </section>
        </div>

        <div className="review-col">
          <section className="card card-pad" aria-label="Décision">
            <div className="card-head">
              <div>
                <h2 className="card-title">Décision</h2>
                <p className="card-sub">La décision est définitive et écrite dans le journal d'audit.</p>
              </div>
              <Gavel size={20} className="faint" aria-hidden="true" />
            </div>

            {canDecide ? (
              <form
                className="stack-sm"
                onSubmit={(event) => {
                  event.preventDefault();
                  setConfirmDecision(true);
                }}
                noValidate
              >
                {decisionError && (
                  <div className="alert alert-error" role="alert">
                    <XCircle size={18} />
                    <span>{decisionError}</span>
                  </div>
                )}
                <div className="field">
                  <span className="field-label">Verdict de l'analyste</span>
                  <Segmented
                    label="Verdict de l'analyste"
                    value={decision}
                    onChange={changeDecision}
                    options={DECISION_VALUES.map((value) => ({ value, label: DECISION[value] }))}
                  />
                </div>
                <div className={`alert ${decision === "confirm_phishing" ? "alert-error" : "alert-success"}`}>
                  {decision === "confirm_phishing" ? <ShieldAlert size={18} /> : <CheckCircle2 size={18} />}
                  <span>
                    {decision === "confirm_phishing"
                      ? "Le scan passera en « Confirmé » et le signalement sera résolu."
                      : "Le scan passera en « Faux positif » et le signalement sera résolu."}
                  </span>
                </div>
                {decision === "confirm_phishing" && (
                  <Checkbox
                    label="Ajouter le domaine à la blocklist"
                    description="Le scan passera en « Bloqué ». Les prochains scans de ce domaine seront refusés immédiatement."
                    checked={addToBlocklist}
                    onChange={setAddToBlocklist}
                  />
                )}
                <TextAreaField
                  label="Commentaire (optionnel)"
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  rows={4}
                  maxLength={1000}
                  placeholder="Justification courte de la décision…"
                  hint="1000 caractères maximum. Visible par les autres analystes."
                />
                <div className="form-actions">
                  <Button variant="gold" type="submit" icon={Gavel} disabled={deciding}>
                    Enregistrer la décision
                  </Button>
                </div>
              </form>
            ) : (
              <DecisionSummary review={review} />
            )}
          </section>
        </div>
      </div>

      <ConfirmDialog
        open={confirmDecision}
        onClose={() => setConfirmDecision(false)}
        onConfirm={submitDecision}
        loading={deciding}
        tone={decision === "confirm_phishing" ? "danger" : "gold"}
        title="Confirmer la décision ?"
        confirmLabel="Enregistrer"
        message={
          <>
            <strong style={{ color: "var(--text)" }}>{DECISION[decision] || decision}</strong> sera enregistré pour{" "}
            <strong style={{ color: "var(--text)" }}>{review.domain}</strong>.
            {decision === "confirm_phishing" && addToBlocklist && " Le domaine sera aussi ajouté à la blocklist."}
            {" "}Cette action est définitive.
          </>
        }
      />

      <ConfirmDialog
        open={rescanOpen}
        onClose={() => setRescanOpen(false)}
        onConfirm={runRescan}
        loading={rescuing}
        tone="gold"
        title="Relancer un scan ?"
        confirmLabel="Relancer"
        message={
          <>
            Un nouveau scan complet de <strong style={{ color: "var(--text)" }}>{review.domain}</strong> sera créé et
            compté dans votre quota quotidien. Le scan actuel reste inchangé.
          </>
        }
      />
    </>
  );
}
