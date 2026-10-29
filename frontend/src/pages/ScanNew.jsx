import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, History, Link2, ShieldAlert } from "lucide-react";
import { createScan, getScanQuota } from "../api/scans";
import Button from "../components/ui/Button";
import { TextField } from "../components/ui/Fields";
import PageHeader from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/States";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { formatDateTime } from "../utils/format";

function validateUrl(raw) {
  try {
    const parsed = new URL(raw.trim());
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return "Seules les adresses http:// et https:// sont acceptées.";
    }
    if (raw.trim().length > 2048) return "L'adresse ne peut pas dépasser 2048 caractères.";
    if (parsed.username || parsed.password) return "Ne pas inclure d'identifiants dans l'URL.";
    if (!parsed.hostname) return "Le domaine est manquant.";
    return "";
  } catch {
    return "Saisissez une adresse URL valide, par exemple https://exemple.com.";
  }
}

export default function ScanNew() {
  useDocumentTitle("Nouveau scan");
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const relaunchUrl = searchParams.get("url") || "";
  const [url, setUrl] = useState(relaunchUrl);
  const [fieldError, setFieldError] = useState("");
  const [formError, setFormError] = useState("");
  const [quota, setQuota] = useState(null);
  const [quotaError, setQuotaError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [retryIn, setRetryIn] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getScanQuota(controller.signal)
      .then((data) => setQuota(data))
      .catch((err) => {
        if (err?.name !== "AbortError") setQuotaError(err?.message || "Quota indisponible.");
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (retryIn <= 0) return undefined;
    const timer = setInterval(() => setRetryIn((value) => Math.max(0, value - 1)), 1000);
    return () => clearInterval(timer);
  }, [retryIn]);

  const submit = async (event) => {
    event.preventDefault();
    setFieldError("");
    setFormError("");
    const validation = validateUrl(url);
    if (validation) {
      setFieldError(validation);
      return;
    }
    if (quota && quota.remaining <= 0) {
      setFormError("Quota quotidien épuisé. Patientez jusqu'à la réinitialisation.");
      return;
    }
    setSubmitting(true);
    try {
      const created = await createScan(url.trim());
      navigate(`/scans/${created.id}`);
    } catch (err) {
      if (err?.status === 429) {
        setRetryIn(err.retryAfter || 60);
        setFormError(err.message || "Quota atteint. Patientez avant de réessayer.");
      } else {
        setFormError(err?.message || "La demande d'analyse a échoué.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const remaining = quota?.remaining ?? null;
  const used = quota?.used ?? 0;
  const limit = quota?.limit ?? 0;
  const ratio = limit > 0 ? Math.min(100, Math.max(0, (used / limit) * 100)) : 0;
  const exhausted = remaining !== null && remaining <= 0;

  return (
    <>
      <PageHeader
        title="Nouveau scan"
        description="Soumettez une adresse web. L'analyse complète se poursuit en arrière-plan et reste consultable dans votre historique."
        actions={
          <Button variant="ghost" to="/scans" icon={History}>
            Mon historique
          </Button>
        }
      />

      <div className="scan-new-grid">
        <section className="card card-pad" aria-labelledby="scan-form-title">
          <div className="card-head">
            <div>
              <h2 id="scan-form-title" className="card-title">Adresse à analyser</h2>
              <p className="card-sub">Le serveur vérifie aussi le format, le quota et les adresses interdites (SSRF).</p>
            </div>
          </div>

          <form onSubmit={submit} noValidate data-testid="scan-form">
            {relaunchUrl && (
              <div className="alert alert-info" role="status" style={{ marginBottom: 16 }}>
                <ShieldAlert size={18} />
                <span>
                  Relance de l'adresse existante. Ce nouveau scan décompte 1 de votre quota.
                </span>
              </div>
            )}
            <TextField
              label="URL à analyser"
              type="url"
              inputMode="url"
              placeholder="https://exemple.com/page"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                setFieldError("");
                setFormError("");
              }}
              error={fieldError}
              hint="Adresse http:// ou https:// uniquement, 2048 caractères maximum."
              icon={Link2}
              autoComplete="url"
              name="url"
              data-testid="scan-url"
            />

            <div className="inline-actions" style={{ marginTop: 18 }}>
              <Button
                variant="gold"
                type="submit"
                iconRight={ArrowRight}
                loading={submitting}
                disabled={exhausted || retryIn > 0}
                data-testid="scan-submit"
              >
                Lancer l'analyse
              </Button>
              {retryIn > 0 && (
                <span className="muted" role="status" data-testid="scan-countdown">
                  Réessayez dans {retryIn} s.
                </span>
              )}
            </div>
          </form>

          {formError && (
            <div className="alert alert-error" role="alert" style={{ marginTop: 16 }} data-testid="scan-error">
              <ShieldAlert size={18} />
              <span>{formError}</span>
            </div>
          )}

          <p className="url-analysis-access" style={{ marginTop: 18 }}>
            Une URL locale, privée ou réservée est refusée par le serveur. Ne visitez jamais un lien suspect
            dans votre navigateur : la plateforme l'inspecte dans un bac à sable isolé.
          </p>
        </section>

        <aside className="card card-pad" aria-labelledby="quota-title" data-testid="quota-card">
          <div className="card-head">
            <div>
              <h2 id="quota-title" className="card-title">Quota du jour</h2>
              <p className="card-sub">Un scan complet est décompté à la soumission.</p>
            </div>
          </div>
          {!quota && !quotaError && (
            <div className="stack-sm">
              <Skeleton h={18} w="45%" />
              <Skeleton h={10} />
            </div>
          )}
          {quotaError && <p className="alert alert-error" role="alert">{quotaError}</p>}
          {quota && (
            <>
              <div className="quota-number">
                <strong data-testid="quota-remaining">{remaining}</strong>
                <span>scan{remaining === 1 ? "" : "s"} restant{remaining === 1 ? "" : "s"}</span>
              </div>
              <div className="quota-meter" aria-hidden="true">
                <span style={{ width: `${ratio}%` }} className={exhausted ? "is-empty" : ""} />
              </div>
              <p className="muted" style={{ margin: "10px 0 0", fontSize: "var(--fs-xs)" }}>
                {used} utilisé{used === 1 ? "" : "s"} sur {limit} · réinitialisation le{" "}
                {formatDateTime(quota.reset_at)}
              </p>
              {exhausted && (
                <div className="alert alert-gold" role="status" style={{ marginTop: 16 }}>
                  <ShieldAlert size={18} />
                  <span>Quota épuisé. Vous pourrez relancer un scan après la réinitialisation.</span>
                </div>
              )}
            </>
          )}
        </aside>
      </div>
    </>
  );
}
