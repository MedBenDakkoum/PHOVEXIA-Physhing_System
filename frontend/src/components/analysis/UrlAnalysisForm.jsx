import { useState } from "react";
import { ArrowRight, Link2, ShieldAlert } from "lucide-react";
import Button from "../ui/Button";
import { TextField } from "../ui/Fields";

/** Shared URL input for the public home page and every dashboard role. */
export default function UrlAnalysisForm({ role }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setNotice("");
    setError("");
    let parsed;
    try {
      parsed = new URL(url.trim());
    } catch {
      setError("Saisissez une adresse URL valide, par exemple https://example.com.");
      return;
    }
    // Client checks ONLY scheme, length, credentials — server checks host/forbidden
    if (!/^[a-z][a-z0-9+.-]*:$/i.test(parsed.protocol)) {
      setError("Seules les adresses web HTTP ou HTTPS sont acceptées.");
      return;
    }
    if (url.trim().length > 2048) {
      setError("L'adresse est trop longue.");
      return;
    }
    if (parsed.username || parsed.password) {
      setError("Ne pas inclure d'identifiants dans l'URL.");
      return;
    }
    // Quick-check flow (anonymous) — real API call
    try {
      const res = await fetch("/api/quick-check/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() })
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || "Erreur du service d'analyse.");
        return;
      }
      const data = await res.json();
      setNotice("Analyse rapide : verdict = " + (data.verdict || data.status || "traité") + ".");
    } catch (e) {
      setError("Service indisponible. Réessayez plus tard.");
    }
  };

  return (
    <section className="card card-pad url-analysis" aria-labelledby="url-analysis-title">
      <div className="card-head">
        <div>
          <h2 id="url-analysis-title" className="card-title">Analyser une adresse web</h2>
          <p className="card-sub">Collez un lien suspect pour préparer son analyse de sécurité.</p>
        </div>
        <span className="url-analysis-icon" aria-hidden="true"><Link2 size={20} /></span>
      </div>
      <form className="url-analysis-form" onSubmit={submit} noValidate>
        <TextField
          label="URL à vérifier"
          type="url"
          inputMode="url"
          placeholder="https://exemple.com/page"
          value={url}
          onChange={(event) => { setUrl(event.target.value); setError(""); setNotice(""); }}
          error={error}
          hint="L’adresse doit commencer par http:// ou https://."
          icon={Link2}
          autoComplete="url"
        />
        <Button variant="gold" type="submit" iconRight={ArrowRight}>Vérifier l’adresse</Button>
      </form>
      {notice && <p className="alert alert-gold url-analysis-notice" role="status"><ShieldAlert size={18} />{notice}</p>}
      <p className="url-analysis-access">
        {role === "guest"
          ? "Aucun compte n’est nécessaire pour saisir une adresse. Le service d’analyse sera disponible prochainement."
          : role === "end_user" || role === "viewer"
            ? "Accès lecteur : vous pouvez préparer une adresse à vérifier."
            : "Votre espace est prêt pour l’analyse dès que le service sera disponible."}
      </p>
    </section>
  );
}
