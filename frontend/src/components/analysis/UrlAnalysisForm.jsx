import { useState } from "react";
import { ArrowRight, Link2, ShieldAlert } from "lucide-react";
import Button from "../ui/Button";
import { TextField } from "../ui/Fields";

/** Shared URL input for the public home page and every dashboard role. */
export default function UrlAnalysisForm({ role }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const submit = (event) => {
    event.preventDefault();
    setNotice("");
    let parsed;
    try {
      parsed = new URL(url.trim());
    } catch {
      setError("Saisissez une adresse URL valide, par exemple https://example.com.");
      return;
    }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) {
      setError("Seules les adresses web HTTP ou HTTPS sont acceptées.");
      return;
    }
    setError("");
    setNotice("Adresse validée. Le service d’analyse d’URL n’est pas encore connecté.");
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
          : role === "viewer"
            ? "Accès lecteur : vous pouvez préparer une adresse à vérifier."
            : "Votre espace est prêt pour l’analyse dès que le service sera disponible."}
      </p>
    </section>
  );
}
