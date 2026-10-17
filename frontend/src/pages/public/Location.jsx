import { useState } from "react";
import { Check, Clock, Copy, ExternalLink, MapPin, Navigation } from "lucide-react";
import Button from "../../components/ui/Button";
import PageHero from "../../components/ui/PageHero";
import { directionsUrl, fullAddress, mapEmbedUrl, mapOpenUrl, SITE } from "../../config/site";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";

export default function Location() {
  useDocumentTitle("Localisation");
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(fullAddress());
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    } catch {
      /* presse-papiers indisponible */
    }
  };

  return (
    <>
      <PageHero title="Où nous trouver" lead="Venez à notre rencontre ou préparez votre itinéraire en un clic." />

      <section className="section">
        <div className="loc-grid">
          <div className="card card-pad loc-info">
            <div className="info-item">
              <span className="row-ico">
                <MapPin size={22} />
              </span>
              <div>
                <h2>Adresse</h2>
                <address>
                  {SITE.address.line1}
                  <br />
                  {SITE.address.postalCode} {SITE.address.city}
                  <br />
                  {SITE.address.country}
                </address>
              </div>
            </div>

            <hr className="divider" />

            <div className="info-item">
              <span className="row-ico">
                <Clock size={22} />
              </span>
              <div style={{ flex: 1 }}>
                <h2>Horaires d'ouverture</h2>
                <dl className="hours">
                  {SITE.hours.map((h) => (
                    <div key={h.days}>
                      <dt>{h.days}</dt>
                      <dd>{h.time}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            </div>

            <div className="loc-actions">
              <Button variant="gold" icon={Navigation} href={directionsUrl()}>
                Itinéraire
              </Button>
              <Button variant="ghost" icon={copied ? Check : Copy} onClick={copy}>
                {copied ? "Adresse copiée" : "Copier l'adresse"}
              </Button>
            </div>
          </div>

          <div className="map-card">
            <iframe
              title={`Carte : ${fullAddress()}`}
              className="map-frame"
              src={mapEmbedUrl()}
              loading="lazy"
              referrerPolicy="no-referrer"
            />
            <a className="map-open" href={mapOpenUrl()} target="_blank" rel="noreferrer">
              Agrandir la carte <ExternalLink size={14} />
            </a>
          </div>
        </div>
      </section>
    </>
  );
}
