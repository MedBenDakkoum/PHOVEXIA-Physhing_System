import { useState } from "react";
import { Link } from "react-router-dom";
import { Check, CircleAlert, Clock, Mail, MapPin, Phone, Send } from "lucide-react";
import Button from "../../components/ui/Button";
import { SelectField, TextField } from "../../components/ui/Fields";
import PageHero from "../../components/ui/PageHero";
import { fullAddress, SITE } from "../../config/site";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";

const SUBJECTS = ["Question générale", "Demande de démonstration", "Support technique", "Signaler un problème de sécurité", "Autre"];

export default function Contact() {
  useDocumentTitle("Contact");
  const [form, setForm] = useState({ name: "", email: "", subject: SUBJECTS[0], message: "" });
  const [errors, setErrors] = useState({});
  const [sent, setSent] = useState(false);

  const set = (k) => (e) => {
    setForm((f) => ({ ...f, [k]: e.target.value }));
    setErrors((er) => ({ ...er, [k]: undefined }));
    setSent(false);
  };

  // Le backend n'expose pas d'endpoint de contact : le message est préparé
  // dans l'application de messagerie de l'utilisateur (mailto:).
  const submit = (e) => {
    e.preventDefault();
    const next = {};
    if (!form.name.trim()) next.name = "Saisissez votre nom.";
    if (!form.email.trim()) next.email = "Saisissez votre adresse e-mail.";
    else if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) next.email = "Saisissez une adresse e-mail valide.";
    if (form.message.trim().length < 10) next.message = "Votre message doit contenir au moins 10 caractères.";
    setErrors(next);
    if (Object.keys(next).length) return;

    const body = `${form.message.trim()}\n\n— ${form.name.trim()} (${form.email.trim()})`;
    window.location.href = `mailto:${SITE.email}?subject=${encodeURIComponent(`[${SITE.name}] ${form.subject}`)}&body=${encodeURIComponent(body)}`;
    setSent(true);
  };

  return (
    <>
      <PageHero title="Contactez-nous" lead="Une question, une démonstration à planifier ou un incident à signaler ? Écrivez-nous." />

      <section className="section">
        <div className="contact-grid">
          <form className="card card-pad" onSubmit={submit} noValidate>
            <div className="card-head">
              <div>
                <h2 className="card-title">Envoyer un message</h2>
                <p className="card-sub">Votre application de messagerie s'ouvrira avec le message prêt à envoyer.</p>
              </div>
            </div>
            <div className="form-grid">
              <TextField label="Nom" autoComplete="name" value={form.name} onChange={set("name")} error={errors.name} />
              <TextField label="Adresse e-mail" type="email" autoComplete="email" value={form.email} onChange={set("email")} error={errors.email} />
              <div className="full">
                <SelectField label="Sujet" value={form.subject} onChange={set("subject")}>
                  {SUBJECTS.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </SelectField>
              </div>
              <div className="field full">
                <label htmlFor="msg">Message</label>
                <textarea
                  id="msg"
                  className="input textarea"
                  rows={6}
                  value={form.message}
                  onChange={set("message")}
                  aria-invalid={errors.message ? "true" : undefined}
                />
                {errors.message && (
                  <span className="field-error" role="alert">
                    <CircleAlert size={14} style={{ marginTop: 2, flex: "none" }} /> {errors.message}
                  </span>
                )}
              </div>
            </div>
            {sent && (
              <div className="alert alert-success" role="status" style={{ marginTop: 16 }}>
                <Check size={18} />
                <span>
                  Votre messagerie s'est ouverte. Si rien ne s'affiche, écrivez directement à <a href={`mailto:${SITE.email}`}>{SITE.email}</a>.
                </span>
              </div>
            )}
            <div className="form-actions">
              <Button type="submit" variant="gold" icon={Send}>
                Préparer l'envoi
              </Button>
            </div>
          </form>

          <aside className="contact-side">
            <ul className="info-list">
              <li>
                <span className="row-ico">
                  <Mail size={22} />
                </span>
                <div>
                  <h2>E-mail</h2>
                  <a href={`mailto:${SITE.email}`}>{SITE.email}</a>
                </div>
              </li>
              <li>
                <span className="row-ico">
                  <Phone size={22} />
                </span>
                <div>
                  <h2>Téléphone</h2>
                  <a href={`tel:${SITE.phone.replace(/\s/g, "")}`}>{SITE.phone}</a>
                </div>
              </li>
              <li>
                <span className="row-ico">
                  <MapPin size={22} />
                </span>
                <div>
                  <h2>Adresse</h2>
                  <p>{fullAddress()}</p>
                  <Link to="/location">Voir la carte</Link>
                </div>
              </li>
              <li>
                <span className="row-ico">
                  <Clock size={22} />
                </span>
                <div>
                  <h2>Horaires</h2>
                  <p>
                    {SITE.hours[0].days} : {SITE.hours[0].time}
                  </p>
                </div>
              </li>
            </ul>
          </aside>
        </div>
      </section>
    </>
  );
}
