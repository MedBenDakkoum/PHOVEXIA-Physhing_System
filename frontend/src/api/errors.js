// Traduction des messages d'erreur DRF / Django (anglais) vers le français.
const EXACT = {
  "No active account found with the given credentials":
    "E-mail ou mot de passe incorrect, ou compte suspendu.",
  "Authentication credentials were not provided.": "Vous devez être connecté pour effectuer cette action.",
  "You do not have permission to perform this action.": "Vous n'avez pas les droits nécessaires pour cette action.",
  "Given token not valid for any token type": "Votre session a expiré. Reconnectez-vous.",
  "Token is invalid or expired": "Votre session a expiré. Reconnectez-vous.",
  "Token is blacklisted": "Cette session a été fermée. Reconnectez-vous.",
  "Not found.": "Élément introuvable.",
  "This field is required.": "Ce champ est obligatoire.",
  "This field may not be blank.": "Ce champ ne peut pas être vide.",
  "This field may not be null.": "Ce champ ne peut pas être vide.",
  "Enter a valid email address.": "Saisissez une adresse e-mail valide.",
  "Cet email est déjà utilisé.": "Cet e-mail est déjà utilisé.",
  "This password is too common.": "Ce mot de passe est trop courant.",
  "This password is entirely numeric.": "Le mot de passe ne peut pas être composé uniquement de chiffres.",
  "The password is too similar to the email address.": "Le mot de passe ressemble trop à votre adresse e-mail.",
  "The password is too similar to the first name.": "Le mot de passe ressemble trop à votre prénom.",
  "The password is too similar to the last name.": "Le mot de passe ressemble trop à votre nom.",
};

export function translateMessage(msg) {
  if (typeof msg !== "string") return String(msg);
  if (EXACT[msg]) return EXACT[msg];
  let m = msg.match(/This password is too short\. It must contain at least (\d+) characters?\./);
  if (m) return `Mot de passe trop court : ${m[1]} caractères minimum.`;
  m = msg.match(/Request was throttled\. Expected available in (\d+) seconds?\./);
  if (m) return `Trop de requêtes. Réessayez dans ${m[1]} secondes.`;
  if (/Request was throttled/.test(msg)) return "Trop de requêtes. Patientez un instant avant de réessayer.";
  m = msg.match(/"(.+)" is not a valid choice\./);
  if (m) return `La valeur « ${m[1]} » n'est pas valide.`;
  if (/already exists/i.test(msg)) return "Cet e-mail est déjà utilisé.";
  if (/Enter a valid date/i.test(msg)) return "Date invalide.";
  if (/Select a valid choice/i.test(msg)) return "Valeur invalide.";
  return msg;
}

export class ApiError extends Error {
  constructor(message, { status = 0, data = null, retryAfter = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
    this.retryAfter = retryAfter;
  }

  /** Erreurs par champ : { email: "…", password: "…" } (premier message de chaque champ). */
  get fieldErrors() {
    const out = {};
    if (this.data && typeof this.data === "object" && !Array.isArray(this.data)) {
      for (const [k, v] of Object.entries(this.data)) {
        if (k === "detail") continue;
        const first = Array.isArray(v) ? v[0] : v;
        if (typeof first === "string") out[k] = translateMessage(first);
      }
    }
    return out;
  }
}

/** Construit un message lisible à partir de la réponse d'erreur du backend. */
export function messageFromResponse(status, data) {
  if (status === 0) return "Impossible de joindre le serveur. Vérifiez votre connexion et que le backend est lancé.";
  if (status === 429) {
    const detail = data && typeof data === "object" ? data.detail : "";
    return translateMessage(detail || "Request was throttled.");
  }
  if (status >= 500) return "Erreur interne du serveur. Réessayez dans un instant.";
  if (data && typeof data === "object") {
    if (typeof data.detail === "string") return translateMessage(data.detail);
    if (Array.isArray(data.non_field_errors)) return translateMessage(data.non_field_errors[0]);
    const entries = Object.entries(data);
    if (entries.length) {
      const [, v] = entries[0];
      return translateMessage(Array.isArray(v) ? v[0] : v);
    }
  }
  if (status === 401) return "Vous devez être connecté pour effectuer cette action.";
  if (status === 403) return "Vous n'avez pas les droits nécessaires pour cette action.";
  if (status === 404) return "Élément introuvable.";
  return "Une erreur est survenue.";
}

export const errorMessage = (e) => (e instanceof ApiError ? e.message : e?.message || "Une erreur est survenue.");
