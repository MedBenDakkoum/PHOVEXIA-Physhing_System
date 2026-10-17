// Indications visuelles alignées sur AUTH_PASSWORD_VALIDATORS (settings.py).
// La validation définitive reste faite par le backend.
export function passwordChecks(password, email = "") {
  const local = (email || "").split("@")[0].toLowerCase();
  return [
    { id: "len", label: "8 caractères minimum", ok: password.length >= 8 },
    { id: "num", label: "Pas uniquement des chiffres", ok: password.length > 0 && !/^\d+$/.test(password) },
    {
      id: "sim",
      label: "Différent de votre e-mail",
      ok: password.length > 0 && !(local.length >= 4 && password.toLowerCase().includes(local)),
    },
  ];
}

export function passwordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (/^\d+$/.test(password)) score = Math.min(score, 1);
  const levels = [
    { label: "Très faible", tone: "danger" },
    { label: "Faible", tone: "danger" },
    { label: "Moyen", tone: "gold" },
    { label: "Bon", tone: "info" },
    { label: "Solide", tone: "success" },
    { label: "Excellent", tone: "success" },
  ];
  return { score, ...levels[password ? score : 0] };
}
