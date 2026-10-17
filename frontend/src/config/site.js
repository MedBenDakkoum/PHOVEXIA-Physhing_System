// ============================================================================
//  À PERSONNALISER : coordonnées affichées sur les pages Accueil, Localisation
//  et Contact. Remplacez ces valeurs d'exemple par celles de votre organisation.
// ============================================================================
export const SITE = {
  name: "Phishing Multimodal",
  email: "contact@phishing-multimodal.example",
  phone: "+216 71 000 000",
  address: {
    line1: "Avenue Habib Bourguiba",
    postalCode: "1000",
    city: "Tunis",
    country: "Tunisie",
  },
  // Coordonnées GPS pour la carte (OpenStreetMap)
  geo: { lat: 36.8008, lng: 10.18 },
  hours: [
    { days: "Lundi – Vendredi", time: "08h30 – 17h30" },
    { days: "Samedi", time: "09h00 – 13h00" },
    { days: "Dimanche", time: "Fermé" },
  ],
};

export const fullAddress = () => {
  const a = SITE.address;
  return `${a.line1}, ${a.postalCode} ${a.city}, ${a.country}`;
};

export const mapEmbedUrl = () => {
  const { lat, lng } = SITE.geo;
  const dx = 0.012;
  const dy = 0.007;
  return `https://www.openstreetmap.org/export/embed.html?bbox=${lng - dx}%2C${lat - dy}%2C${lng + dx}%2C${lat + dy}&layer=mapnik&marker=${lat}%2C${lng}`;
};
export const mapOpenUrl = () => `https://www.openstreetmap.org/?mlat=${SITE.geo.lat}&mlon=${SITE.geo.lng}#map=16/${SITE.geo.lat}/${SITE.geo.lng}`;
export const directionsUrl = () => `https://www.openstreetmap.org/directions?to=${SITE.geo.lat}%2C${SITE.geo.lng}`;
