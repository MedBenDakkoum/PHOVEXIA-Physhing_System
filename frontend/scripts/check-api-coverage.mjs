#!/usr/bin/env node
/**
 * Vérifie que chaque opération de backend/openapi.json est appelée par le
 * frontend, ou documente explicitement pourquoi elle ne l'est pas.
 *
 * Usage: node scripts/check-api-coverage.mjs
 * Écrit docs/endpoint_coverage.md et sort en erreur si une opération n'est ni
 * couverte ni déclarée comme écart autorisé.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND = path.resolve(HERE, "..");
const REPO = path.resolve(FRONTEND, "..");
const OPENAPI = path.join(REPO, "backend", "openapi.json");
const SRC = path.join(FRONTEND, "src");
const OUTPUT = path.join(REPO, "docs", "endpoint_coverage.md");
const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"];

const ALLOWED_GAPS = new Map([
  ["POST /api/auth/password-reset/", "API de réinitialisation par e-mail non câblée dans l'interface ; hors périmètre FE-1."],
  ["POST /api/auth/password-reset/confirm/", "Confirmation du lien de réinitialisation non câblée dans l'interface ; hors périmètre FE-1."],
  ["GET /api/schema/", "Schéma OpenAPI brut, public, destiné aux outils et non à l'interface."],
  ["GET /api/health/", "Sonde publique de disponibilité, non affichée dans l'interface."],
  ["GET /api/audit/logs/{id}/", "Détail d'un événement non affiché : la liste d'audit FE-3 contient déjà les champs nécessaires."],
  ["GET /api/admin/models/{public_id}/", "Détail d'une version non requis par l'écran FE-3 ; la liste et la comparaison couvrent le besoin."],
]);

const OUT_OF_SCOPE = [
  ["Campagnes", "/api/campaigns/", "Fonctionnalité non construite (aucune route dans OpenAPI)."],
  ["Signalement d'abus", "non exposé", "Fonctionnalité non construite ; seul le signalement de verdict existe."],
  ["Explication du verdict", "non exposé", "Fonctionnalité non construite (pas de route d'explication)."],
  ["Dérive du modèle", "non exposé", "Fonctionnalité non construite (pas de route de drift)."],
  ["Ré-entraînement", "non exposé", "Fonctionnalité non construite (pas de route de retraining)."],
  ["Analyse .eml", "non exposé", "Fonctionnalité non construite (pas de route .eml)."],
];

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    return /\.(js|jsx)$/.test(entry.name) ? [full] : [];
  });
}

function normalise(apiPath) {
  return apiPath.replace(/\{[^}]+\}/g, "{}");
}

function parseEndpoints() {
  const file = fs.readFileSync(path.join(SRC, "api", "constants.js"), "utf8");
  const block = file.match(/export const ENDPOINTS = \{([\s\S]*?)\n\};/);
  if (!block) throw new Error("ENDPOINTS introuvables dans src/api/constants.js");
  const endpoints = new Map();
  for (const line of block[1].split(/\r?\n/)) {
    const stringMatch = line.match(/^\s*([A-Za-z0-9_]+):\s*"([^"]+)"/);
    if (stringMatch) {
      endpoints.set(stringMatch[1], stringMatch[2]);
      continue;
    }
    const fnMatch = line.match(/^\s*([A-Za-z0-9_]+):\s*\([^)]*\)\s*=>\s*`([^`]+)`/);
    if (fnMatch) {
      endpoints.set(fnMatch[1], fnMatch[2].replace(/\$\{[^}]+\}/g, "{}"));
    }
  }
  return endpoints;
}

const endpoints = parseEndpoints();
const calls = new Map();

for (const file of walk(SRC)) {
  const relative = path.relative(FRONTEND, file).replaceAll("\\", "/");
  if (relative === "src/api/constants.js") continue;
  const content = fs.readFileSync(file, "utf8");
  for (const match of content.matchAll(/ENDPOINTS\.([A-Za-z0-9_]+)/g)) {
    const endpoint = endpoints.get(match[1]);
    if (!endpoint) continue;
    const key = normalise(endpoint);
    if (!calls.has(key)) calls.set(key, new Set());
    calls.get(key).add(relative);
  }
  for (const match of content.matchAll(/["'`](\/api\/[A-Za-z0-9_./{}:-]+)["'`]/g)) {
    const key = normalise(match[1]);
    if (!calls.has(key)) calls.set(key, new Set());
    calls.get(key).add(relative);
  }
}

const spec = JSON.parse(fs.readFileSync(OPENAPI, "utf8"));
const operations = [];
for (const [apiPath, item] of Object.entries(spec.paths || {})) {
  for (const method of HTTP_METHODS) {
    if (!item[method]) continue;
    const key = normalise(apiPath);
    const files = [...(calls.get(key) || [])].sort();
    const gapKey = `${method.toUpperCase()} ${apiPath}`;
    operations.push({
      method: method.toUpperCase(),
      apiPath,
      files,
      allowedGap: ALLOWED_GAPS.get(gapKey) || "",
      summary: item[method].summary || "",
    });
  }
}

operations.sort((a, b) => a.apiPath.localeCompare(b.apiPath) || a.method.localeCompare(b.method));
const uncovered = operations.filter((op) => op.files.length === 0 && !op.allowedGap);
const covered = operations.filter((op) => op.files.length > 0);

const lines = [
  "# Couverture des endpoints par le frontend",
  "",
  `Généré par \`frontend/scripts/check-api-coverage.mjs\` depuis \`backend/openapi.json\`.`,
  "",
  "## Synthèse",
  "",
  `- Opérations OpenAPI : **${operations.length}**`,
  `- Opérations avec au moins un appel frontend : **${covered.length}**`,
  `- Écarts autorisés documentés : **${operations.filter((op) => !op.files.length && op.allowedGap).length}**`,
  `- Opérations non couvertes et non justifiées : **${uncovered.length}**`,
  "",
  "Un endpoint est considéré couvert lorsqu'au moins un fichier de `frontend/src` référence son chemin via `ENDPOINTS`.",
  "",
  "## Matrice path + méthode",
  "",
  "| Méthode | Endpoint | Fichier(s) frontend | Statut |",
  "|---|---|---|---|",
];

for (const op of operations) {
  const status = op.files.length ? "Couvert" : op.allowedGap ? "Écart autorisé" : "**NON COUVERT**";
  const files = op.files.length ? op.files.map((file) => `\`${file}\``).join("<br>") : "—";
  lines.push(`| ${op.method} | \`${op.apiPath}\` | ${files} | ${status} |`);
}

lines.push("", "## Écarts autorisés", "");
for (const op of operations.filter((item) => !item.files.length && item.allowedGap)) {
  lines.push(`- **${op.method} \`${op.apiPath}\`** : ${op.allowedGap}`);
}
if (!operations.some((item) => !item.files.length && item.allowedGap)) {
  lines.push("- Aucun.");
}

lines.push("", "## Fonctionnalités hors périmètre", "");
for (const [name, endpoint, reason] of OUT_OF_SCOPE) {
  lines.push(`- **${name}** (\`${endpoint}\`) : ${reason}`);
}

if (uncovered.length) {
  lines.push("", "## Opérations non couvertes", "");
  for (const op of uncovered) {
    lines.push(`- **${op.method} \`${op.apiPath}\`** : aucun appel frontend et aucune justification.`);
  }
}

lines.push("", "## Rappel", "");
lines.push(
  "Les écarts ci-dessus sont volontaires et limités aux endpoints publics de schéma/santé et aux écrans non construits. Toute nouvelle route backend doit soit être appelée par un écran, soit être ajoutée à cette liste avec une justification."
);

fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
fs.writeFileSync(OUTPUT, `${lines.join("\n")}\n`, "utf8");

console.log(`OpenAPI: ${operations.length} opérations`);
console.log(`Couvertes: ${covered.length}`);
console.log(`Écarts autorisés: ${operations.filter((op) => !op.files.length && op.allowedGap).length}`);
console.log(`Non couvertes: ${uncovered.length}`);
console.log(`Rapport: ${path.relative(REPO, OUTPUT)}`);

if (uncovered.length) {
  for (const op of uncovered) console.error(`NON COUVERT: ${op.method} ${op.apiPath}`);
  process.exitCode = 1;
}
