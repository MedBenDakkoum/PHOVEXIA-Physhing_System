import { test, expect } from "@playwright/test";

const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || "admin@test.com",
  password: process.env.E2E_ADMIN_PASSWORD || "AdminRealE2e!2026",
};
const USER = {
  email: process.env.E2E_USER_EMAIL || "e2e.analyst.user@example.com",
  password: process.env.E2E_USER_PASSWORD || "E2eReview!2026x",
};

async function login(page, email, password) {
  await page.goto("/login");
  await page.getByRole("textbox", { name: "Adresse e-mail" }).fill(email);
  await page.getByRole("textbox", { name: "Mot de passe" }).fill(password);
  await page.getByRole("button", { name: "Se connecter" }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function logout(page) {
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.setItem("pm.loggedOut", "1");
  });
}

test.describe("FE-3 administration", () => {
  test("admin dashboard, models, settings, health, audit and API keys", async ({ page }) => {
    await login(page, USER.email, USER.password);
    await page.goto("/app/admin/settings");
    await expect(page.getByRole("heading", { name: "Accès non autorisé" })).toBeVisible();
    await expect(page.getByText("Votre rôle ne permet pas d'ouvrir cette page.")).toBeVisible();

    await logout(page);
    await login(page, ADMIN.email, ADMIN.password);
    await expect(page.getByRole("heading", { name: "Vue d’ensemble" })).toBeVisible();
    await expect(page.getByText("Scans analysés")).toBeVisible();
    await expect(page.getByText("Taux de phishing")).toBeVisible();
    await expect(page.getByText("En attente de revue")).toBeVisible();
    await expect(page.getByRole("button", { name: "7 jours" })).toBeVisible();

    await page.goto("/app/admin/models");
    await expect(page.getByRole("heading", { name: "Versions du modèle" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Enregistrer une version" })).toBeVisible();
    await page.getByRole("button", { name: "Enregistrer une version" }).click();
    const createModelDialog = page.getByRole("dialog", { name: "Enregistrer une version" });
    await expect(createModelDialog).toBeVisible();
    await createModelDialog.getByLabel("Nom").fill("E2E validation");
    await createModelDialog.getByLabel("Version").fill("e2e-invalid");
    await createModelDialog.getByLabel("Métriques (JSON)").fill("{");
    await createModelDialog.getByRole("button", { name: "Enregistrer" }).click();
    await expect(createModelDialog.getByText("Les métriques doivent être un objet JSON valide.")).toBeVisible();
    await createModelDialog.getByRole("button", { name: "Annuler" }).click();
    const checks = page.getByRole("checkbox", { name: /Comparer/ });
    await expect(checks.first()).toBeVisible();
    await checks.nth(0).check();
    await checks.nth(1).check();
    await page.getByRole("button", { name: /Comparer \(2\)/ }).click();
    const compareDialog = page.getByRole("dialog", { name: "Comparer les versions" });
    await expect(compareDialog).toBeVisible();
    await expect(compareDialog.getByText("precision")).toBeVisible();
    await compareDialog.getByRole("button", { name: "Fermer", exact: true }).first().click();

    await page.goto("/app/admin/settings");
    await expect(page.getByRole("heading", { name: "Réglages de détection" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Seuils de décision" })).toBeVisible();
    await expect(page.getByLabel("Seuil phishing")).toHaveValue(/0\.\d+/);
    await expect(page.getByLabel("Seuil incertain")).toHaveValue(/0\.\d+/);
    await page.getByLabel("Seuil phishing").fill("0.2");
    await page.getByLabel("Seuil incertain").fill("0.5");
    await page.getByRole("button", { name: "Enregistrer" }).click();
    await expect(
      page.getByText("La règle 0 < seuil incertain < seuil phishing ≤ 1 doit être respectée.").first()
    ).toBeVisible();
    await page.getByRole("button", { name: "Annuler" }).click();
    await expect(page.getByText("Traçabilité")).toBeVisible();

    await page.goto("/app/admin/health");
    await expect(page.getByRole("heading", { name: "Santé du système" })).toBeVisible();
    await expect(page.getByText("Base de données")).toBeVisible();
    await expect(page.getByText("Workers Celery")).toBeVisible();
    await expect(page.getByText("Modèle servi")).toBeVisible();
    await expect(page.getByRole("button", { name: "Revérifier" })).toBeVisible();

    await page.goto("/app/admin/users");
    await expect(page.getByRole("heading", { name: "Utilisateurs" })).toBeVisible();
    await page.goto("/app/admin/audit");
    await expect(page.getByRole("heading", { name: "Journal d'audit" })).toBeVisible();

    await page.goto("/app/admin/api-keys");
    await expect(page.getByRole("heading", { name: "Clés API" })).toBeVisible();
    const keyName = `E2E Admin ${Date.now()}`;
    await page.getByRole("button", { name: "Créer une clé" }).first().click();
    const createDialog = page.getByRole("dialog", { name: "Créer une clé API" });
    await expect(createDialog).toBeVisible();
    await createDialog.getByLabel("Nom").fill(keyName);
    await createDialog.getByRole("button", { name: "Créer la clé" }).click();

    const createdDialog = page.getByRole("dialog", { name: "Clé API créée" });
    await expect(createdDialog).toBeVisible();
    const secret = (await createdDialog.locator(".secret-box code").textContent())?.trim();
    expect(secret?.length).toBeGreaterThan(20);
    await createdDialog.getByRole("button", { name: "J’ai copié le secret" }).click();
    const row = page.locator("tr", { hasText: keyName }).first();
    await expect(row).toBeVisible();
    await row.getByRole("button", { name: "Révoquer" }).click();
    const revokeDialog = page.getByRole("dialog", { name: "Révoquer cette clé ?" });
    await expect(revokeDialog).toBeVisible();
    await revokeDialog.getByRole("button", { name: "Révoquer", exact: true }).click();
    await expect(page.locator("tr", { hasText: keyName }).first()).toContainText("Révoquée", {
      timeout: 15000,
    });
  });
});
