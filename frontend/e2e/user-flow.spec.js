import { test, expect } from "@playwright/test";

const API = process.env.E2E_API_URL || "http://127.0.0.1:8080";
const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || "admin@test.com",
  password: process.env.E2E_ADMIN_PASSWORD || "AdminRealE2e!2026",
};
const TERMINAL_STATUS = /Détecté|En revue|Confirmé|Faux positif|Bloqué|Échoué/;

function watch(page) {
  const issues = { pageErrors: [], consoleErrors: [], http: [] };
  page.on("pageerror", (error) => issues.pageErrors.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") issues.consoleErrors.push(message.text());
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      issues.http.push({
        status: response.status(),
        method: response.request().method(),
        url: response.url(),
      });
    }
  });
  return issues;
}

function assertClean(issues) {
  const apiErrors = issues.http.filter(
    (entry) =>
      entry.status !== 400 ||
      entry.method !== "POST" ||
      !new URL(entry.url).pathname.endsWith("/api/scans/")
  );
  const unexpectedConsole = issues.consoleErrors.filter(
    (message) =>
      !/Failed to load resource: the server responded with a status of 400 \(Bad Request\)/.test(
        message
      )
  );
  expect(issues.pageErrors).toEqual([]);
  expect(unexpectedConsole).toEqual([]);
  expect(apiErrors).toEqual([]);
}

async function clearExampleBlocklist(request) {
  const login = await request.post(`${API}/api/auth/login/`, {
    data: ADMIN,
  });
  expect(login.status(), await login.text()).toBe(200);
  const { access } = await login.json();
  const headers = { Authorization: `Bearer ${access}` };

  const blocked = await request.get(`${API}/api/blocklist/?q=example.com&page_size=100`, { headers });
  expect(blocked.status(), await blocked.text()).toBe(200);
  for (const entry of (await blocked.json()).results) {
    const removed = await request.delete(`${API}/api/blocklist/${entry.id}/`, {
      headers,
      data: { reason: "E2E user-flow cleanup" },
    });
    expect(removed.status(), `cleanup ${entry.domain}`).toBe(204);
  }
}

async function register(page, account) {
  await page.goto("/register");
  await page.fill('input[name="first_name"]', "E2E");
  await page.fill('input[name="last_name"]', "Parcours");
  await page.fill('input[name="email"]', account.email);
  await page.fill('input[name="password"]', account.password);
  await page.fill('input[name="confirm"]', account.password);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/app\/?$/, { timeout: 20000 });
}

async function login(page, account) {
  await page.goto("/login");
  await page.fill('input[name="email"]', account.email);
  await page.fill('input[name="password"]', account.password);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/app\/?$/, { timeout: 20000 });
}

test.describe("parcours utilisateur", () => {
  test("quick check anonyme : résultat final et aucune erreur client", async ({ page }) => {
    test.setTimeout(6 * 60 * 1000);
    const issues = watch(page);

    await page.goto("/");
    await page.getByTestId("quick-check-url").fill("https://example.com");
    await page.getByTestId("quick-check-submit").click();

    const result = page.getByTestId("quick-check-result");
    await expect(result).toBeVisible({ timeout: 20000 });
    await expect(page.getByTestId("quick-check-status")).toContainText(TERMINAL_STATUS, {
      timeout: 5 * 60 * 1000,
    });
    await expect(result).toContainText("Probabilité de phishing (modèle) :");
    await expect(page.getByTestId("quick-check-submit")).toBeEnabled();

    assertClean(issues);
  });

  test("inscription, connexion, scan complet, SSRF, signalement et historique filtré", async ({
    page,
    context,
  }) => {
    test.setTimeout(8 * 60 * 1000);
    await clearExampleBlocklist(context.request);

    const account = {
      email: `e2e.flow.${Date.now()}@test.com`,
      password: "E2eFlow!2026x",
    };

    const issues = watch(page);
    await register(page, account);
    await expect(page.locator(".command-title")).toContainText("E2E", { timeout: 20000 });

    await page.getByRole("button", { name: "Se déconnecter" }).click();
    await page.waitForURL(/\/$/, { timeout: 15000 });
    await login(page, account);

    await page.goto("/scans/new");
    await page.getByTestId("scan-url").fill("http://localhost");
    await page.getByTestId("scan-submit").click();
    await expect(page.getByTestId("scan-error")).toContainText(/refus/i, { timeout: 20000 });

    await page.getByTestId("scan-url").fill("https://example.com");
    await page.getByTestId("scan-submit").click();
    await page.waitForURL(/\/scans\/[0-9a-f-]{36}$/, { timeout: 20000 });

    const status = page.getByTestId("scan-status");
    await expect(status).toContainText(TERMINAL_STATUS, { timeout: 6 * 60 * 1000 });
    await expect(status).not.toContainText("Échoué");

    const bars = page.getByTestId("probability-bars");
    await expect(bars).toBeVisible({ timeout: 20000 });
    await expect(bars.getByText("Aucune probabilité disponible")).toHaveCount(0);
    await expect(bars.locator(".prob-row")).not.toHaveCount(0);

    const verdict = await page.getByTestId("scan-verdict").innerText();
    const claimed = /phishing/i.test(verdict) ? "safe" : "phishing";
    await page.getByTestId("report-claimed-label").selectOption(claimed);
    await page.getByTestId("report-comment").fill("E2E : le verdict doit être revu par un analyste.");
    await page.getByTestId("report-submit").click();
    await expect(page.getByTestId("report-section")).toContainText("Signalement déjà enregistré", {
      timeout: 20000,
    });

    await page.goto("/scans");
    await page.getByTestId("scan-search").fill("example.com");
    await page.getByTestId("scan-search").press("Enter");
    await expect(page).toHaveURL(/q=example\.com/, { timeout: 15000 });
    const row = page.getByTestId("scan-row").filter({ hasText: "example.com" });
    await expect(row.first()).toBeVisible({ timeout: 20000 });

    assertClean(issues);
  });
});
