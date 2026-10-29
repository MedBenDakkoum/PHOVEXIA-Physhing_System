import { test, expect } from "@playwright/test";

const APP = process.env.E2E_APP_URL || "http://127.0.0.1:5173";
const API = process.env.E2E_API_URL || "http://127.0.0.1:8080";

/** Collecte pageerror (exceptions JS), erreurs console et réponses HTTP >= 400. */
function watch(page) {
  const issues = { pageErrors: [], consoleErrors: [], http: [] };
  page.on("pageerror", (e) => issues.pageErrors.push(String(e)));
  page.on("console", (m) => {
    if (m.type() === "error") issues.consoleErrors.push(m.text());
  });
  page.on("response", (r) => {
    if (r.status() >= 400) issues.http.push(`${r.status()} ${r.url()}`);
  });
  return issues;
}

async function login(page, email, password) {
  await page.goto(`${APP}/login`);
  await page.fill('input[name="email"]', email);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/app/, { timeout: 15000 });
}

test("admin dashboard renders without JS error nor 404", async ({ page }) => {
  const issues = watch(page);
  await login(page, "admin@test.com", "AdminRealE2e!2026");
  await expect(page.locator(".command-title")).toContainText("admin", { timeout: 15000 });
  await expect(page.locator(".command-meta .badge")).toContainText("Administrateur");
  await expect(page.locator(".kpi").first()).toBeVisible({ timeout: 15000 });

  expect(issues.pageErrors).toEqual([]);
  expect(issues.http.filter((h) => h.includes("/api/api/"))).toEqual([]);
  expect(issues.http).toEqual([]);
  expect(issues.consoleErrors).toEqual([]);
});

test("end_user dashboard renders (ROLE_META end_user)", async ({ page, context }) => {
  const email = `e2e-front-${Date.now()}@test.com`;
  const reg = await context.request.post(`${API}/api/auth/register/`, {
    data: { email, password: "E2eFront!2026", first_name: "Front", last_name: "E2E" },
  });
  expect(reg.status()).toBe(201);

  const issues = watch(page);
  await login(page, email, "E2eFront!2026");
  await expect(page.locator(".command-title")).toContainText("Front", { timeout: 15000 });
  // Vue "Votre compte" (MemberOverview) : la description du rôle end_user existe
  await expect(page.locator('section[aria-label="Votre compte"] .card-sub')).toContainText(
    "Vérifie ses liens",
    { timeout: 15000 }
  );
  await expect(page.locator(".command-meta .badge")).toContainText("Utilisateur");

  expect(issues.pageErrors).toEqual([]);
  expect(issues.http.filter((h) => h.includes("/api/api/"))).toEqual([]);
  expect(issues.http).toEqual([]);
  expect(issues.consoleErrors).toEqual([]);
});

test("no request goes to the double /api/api/ prefix", async ({ page }) => {
  const paths = [];
  page.on("request", (r) => paths.push(new URL(r.url()).pathname));
  await page.goto(`${APP}/login`);
  await page.waitForLoadState("networkidle");
  expect(paths.filter((p) => p.startsWith("/api/api/"))).toEqual([]);
});
