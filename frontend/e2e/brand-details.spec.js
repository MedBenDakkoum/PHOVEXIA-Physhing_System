import path from "node:path";
import { test, expect } from "@playwright/test";

const API = process.env.E2E_API_URL || "http://127.0.0.1:8080";
const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL,
  password: process.env.E2E_ADMIN_PASSWORD,
};
const TERMINAL = new Set([
  "detected",
  "under_review",
  "confirmed",
  "false_positive",
  "blocked",
  "failed",
]);
const EVIDENCE = path.resolve(process.cwd(), "..", "docs", "evidence");

async function loginApi(request) {
  const response = await request.post(`${API}/api/auth/login/`, {
    data: { email: ADMIN.email, password: ADMIN.password },
  });
  expect(response.status(), await response.text()).toBe(200);
  const body = await response.json();
  return body.access;
}

async function createScan(request, access, url) {
  const response = await request.post(`${API}/api/scans/`, {
    headers: { Authorization: `Bearer ${access}` },
    data: { url },
  });
  expect(response.status(), await response.text()).toBe(202);
  return (await response.json()).id;
}

async function waitForTerminal(request, access, id) {
  const deadline = Date.now() + 6 * 60 * 1000;
  while (Date.now() < deadline) {
    const response = await request.get(`${API}/api/scans/${id}/`, {
      headers: { Authorization: `Bearer ${access}` },
    });
    expect(response.status(), await response.text()).toBe(200);
    const scan = await response.json();
    if (TERMINAL.has(scan.status)) return scan;
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`Scan ${id} did not reach a terminal status in 6 minutes`);
}

async function loginUi(page) {
  await page.goto("/login");
  await page.fill('input[name="email"]', ADMIN.email);
  await page.fill('input[name="password"]', ADMIN.password);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/app\/?$/, { timeout: 20000 });
}

test.describe("explication de la règle de marque", () => {
  test.beforeEach(() => {
    test.skip(!ADMIN.email || !ADMIN.password, "E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD are required");
  });

  test("google.com : bouton Détails, popup accessible, Échap et Fermer", async ({ page, request }) => {
    test.setTimeout(8 * 60 * 1000);
    const access = await loginApi(request);
    const id = await createScan(request, access, "https://google.com/");
    const scan = await waitForTerminal(request, access, id);

    expect(scan.status).toBe("detected");
    expect(scan.partial).toBe(false);
    expect(scan.policy_flags.map((flag) => flag.code)).toContain("OFFICIAL_BRAND_HOMEPAGE");

    await page.setViewportSize({ width: 1280, height: 900 });
    await loginUi(page);
    await page.goto(`/scans/${id}`);

    const card = page.getByTestId("probability-bars");
    const open = card.getByTestId("brand-details-open");
    await expect(open).toBeVisible({ timeout: 20000 });
    await expect(card.locator(".card-head")).toContainText("Détails");

    await open.click();
    const dialog = page.getByTestId("brand-explanation-dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute("aria-labelledby", "brand-explain-title");
    await expect(dialog.getByRole("heading", { name: "Pourquoi ce verdict ?" })).toBeVisible();
    await expect(dialog).toContainText("page d'accueil officielle de google.com");
    await expect(dialog).toContainText("Notre IA a appris sur un jeu de données");
    await expect(dialog).toContainText("Nous avons ajouté une vérification du nom de domaine officiel");
    await expect(dialog).toContainText("Verdict final :");
    await expect(dialog).toContainText("Modèle seul :");
    await expect(dialog.getByTestId("brand-explanation-close")).toBeVisible();

    await dialog.screenshot({ path: path.join(EVIDENCE, "brand_details_popup_1280.png") });

    await page.setViewportSize({ width: 360, height: 740 });
    await expect(dialog).toBeVisible();
    await dialog.screenshot({ path: path.join(EVIDENCE, "brand_details_popup_360.png") });

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(open).toBeFocused();

    await page.setViewportSize({ width: 1280, height: 900 });
    await open.click();
    await expect(dialog).toBeVisible();
    await dialog.getByTestId("brand-explanation-close").click();
    await expect(dialog).toBeHidden();
    await expect(open).toBeFocused();
  });

  test("github.com : aucun bouton Détails, historique et dashboard inchangés", async ({ page, request }) => {
    test.setTimeout(8 * 60 * 1000);
    const access = await loginApi(request);
    const id = await createScan(request, access, "https://github.com/");
    const scan = await waitForTerminal(request, access, id);
    expect(scan.policy_flags).toEqual([]);

    await loginUi(page);
    await page.goto(`/scans/${id}`);
    await expect(page.getByTestId("probability-bars")).toBeVisible({ timeout: 20000 });
    await expect(page.getByTestId("brand-details-open")).toHaveCount(0);
    await expect(page.getByTestId("brand-explanation-dialog")).toHaveCount(0);

    await page.goto("/scans");
    await expect(page.getByTestId("scan-row").first()).toBeVisible({ timeout: 20000 });
    await expect(page.getByTestId("brand-details-open")).toHaveCount(0);

    await page.goto("/app");
    await expect(page.locator(".command-title")).toBeVisible({ timeout: 20000 });
    await expect(page.getByTestId("brand-details-open")).toHaveCount(0);

    await page.goto("/");
    await expect(page.getByTestId("quick-check-url")).toBeVisible();
    await expect(page.getByTestId("brand-details-open")).toHaveCount(0);
  });
});
