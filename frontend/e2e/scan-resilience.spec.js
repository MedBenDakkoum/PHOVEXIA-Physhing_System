import { test, expect } from "@playwright/test";

const API = process.env.E2E_API_URL || "http://127.0.0.1:8080";
const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || "admin@test.com",
  password: process.env.E2E_ADMIN_PASSWORD || "AdminRealE2e!2026",
};
const SCAN_ID = "19846870-3336-4080-b507-69153a37fe98";
const FAILED_URL = "https://www.zara.com/tn/login";

test("scan échoué : aucune requête de capture et relance préremplie", async ({
  page,
  request,
}) => {
  test.setTimeout(60 * 1000);
  const login = await request.post(`${API}/api/auth/login/`, { data: ADMIN });
  expect(login.status(), await login.text()).toBe(200);
  const tokens = await login.json();

  const failed = {
    id: SCAN_ID,
    url: FAILED_URL,
    domain: "www.zara.com",
    mode: "full",
    status: "failed",
    verdict: null,
    score: null,
    detection_source: "model",
    model_version: "",
    final_url: "",
    partial: false,
    reason_code: "COLLECTOR_UNAVAILABLE",
    signals: {},
    probabilities: {},
    has_screenshot: false,
    created_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    has_report: false,
    report_status: null,
    reviewed_at: null,
  };

  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
  };
  let screenshotRequests = 0;
  await page.route(`**/api/scans/${SCAN_ID}/screenshot/`, (route) => {
    screenshotRequests += 1;
    return route.fulfill({ status: 404, headers: cors, body: "" });
  });
  await page.route(`**/api/scans/${SCAN_ID}/`, (route) => {
    if (route.request().method() === "OPTIONS") {
      return route.fulfill({ status: 204, headers: cors });
    }
    return route.fulfill({ status: 200, headers: cors, json: failed });
  });

  await page.goto("/login");
  await page.evaluate(
    ([access, refresh]) =>
      localStorage.setItem("pm.tokens", JSON.stringify({ access, refresh })),
    [tokens.access, tokens.refresh]
  );
  await page.goto(`/scans/${SCAN_ID}`);

  await expect(page.getByTestId("scan-failed-banner")).toContainText(
    "L'analyse a échoué"
  );
  await expect(page.getByTestId("scan-relaunch")).toContainText(
    "Relancer cette adresse"
  );
  await expect(page.getByText("Aucune capture n'est disponible")).toBeVisible();
  await expect(page.getByTestId("scan-relaunch")).toHaveAttribute(
    "href",
    `/scans/new?url=${encodeURIComponent(FAILED_URL)}`
  );

  await page.getByTestId("scan-relaunch").click();
  await expect(page).toHaveURL(/\/scans\/new\?url=/);
  await expect(page.getByTestId("scan-url")).toHaveValue(FAILED_URL);
  await expect(page.getByText("décompte 1 de votre quota")).toBeVisible();

  expect(screenshotRequests).toBe(0);
});
