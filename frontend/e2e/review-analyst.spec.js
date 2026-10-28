import { test, expect } from "@playwright/test";

const API = process.env.E2E_API_URL || "http://127.0.0.1:8080";
const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || "admin@test.com",
  password: process.env.E2E_ADMIN_PASSWORD || "AdminRealE2e!2026",
};
const USER = {
  email: process.env.E2E_USER_EMAIL || "e2e.analyst.user@example.com",
  password: process.env.E2E_USER_PASSWORD || "E2eReview!2026x",
};
const TARGET_URL = "https://example.com/";

const authHeaders = (token) => ({ Authorization: `Bearer ${token}` });

async function login(request, email, password) {
  const response = await request.post(`${API}/api/auth/login/`, {
    data: { email, password },
  });
  expect(response.status(), await response.text()).toBe(200);
  return response.json();
}

test.describe("FE-2 analyst review", () => {
  test("uncertain scan is decided, blocklisted, then immediately detected", async ({ page, request }) => {
    test.setTimeout(6 * 60 * 1000);

    const admin = await login(request, ADMIN.email, ADMIN.password);

    const blocked = await request.get(`${API}/api/blocklist/?q=example.com&page_size=100`, {
      headers: authHeaders(admin.access),
    });
    expect(blocked.status()).toBe(200);
    for (const entry of (await blocked.json()).results) {
      const removed = await request.delete(`${API}/api/blocklist/${entry.id}/`, {
        headers: authHeaders(admin.access),
        data: { reason: "E2E cleanup before review test" },
      });
      expect(removed.status(), `cleanup ${entry.domain}`).toBe(204);
    }

    const userLogin = await request.post(`${API}/api/auth/login/`, {
      data: { email: USER.email, password: USER.password },
    });
    let user;
    if (userLogin.status() === 200) {
      user = await userLogin.json();
    } else {
      expect(userLogin.status(), await userLogin.text()).toBe(401);
      const registered = await request.post(`${API}/api/auth/register/`, {
        data: { email: USER.email, password: USER.password, first_name: "E2E", last_name: "Review" },
      });
      expect([201, 400]).toContain(registered.status());
      user = await login(request, USER.email, USER.password);
    }

    const created = await request.post(`${API}/api/scans/`, {
      headers: authHeaders(user.access),
      data: { url: TARGET_URL },
    });
    expect(created.status(), await created.text()).toBe(202);
    const createdBody = await created.json();
    const scanId = createdBody.id;
    expect(scanId).toBeTruthy();

    let scan = null;
    for (let attempt = 0; attempt < 80; attempt += 1) {
      await page.waitForTimeout(3000);
      const response = await request.get(`${API}/api/scans/${scanId}/`, {
        headers: authHeaders(user.access),
      });
      expect(response.status()).toBe(200);
      scan = await response.json();
      if (["detected", "under_review", "failed"].includes(scan.status)) break;
    }

    expect(scan, "scan detail after polling").not.toBeNull();
    expect(scan.status, `unexpected scan status ${scan.status}`).not.toBe("failed");
    expect(["detected", "under_review"]).toContain(scan.status);

    if (!scan.has_report) {
      const reported = await request.post(`${API}/api/scans/${scanId}/report/`, {
        headers: authHeaders(user.access),
        data: { claimed_label: "phishing", comment: "E2E: verdict à vérifier par un analyste." },
      });
      expect(reported.status(), await reported.text()).toBe(201);
    }

    const reviewResponse = await request.get(`${API}/api/review/${scanId}/`, {
      headers: authHeaders(admin.access),
    });
    expect(reviewResponse.status()).toBe(200);
    const review = await reviewResponse.json();
    expect(review.status).toBe("under_review");
    expect(review.reported).toBe(true);

    await page.goto("/login");
    await page.getByRole("textbox", { name: "Adresse e-mail" }).fill(ADMIN.email);
    await page.getByRole("textbox", { name: "Mot de passe" }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Se connecter" }).click();
    await expect(page).toHaveURL(/\/app\/?$/);

    await page.goto("/review");
    await expect(page.getByRole("heading", { name: "File de revue" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Toutes les origines" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Incertain", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Signalé", exact: true })).toBeVisible();

    await page.goto(`/review/${scanId}`);
    await expect(page.getByRole("heading", { name: "Examen du cas" })).toBeVisible();
    const urlBox = page.locator(".url-box").first();
    await expect(urlBox).toContainText("example.com");
    await expect(urlBox.locator("a")).toHaveCount(0);

    await expect(page.getByRole("button", { name: "Confirmer phishing" })).toHaveAttribute(
      "aria-pressed",
      "true"
    );
    await page.getByRole("checkbox", { name: /Ajouter le domaine/ }).check();
    await page.getByLabel("Commentaire (optionnel)").fill("E2E: phishing confirmé, domaine bloqué.");
    await page.getByRole("button", { name: "Enregistrer la décision" }).click();
    const dialog = page.getByRole("dialog", { name: "Confirmer la décision ?" });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Enregistrer", exact: true }).click();
    await expect(
      page.getByText("Phishing confirmé et domaine ajouté à la blocklist.")
    ).toBeVisible({ timeout: 30000 });

    await page.goto("/blocklist");
    await expect(page.getByRole("heading", { name: "Blocklist" })).toBeVisible();
    await expect(page.locator("tr", { hasText: "example.com" }).first()).toBeVisible();

    await page.goto("/admin/brands");
    await expect(page.getByRole("heading", { name: "Marques protégées" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Ajouter une marque" }).first()).toBeVisible();

    const finalCreated = await request.post(`${API}/api/scans/`, {
      headers: authHeaders(user.access),
      data: { url: TARGET_URL },
    });
    expect(finalCreated.status(), await finalCreated.text()).toBe(202);
    const finalBody = await finalCreated.json();
    expect(finalBody.detection_source).toBe("blocklist");

    const finalDetail = await request.get(`${API}/api/scans/${finalBody.id}/`, {
      headers: authHeaders(user.access),
    });
    expect(finalDetail.status()).toBe(200);
    const finalScan = await finalDetail.json();
    expect(finalScan.verdict).toBe("phishing");
    expect(finalScan.detection_source).toBe("blocklist");
    expect(finalScan.score).toBe(1);

    const notifications = await request.get(`${API}/api/notifications/`, {
      headers: authHeaders(user.access),
    });
    expect(notifications.status()).toBe(200);
    const notificationsBody = await notifications.json();
    expect(notificationsBody.unread_count).toBeGreaterThan(0);
    expect(notificationsBody.results[0].message).toContain("example.com");

    await page.evaluate(
      ({ access, refresh }) => {
        localStorage.clear();
        localStorage.setItem("pm.tokens", JSON.stringify({ access, refresh }));
      },
      { access: user.access, refresh: user.refresh }
    );
    await page.goto("/notifications");
    await expect(page.getByRole("heading", { name: "Notifications" })).toBeVisible();
    const firstNotification = page.locator(".notif-item").first();
    await expect(firstNotification).toContainText("example.com");
    await expect(firstNotification).toContainText("Non lue");
    await firstNotification.getByRole("button", { name: "Marquer comme lue" }).click();
    await expect(page.locator(".notif-item").first()).not.toContainText("Non lue", {
      timeout: 15000,
    });
  });
});
