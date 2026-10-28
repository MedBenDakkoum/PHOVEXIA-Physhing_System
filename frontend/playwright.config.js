import { defineConfig, devices } from "@playwright/test";

const API_URL = process.env.E2E_API_URL || "http://127.0.0.1:8080";
const APP_URL = process.env.E2E_APP_URL || "http://127.0.0.1:5173";

export default defineConfig({
  testDir: "./e2e",
  timeout: 6 * 60 * 1000,
  expect: { timeout: 20 * 1000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: "reports/playwright", open: "never" }],
  ],
  use: {
    baseURL: APP_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5173",
    url: APP_URL,
    reuseExistingServer: true,
    timeout: 120 * 1000,
    env: { VITE_BACKEND_URL: API_URL },
  },
});
