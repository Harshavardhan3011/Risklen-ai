import { defineConfig } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "..");
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("Set DATABASE_URL to the isolated local risklens_perf_test database before running browser tests.");
const localJwtSecret = randomBytes(32).toString("hex");

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  globalSetup: resolve(root, "frontend/e2e/global-setup.ts"),
  use: { baseURL: "http://127.0.0.1:5173", browserName: "chromium", launchOptions: { channel: "chrome" }, screenshot: "only-on-failure", trace: "retain-on-failure" },
  webServer: [
    {
      command: "npm.cmd run dev",
      cwd: resolve(root, "backend"),
      url: "http://127.0.0.1:4000/health",
      reuseExistingServer: false,
      timeout: 120_000,
      env: { NODE_ENV: "development", DATABASE_MODE: "postgres", DATABASE_URL: databaseUrl, DIRECT_URL: databaseUrl, JWT_SECRET: localJwtSecret, FRONTEND_ORIGIN: "http://127.0.0.1:5173", PORT: "4000" },
    },
    {
      command: "npm.cmd run dev -- --host 127.0.0.1",
      cwd: resolve(root, "frontend"),
      url: "http://127.0.0.1:5173/login",
      reuseExistingServer: false,
      timeout: 120_000,
      env: { VITE_API_URL: "http://127.0.0.1:4000" },
    },
  ],
});
