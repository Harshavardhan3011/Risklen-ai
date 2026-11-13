import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import type { FullConfig } from "@playwright/test";

export default function globalSetup(_config: FullConfig) {
  const root = resolve(process.cwd(), "..");
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required for disposable browser fixtures.");
  const parsed = new URL(databaseUrl);
  if (!["127.0.0.1", "localhost", "::1"].includes(parsed.hostname) || parsed.port !== "55432" || parsed.pathname !== "/risklens_perf_test") {
    throw new Error("Browser fixture setup accepts only the isolated loopback risklens_perf_test database on port 55432.");
  }
  execFileSync(process.execPath, [resolve(root, "backend/node_modules/tsx/dist/cli.mjs"), "e2e/seed-browser.ts"], {
    cwd: resolve(root, "backend"), stdio: "inherit", env: { ...process.env, DATABASE_URL: databaseUrl, DIRECT_URL: databaseUrl },
  });
}
