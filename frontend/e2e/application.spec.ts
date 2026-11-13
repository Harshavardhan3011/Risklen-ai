import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const analystEmail = "browser.analyst@risklens.test";
const adminEmail = "browser.admin@risklens.test";
const customerEmail = "browser.customer@risklens.test";
const password = process.env.RISKLEN_E2E_PASSWORD;
if (!password || password.length < 12) throw new Error("Set RISKLEN_E2E_PASSWORD for the disposable browser fixture accounts.");
const screenshots = resolve(process.cwd(), "../docs/frontend-browser-artifacts");

test("login, identity, routes, key workflows, access, errors, refresh and mobile", async ({ page }) => {
  const consoleErrors: string[] = [];
  const failedRequests: string[] = [];
  const httpErrors: Array<{ status: number; url: string }> = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  page.on("requestfailed", (request) => failedRequests.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText}`));
  page.on("response", (response) => { if (response.status() >= 400) httpErrors.push({ status: response.status(), url: response.url() }); });

  await page.goto("/login");
  await page.getByLabel("Email address").fill("invalid@risklens.test");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Sign-in failed");

  let releaseOverview!: () => void;
  const overviewGate = new Promise<void>((resolve) => { releaseOverview = resolve; });
  await page.route("**/api/overview", async (route) => { await overviewGate; await route.continue(); });
  await page.getByLabel("Email address").fill(analystEmail);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.locator(".chart-skeleton")).toBeVisible();
  const overviewResponse = page.waitForResponse((response) => response.url().includes("/api/overview") && response.status() === 200);
  releaseOverview();
  await overviewResponse;
  await page.unroute("**/api/overview");
  await expect(page.getByLabel(/Signed in as Test Analyst, browser\.analyst@risklens\.test, Analyst/)).toBeVisible();
  await expect(page.locator(".avatar")).toHaveText("TA");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Open alerts")).toBeVisible();
  await mkdir(screenshots, { recursive: true });
  await page.screenshot({ path: resolve(screenshots, "dashboard.png"), fullPage: true });

  let releaseInitialTransactions!: () => void;
  const initialTransactionsGate = new Promise<void>((resolve) => { releaseInitialTransactions = resolve; });
  await page.route("**/api/transactions**", async (route) => { await initialTransactionsGate; await route.continue(); });
  await page.goto("/transactions");
  await expect(page.getByLabel("Loading records")).toBeVisible();
  const initialTransactionsResponse = page.waitForResponse((response) => response.url().includes("/api/transactions") && response.status() === 200);
  releaseInitialTransactions();
  await initialTransactionsResponse;
  await page.unroute("**/api/transactions**");
  await expect(page.getByRole("heading", { name: "Transactions" })).toBeVisible();
  await expect(page.getByText("PW-TXN-2026-00000001")).toBeVisible();
  await expect(page.getByRole("button", { name: "Next page" })).toBeEnabled();
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.locator(".pagination div span").last()).toHaveText(/Page 2 of \d+/);
  await page.getByLabel("Transaction status").selectOption("POSTED");
  await expect(page.locator(".pagination div span").last()).toHaveText(/Page 1 of \d+/);
  await page.getByLabel("Search transactions").fill("PW-TXN-2026-00000001");
  await expect(page.getByText("PW-TXN-2026-00000001")).toBeVisible();
  await expect(page.getByText("Page 1 of 1")).toBeVisible();
  await page.goto("/transactions");
  const transactionResponse = page.waitForResponse((response) => response.url().includes("/api/transactions") && response.status() === 200);
  await page.reload();
  await transactionResponse;
  await expect(page.getByLabel(/Signed in as Test Analyst, browser\.analyst@risklens\.test, Analyst/)).toBeVisible();

  await page.goto("/alerts");
  await page.getByLabel("Search alerts").fill("PW-ALT-2026-000001");
  await expect(page.getByText("PW-ALT-2026-000001")).toBeVisible();
  await page.getByRole("row", { name: /PW-ALT-2026-000001/ }).getByRole("button", { name: "Review" }).click();
  await expect(page.getByRole("dialog")).toContainText("High-risk merchant category matched the synthetic rule.");
  await expect(page.getByRole("dialog")).toContainText("Browser fixture risk rule");
  await page.getByRole("button", { name: "Close alert details" }).click();

  await page.goto("/cases");
  await expect(page.getByText("PW-CASE-2026-000001")).toBeVisible();
  await page.getByRole("row", { name: /PW-CASE-2026-000001/ }).getByRole("button", { name: "View details" }).click();
  await expect(page.getByRole("dialog")).toContainText("Case history");
  await expect(page.getByRole("dialog")).toContainText("Created");
  await page.getByLabel("Case disposition").selectOption("FALSE_POSITIVE");
  await page.getByLabel("Analyst comment").fill("Synthetic browser verification disposition.");
  await page.getByRole("button", { name: "Record disposition" }).click();
  await expect(page.getByRole("dialog")).toContainText("False Positive");
  await expect(page.getByRole("dialog")).toContainText("Disposition Recorded");
  await expect(page.getByRole("dialog")).toContainText("Synthetic browser verification disposition.");
  await page.screenshot({ path: resolve(screenshots, "case-disposition-history.png"), fullPage: true });
  await page.getByRole("button", { name: "Close case details" }).click();

  const routeTitles: Array<[string, string]> = [
    ["/dashboard", "Dashboard"], ["/transactions", "Transactions"], ["/alerts", "Risk Alerts"],
    ["/cases", "Case Management"], ["/customers", "Customer Records"], ["/accounts", "Account Monitoring"],
    ["/analytics", "Risk Analytics"], ["/rules", "Risk Rules"], ["/data-generation", "Data Processing"],
    ["/validation", "Validation Results"], ["/audit", "Audit History"], ["/settings", "System Settings"],
  ];
  for (const [route, title] of routeTitles) {
    await page.goto(route);
    await expect(page.getByRole("heading", { name: title }).first()).toBeVisible();
    await page.waitForLoadState("networkidle");
    await expect(page.getByLabel(/Signed in as Test Analyst/)).toBeVisible();
  }
  await page.goto("/");
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.goto("/not-a-real-route");
  await expect(page.getByRole("heading", { name: "Page not found" }).first()).toBeVisible();
  await page.goto("/users");
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel("Email address").fill(adminEmail);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByLabel(/Signed in as Test Administrator, browser\.admin@risklens\.test, Admin/)).toBeVisible();
  await page.goto("/users");
  await expect(page.getByRole("heading", { name: "User Management" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();

  await page.getByLabel("Email address").fill(customerEmail);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByLabel(/Signed in as Test Customer, browser\.customer@risklens\.test, Customer/)).toBeVisible();
  await page.goto("/users");
  await expect(page).toHaveURL(/\/transactions$/);
  await expect(page.getByRole("navigation", { name: "Primary navigation" }).getByLabel("Dashboard")).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Primary navigation" }).getByLabel("Risk Alerts")).toHaveCount(0);
  await page.goto("/alerts");
  await expect(page).toHaveURL(/\/transactions$/);
  await page.goto("/accounts");
  await expect(page.getByText("PW-ACC-CUS-000001-01")).toBeVisible();
  await expect(page.getByText(/PW-ACC-CUS-OTHER/)).toHaveCount(0);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/transactions");
  await expect(page.getByRole("heading", { name: "Transactions" })).toBeVisible();
  await expect(page.locator(".sidebar")).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", await page.evaluate(() => document.documentElement.clientWidth));
  await page.screenshot({ path: resolve(screenshots, "transactions-mobile.png"), fullPage: true });
  await expect(page.locator(".sidebar").getByRole("button", { name: "Sign out" })).toBeVisible();
  await page.locator(".sidebar").getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  const mobileEmail = await page.getByLabel("Email address").boundingBox();
  expect(mobileEmail).not.toBeNull();
  expect(mobileEmail!.x + mobileEmail!.width).toBeLessThanOrEqual(390);
  await page.getByLabel("Email address").fill(analystEmail);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByLabel(/Signed in as Test Analyst/)).toBeVisible();
  await page.getByRole("navigation", { name: "Primary navigation" }).getByLabel("Dashboard").click();
  await expect(page).toHaveURL(/\/dashboard$/);

  await page.route("**/api/overview", (route) => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "synthetic browser error" }) }));
  await page.goto("/dashboard");
  await expect(page.getByRole("alert")).toContainText("Dashboard data could not be loaded");
  await page.screenshot({ path: resolve(screenshots, "dashboard-error-retry.png"), fullPage: true });
  await page.unroute("**/api/overview");
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("Open alerts")).toBeVisible();

  await page.locator(".sidebar").getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);

  const runtimeConsoleErrors = consoleErrors.filter((message) => !message.startsWith("Failed to load resource: the server responded with a status of"));
  expect(runtimeConsoleErrors, `Browser runtime console errors: ${runtimeConsoleErrors.join(" | ")}`).toEqual([]);
  const unexpectedFailedRequests = failedRequests.filter((failure) => !failure.includes("net::ERR_ABORTED"));
  expect(unexpectedFailedRequests, `Unexpected failed requests: ${unexpectedFailedRequests.join(" | ")}`).toEqual([]);
  const unexpectedHttpErrors = httpErrors.filter(({ status, url }) => !(
    (status === 401 && url.includes("/api/auth/login"))
    || (status === 403 && (url.includes("/api/users") || url.includes("/api/overview")))
    || (status === 503 && url.includes("/api/overview"))
    || (status === 404 && new URL(url).pathname === "/favicon.ico")
  ));
  expect(unexpectedHttpErrors, `Unexpected HTTP errors: ${JSON.stringify(unexpectedHttpErrors)}`).toEqual([]);
});
