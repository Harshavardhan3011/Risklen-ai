import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import bcrypt from "bcryptjs";
import { Prisma, PrismaClient } from "@prisma/client";
import request from "supertest";
import { test } from "node:test";
import { createPostgresApp } from "../src/postgres-server.js";

const databaseUrl = process.env.DATABASE_URL;
const enabled = process.env.RUN_POSTGRES_INTEGRATION_TESTS === "true";
const isDisposableLocalDatabase = (() => {
  if (!databaseUrl) return false;
  try {
    const url = new URL(databaseUrl);
    return ["127.0.0.1", "localhost", "::1"].includes(url.hostname)
      && url.port === "55432"
      && url.pathname === "/risklens_perf_test";
  } catch {
    return false;
  }
})();

test("PostgreSQL API integration, workflow, query, pagination, and cache checks", { skip: !databaseUrl || !enabled }, async (t) => {
  assert.equal(isDisposableLocalDatabase, true, "Integration tests require only the dedicated localhost risklens_perf_test database on port 55432.");
  process.env.JWT_SECRET = "risklens-local-postgres-integration-secret";
  process.env.FRONTEND_ORIGIN = "http://localhost:5173";
  const prisma = new PrismaClient();
  const app = await createPostgresApp();
  const suffix = randomUUID();
  const now = new Date();
  const earlier = new Date(now.getTime() - 60_000);
  const customerId = `IT-CUS-${suffix}`;
  const otherCustomerId = `IT-CUS-OTHER-${suffix}`;
  const customerEmail = `customer-${suffix}@integration.risklens.test`;
  const accountId = `IT-ACC-${suffix}`;
  const otherAccountId = `IT-ACC-OTHER-${suffix}`;
  const transactionIds = [0, 1, 2].map((index) => `IT-TXN-${index}-${suffix}`);
  const analystId = randomUUID();
  const adminId = randomUUID();
  const reviewerId = randomUUID();
  const customerUserId = randomUUID();
  const merchantId = `IT-MER-${suffix}`;
  const ruleHighMerchantId = randomUUID();
  const ruleOtherId = randomUUID();
  const password = "RiskLens integration password 2026!";
  const passwordHash = bcrypt.hashSync(password, 4);
  const fixturePrefix = `it-${suffix}`;

  async function createUser(id: string, email: string, name: string, role: "ADMIN" | "ANALYST" | "COMPLIANCE_REVIEWER" | "CUSTOMER") {
    return prisma.user.create({ data: { id, email, name, role, status: "ACTIVE", passwordHash } });
  }
  async function login(email: string) {
    const response = await request(app).post("/api/auth/login").send({ email, password });
    assert.equal(response.status, 200, `login failed for ${email}: ${JSON.stringify(response.body)}`);
    assert.equal(typeof response.body.token, "string");
    return response.body.token as string;
  }
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  const benchmark: Record<string, { coldMs: number; warmMedianMs: number; warmP95Ms: number; status: number; payloadBytes: number }> = {};
  async function measure(name: string, run: () => Promise<request.Response>) {
    const times: number[] = [];
    let last: request.Response | undefined;
    for (let index = 0; index < 6; index += 1) {
      const start = performance.now();
      last = await run();
      times.push(performance.now() - start);
      assert.ok(last.status < 500, `${name} returned ${last.status}: ${JSON.stringify(last.body)}`);
      assert.equal(last.status, 200, `${name} must return 200`);
    }
    const warm = times.slice(1).sort((a, b) => a - b);
    benchmark[name] = {
      coldMs: Number(times[0].toFixed(2)),
      warmMedianMs: Number(median(warm).toFixed(2)),
      warmP95Ms: Number(warm[Math.min(warm.length - 1, Math.ceil(warm.length * 0.95) - 1)].toFixed(2)),
      status: last.status,
      payloadBytes: Buffer.byteLength(JSON.stringify(last.body)),
    };
    return last;
  }

  try {
    await Promise.all([
      createUser(analystId, `analyst-${suffix}@integration.risklens.test`, "Integration Analyst", "ANALYST"),
      createUser(adminId, `admin-${suffix}@integration.risklens.test`, "Integration Administrator", "ADMIN"),
      createUser(reviewerId, `reviewer-${suffix}@integration.risklens.test`, "Integration Reviewer", "COMPLIANCE_REVIEWER"),
      createUser(customerUserId, customerEmail, "Integration Customer User", "CUSTOMER"),
    ]);
    await prisma.customer.createMany({ data: [
      { id: customerId, fullName: `Integration Customer ${suffix}`, email: customerEmail, countryCode: "US" },
      { id: otherCustomerId, fullName: `Other Integration Customer ${suffix}`, email: `other-${suffix}@integration.risklens.test`, countryCode: "CA" },
    ] });
    await prisma.kYCProfile.create({ data: { id: randomUUID(), customerId, status: "VERIFIED", riskRating: "LOW", sourceReference: fixturePrefix } });
    await prisma.account.createMany({ data: [
      { id: accountId, accountType: "CHECKING", status: "OPEN", currency: "USD", currentBalance: new Prisma.Decimal("900.00"), overdraftLimit: new Prisma.Decimal("0.00"), openedAt: earlier },
      { id: otherAccountId, accountType: "SAVINGS", status: "OPEN", currency: "USD", currentBalance: new Prisma.Decimal("500.00"), overdraftLimit: new Prisma.Decimal("0.00"), openedAt: earlier },
    ] });
    await prisma.accountOwner.createMany({ data: [
      { accountId, customerId, ownershipType: "PRIMARY", effectiveFrom: earlier },
      { accountId: otherAccountId, customerId: otherCustomerId, ownershipType: "PRIMARY", effectiveFrom: earlier },
    ] });
    await prisma.merchant.create({ data: { id: merchantId, name: "Integration High-Risk Merchant", categoryCode: "7995", countryCode: "US", riskRating: "HIGH" } });
    await prisma.riskRule.createMany({ data: [
      { id: ruleHighMerchantId, ruleCode: `IT-R008-${suffix}`, version: 1, name: "Integration high-risk merchant", description: "PostgreSQL integration rule.", severity: "HIGH", weight: 35, enabled: true, effectiveFrom: earlier },
      { id: ruleOtherId, ruleCode: `IT-R001-${suffix}`, version: 1, name: "Integration duplicate check", description: "PostgreSQL duplicate-alert rule.", severity: "MEDIUM", weight: 20, enabled: true, effectiveFrom: earlier },
    ] });
    await prisma.transaction.createMany({ data: [
      { id: transactionIds[0], customerId, accountId, merchantId, transactionType: "DEBIT", status: "POSTED", amount: new Prisma.Decimal("100.00"), balanceBefore: new Prisma.Decimal("1000.00"), balanceAfter: new Prisma.Decimal("900.00"), currency: "USD", occurredAt: now, postedAt: now, reference: `${fixturePrefix}-0` },
      { id: transactionIds[1], customerId, accountId, transactionType: "DEBIT", status: "POSTED", amount: new Prisma.Decimal("50.00"), balanceBefore: new Prisma.Decimal("950.00"), balanceAfter: new Prisma.Decimal("900.00"), currency: "USD", occurredAt: earlier, postedAt: earlier, reference: `${fixturePrefix}-1` },
      { id: transactionIds[2], customerId: otherCustomerId, accountId: otherAccountId, transactionType: "CREDIT", status: "POSTED", amount: new Prisma.Decimal("25.00"), balanceBefore: new Prisma.Decimal("475.00"), balanceAfter: new Prisma.Decimal("500.00"), currency: "USD", occurredAt: earlier, postedAt: earlier, reference: `${fixturePrefix}-2` },
    ] });
    await prisma.groundTruthLabel.createMany({ data: [
      { id: randomUUID(), transactionId: transactionIds[0], customerId, scenarioCode: `${fixturePrefix}-positive`, isSuspicious: true, expectedRuleCode: `IT-R008-${suffix}`, labelSource: "integration-fixture" },
      { id: randomUUID(), transactionId: transactionIds[1], customerId, scenarioCode: `${fixturePrefix}-false-positive`, isSuspicious: false, labelSource: "integration-fixture" },
      { id: randomUUID(), transactionId: transactionIds[2], customerId: otherCustomerId, scenarioCode: `${fixturePrefix}-negative`, isSuspicious: false, labelSource: "integration-fixture" },
    ] });
    await prisma.alert.createMany({ data: [
      { id: `IT-ALT-FP-${suffix}`, customerId, accountId, transactionId: transactionIds[1], riskRuleId: ruleOtherId, evaluationVersion: `${fixturePrefix}-fp`, riskScore: 20, priority: "MEDIUM", status: "OPEN", explanation: "Integration false positive.", detectedAt: now },
      { id: `IT-ALT-DUP-${suffix}`, customerId, accountId, transactionId: transactionIds[0], riskRuleId: ruleHighMerchantId, evaluationVersion: `${fixturePrefix}-duplicate`, riskScore: 35, priority: "HIGH", status: "OPEN", explanation: "Duplicate prediction fixture.", detectedAt: now },
    ] });
    await prisma.alertEvent.create({ data: { alertId: `IT-ALT-FP-${suffix}`, actorId: analystId, eventType: "CREATED", details: { source: "integration-test" } } });
    const generationRun = await prisma.generationRun.create({ data: { id: randomUUID(), seed: BigInt(20261022), scale: "integration", status: "COMPLETED", startedAt: earlier, completedAt: now, metadata: { fixture: fixturePrefix } } });
    await prisma.validationResult.create({ data: { id: randomUUID(), generationRunId: generationRun.id, checkName: fixturePrefix, status: "PASSED", message: "Integration result", details: { fixture: fixturePrefix } } });

    const analystToken = await login(`analyst-${suffix}@integration.risklens.test`);
    const adminToken = await login(`admin-${suffix}@integration.risklens.test`);
    const reviewerToken = await login(`reviewer-${suffix}@integration.risklens.test`);
    const customerToken = await login(customerEmail);
    const analyst = { Authorization: `Bearer ${analystToken}` };
    const admin = { Authorization: `Bearer ${adminToken}` };
    const reviewer = { Authorization: `Bearer ${reviewerToken}` };
    const customer = { Authorization: `Bearer ${customerToken}` };

    const health = await request(app).get("/health");
    assert.equal(health.status, 200);
    const me = await request(app).get("/api/auth/me").set(analyst);
    assert.equal(me.status, 200);
    assert.equal(me.body.user.name, "Integration Analyst");
    assert.equal("passwordHash" in me.body.user, false);
    assert.equal((await request(app).get("/api/auth/me").set({ Authorization: "Bearer invalid" })).status, 401);
    assert.equal((await request(app).get("/api/users").set(analyst)).status, 403);
    assert.equal((await request(app).get("/api/users").set(admin).query({ page: 1, pageSize: 2 })).status, 200);

    const assessment = await request(app).post(`/api/risk/assess/${transactionIds[0]}`).set(analyst).send({ createCase: true, assignedToId: reviewerId });
    assert.equal(assessment.status, 200, JSON.stringify(assessment.body));
    assert.equal(assessment.body.assessment.findings.some((finding: { ruleCode: string }) => finding.ruleCode === "R008"), true);
    assert.equal(assessment.body.persisted.alertIds.length, 1);
    const generatedAlertId = assessment.body.persisted.alertIds[0] as string;
    const generatedCaseId = assessment.body.persisted.caseId as string;
    const alertDetail = await request(app).get(`/api/alerts/${generatedAlertId}`).set(analyst);
    assert.equal(alertDetail.status, 200);
    assert.equal(alertDetail.body.evidence.length, 1);
    assert.equal(alertDetail.body.cases[0].id, generatedCaseId);
    assert.equal(alertDetail.body.alert.riskRule.ruleCode, "R008");

    const alertSearch = await request(app).get("/api/alerts").set(analyst).query({ search: generatedAlertId, page: 1, pageSize: 1, status: "OPEN" });
    assert.equal(alertSearch.status, 200);
    assert.equal(alertSearch.body.total, 1);
    assert.equal(alertSearch.body.data[0].id, generatedAlertId);
    const alertBoundary = await request(app).get("/api/alerts").set(analyst).query({ search: generatedAlertId, page: 2, pageSize: 1 });
    assert.equal(alertBoundary.status, 200);
    assert.equal(alertBoundary.body.total, 1);
    assert.equal(alertBoundary.body.data.length, 0);
    const customerSearch = await request(app).get("/api/customers").set(analyst).query({ search: customerId, page: 1, pageSize: 1 });
    assert.equal(customerSearch.status, 200);
    assert.equal(customerSearch.body.total, 1);
    assert.equal(customerSearch.body.data[0].kycProfile.status, "VERIFIED");
    const accountSearch = await request(app).get("/api/accounts").set(analyst).query({ search: accountId, page: 1, pageSize: 1 });
    assert.equal(accountSearch.status, 200);
    assert.equal(accountSearch.body.total, 1);
    const transactionSearch = await request(app).get("/api/transactions").set(analyst).query({ search: transactionIds[0], page: 1, pageSize: 1 });
    assert.equal(transactionSearch.status, 200);
    assert.equal(transactionSearch.body.total, 1);
    assert.equal(transactionSearch.body.data[0].id, transactionIds[0]);
    assert.equal((await request(app).get("/api/transactions").set(analyst).query({ search: transactionIds[0], page: 2, pageSize: 1 })).body.data.length, 0);

    const customerRows = await request(app).get("/api/customers").set(customer).query({ page: 1, pageSize: 10 });
    assert.equal(customerRows.status, 200);
    assert.equal(customerRows.body.total, 1);
    assert.equal(customerRows.body.data[0].id, customerId);
    assert.equal((await request(app).get(`/api/customers/${otherCustomerId}`).set(customer)).status, 403);
    const ownedAccounts = await request(app).get("/api/accounts").set(customer);
    assert.equal(ownedAccounts.status, 200);
    assert.deepEqual(ownedAccounts.body.data.map((row: { id: string }) => row.id), [accountId]);
    assert.equal((await request(app).get(`/api/accounts/${otherAccountId}`).set(customer)).status, 404);
    const ownedTransactions = await request(app).get("/api/transactions").set(customer);
    assert.equal(ownedTransactions.status, 200);
    assert.ok(ownedTransactions.body.data.every((row: { customerId: string }) => row.customerId === customerId));
    assert.equal((await request(app).get("/api/alerts").set(customer)).status, 403);

    const cases = await request(app).get("/api/cases").set(analyst).query({ page: 1, pageSize: 1 });
    assert.equal(cases.status, 200);
    assert.ok(cases.body.total >= 201);
    assert.equal(cases.body.data.length, 1);
    assert.equal(cases.body.data[0].id, generatedCaseId);
    assert.equal(cases.body.data[0].caseAlerts.length, 1);
    const rules = await request(app).get("/api/rules").set(analyst).query({ page: 1, pageSize: 1 });
    assert.equal(rules.status, 200);
    assert.equal(rules.body.data.length, 1);
    assert.match(rules.body.data[0].ruleCode, /^IT-R001-/);
    assert.equal((await request(app).get("/api/validation").set(analyst).query({ page: 1, pageSize: 1 })).status, 200);
    assert.equal((await request(app).get("/api/generation-runs").set(analyst).query({ page: 1, pageSize: 1 })).status, 200);
    assert.equal((await request(app).get("/api/audit").set(reviewer).query({ page: 1, pageSize: 5 })).status, 200);

    const overview = await request(app).get("/api/overview").set(analyst);
    assert.equal(overview.status, 200);
    assert.ok(overview.body.evaluation.truePositives >= 820);
    assert.equal("scenarioCode" in overview.body, false);
    const cached = await prisma.evaluationMetricCache.findUnique({ where: { singleton: true } });
    assert.ok(cached?.payload);
    const cachedRevision = cached!.revision;
    await prisma.alert.create({ data: { id: `IT-ALT-NEW-FP-${suffix}`, customerId: otherCustomerId, accountId: otherAccountId, transactionId: transactionIds[2], riskRuleId: ruleOtherId, evaluationVersion: `${fixturePrefix}-new-fp`, riskScore: 20, priority: "MEDIUM", status: "OPEN", explanation: "Cache invalidation fixture.", detectedAt: now } });
    const invalidated = await prisma.evaluationMetricCache.findUnique({ where: { singleton: true } });
    assert.ok(invalidated);
    assert.ok(invalidated.revision > cachedRevision);
    assert.equal(invalidated.payload, null);
    const updatedOverview = await request(app).get("/api/overview").set(analyst);
    assert.equal(updatedOverview.status, 200);
    assert.equal(updatedOverview.body.evaluation.falsePositives, overview.body.evaluation.falsePositives + 1);
    assert.equal((await prisma.evaluationMetricCache.findUnique({ where: { singleton: true } }))?.payload != null, true);

    const disposition = await request(app).post(`/api/cases/${generatedCaseId}/disposition`).set(analyst).send({ disposition: "FALSE_POSITIVE", comment: "Verified as legitimate activity." });
    assert.equal(disposition.status, 200, JSON.stringify(disposition.body));
    assert.equal(disposition.body.case.status, "CLOSED");
    const [persistedAction, caseHistory, alertHistory, auditHistory, currentAlert, currentCases] = await Promise.all([
      prisma.analystAction.findFirst({ where: { caseId: generatedCaseId, actionType: "DISPOSITION_RECORDED" } }),
      prisma.caseEvent.findMany({ where: { caseId: generatedCaseId }, orderBy: { occurredAt: "asc" } }),
      prisma.alertEvent.findMany({ where: { alertId: generatedAlertId }, orderBy: { occurredAt: "asc" } }),
      prisma.auditEvent.findMany({ where: { entityId: { in: [generatedCaseId, generatedAlertId] } } }),
      prisma.alert.findUnique({ where: { id: generatedAlertId } }),
      request(app).get("/api/cases").set(analyst).query({ page: 1, pageSize: 1 }),
    ]);
    assert.equal(persistedAction?.disposition, "FALSE_POSITIVE");
    assert.ok(caseHistory.some((event) => event.eventType === "CREATED"));
    assert.ok(caseHistory.some((event) => event.eventType === "DISPOSITION_RECORDED"));
    assert.ok(alertHistory.some((event) => event.eventType === "CREATED"));
    assert.ok(alertHistory.some((event) => event.eventType === "STATUS_CHANGED"));
    assert.ok(auditHistory.length >= 2);
    assert.equal(currentAlert?.status, "CLOSED");
    assert.equal(currentCases.body.data[0].status, "CLOSED");
    assert.equal((await request(app).get(`/api/alerts/${generatedAlertId}`).set(analyst)).body.alert.status, "CLOSED");

    await measure("login", () => request(app).post("/api/auth/login").send({ email: `analyst-${suffix}@integration.risklens.test`, password }));
    await measure("auth_me", () => request(app).get("/api/auth/me").set(analyst));
    await measure("overview", () => request(app).get("/api/overview").set(analyst));
    await measure("alerts", () => request(app).get("/api/alerts?page=1&pageSize=25").set(analyst));
    await measure("transactions", () => request(app).get("/api/transactions?page=1&pageSize=25").set(analyst));
    await measure("cases", () => request(app).get("/api/cases?page=1&pageSize=25").set(analyst));
    await measure("customers", () => request(app).get("/api/customers?page=1&pageSize=25").set(analyst));
    await measure("accounts", () => request(app).get("/api/accounts?page=1&pageSize=25").set(analyst));
    await measure("rules", () => request(app).get("/api/rules?page=1&pageSize=25").set(analyst));
    await measure("validation", () => request(app).get("/api/validation?page=1&pageSize=25").set(analyst));
    await measure("generation_runs", () => request(app).get("/api/generation-runs?page=1&pageSize=25").set(analyst));
    await measure("audit", () => request(app).get("/api/audit?page=1&pageSize=25").set(analyst));
    console.log(`POSTGRES_LOCAL_BENCHMARK=${JSON.stringify({ generatedRows: { customers: 5000, accounts: 7000, transactions: 100000, alerts: 1000, casesBeforeFixture: 200, groundTruthLabels: 100000 }, measurements: benchmark })}`);
    t.diagnostic("Fixtures are intentionally retained in the disposable database because append-only event triggers prohibit deleting event history.");
  } finally {
    await prisma.$disconnect();
  }
});
