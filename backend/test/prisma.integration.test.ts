import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import request from "supertest";
import { test } from "node:test";
import { PrismaClient, Prisma } from "@prisma/client";
import { createPostgresApp } from "../src/postgres-server.js";

const databaseUrl = process.env.DATABASE_URL;
const postgresIntegrationEnabled = process.env.RUN_POSTGRES_INTEGRATION_TESTS === "true";
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

function previousEvaluationMetrics(
  labels: Array<{ transactionId: string; scenarioCode: string; isSuspicious: boolean; expectedRuleCode: string | null }>,
  alerts: Array<{ id: string; transactionId: string; riskRule: { ruleCode: string } }>,
  evidenceAlerts: Array<{ alertId: string }>,
  validationTotals: Array<{ status: string; _count: { _all: number } }>,
  latestRun: { startedAt: Date; completedAt: Date | null } | null,
) {
  const positiveTransactions = new Set(labels.filter(label => label.isSuspicious).map(label => label.transactionId));
  const universe = new Set(labels.map(label => label.transactionId));
  const predictedTransactions = new Set(alerts.map(alert => alert.transactionId).filter(id => universe.has(id)));
  const tp = [...predictedTransactions].filter(id => positiveTransactions.has(id)).length;
  const fp = [...predictedTransactions].filter(id => !positiveTransactions.has(id)).length;
  const fn = [...positiveTransactions].filter(id => !predictedTransactions.has(id)).length;
  const tn = Math.max(0, universe.size - tp - fp - fn);
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const evidenceAlertIds = new Set(evidenceAlerts.map(item => item.alertId));
  const evaluatedAlerts = alerts.filter(alert => universe.has(alert.transactionId));
  const ruleMetrics = [...new Set(labels.map(label => label.expectedRuleCode).filter((code): code is string => Boolean(code)))].map(ruleCode => {
    const expected = new Set(labels.filter(label => label.expectedRuleCode === ruleCode && label.isSuspicious).map(label => label.transactionId));
    const predicted = new Set(evaluatedAlerts.filter(alert => alert.riskRule.ruleCode === ruleCode).map(alert => alert.transactionId));
    const ruleTp = [...predicted].filter(id => expected.has(id)).length;
    const ruleFp = [...predicted].filter(id => !expected.has(id)).length;
    const ruleFn = [...expected].filter(id => !predicted.has(id)).length;
    return { ruleCode, precision: ruleTp + ruleFp ? ruleTp / (ruleTp + ruleFp) : 0, recall: ruleTp + ruleFn ? ruleTp / (ruleTp + ruleFn) : 0 };
  });
  const scenarioCoverage = Object.fromEntries([...new Set(labels.map(label => label.scenarioCode))].map(scenarioCode => {
    const expected = labels.filter(label => label.scenarioCode === scenarioCode && label.isSuspicious);
    const found = expected.filter(label => predictedTransactions.has(label.transactionId));
    return [scenarioCode, expected.length ? found.length / expected.length : 1];
  }));
  const validationTotal = validationTotals.reduce((total, item) => total + item._count._all, 0);
  const validationPassed = validationTotals.find(item => item.status === "PASSED")?._count._all ?? 0;
  const processingTimeSeconds = latestRun?.completedAt ? (latestRun.completedAt.getTime() - latestRun.startedAt.getTime()) / 1000 : null;
  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    f1,
    falsePositiveRate: fp + tn ? fp / (fp + tn) : 0,
    ruleMetrics,
    scenarioCoverage,
    alertsPer1000Transactions: universe.size ? (predictedTransactions.size / universe.size) * 1000 : 0,
    processingTimeSeconds,
    evaluationUnit: "transaction ID within the ground-truth universe; duplicate alerts count once",
    matchingMethodology: "Exact alert.transactionId to evaluation.ground_truth_labels.transactionId matching; labels are never returned by operational APIs.",
    evidenceCompleteness: evaluatedAlerts.length ? evaluatedAlerts.filter(alert => evidenceAlertIds.has(alert.id)).length / evaluatedAlerts.length : 0,
    validationPassRate: validationTotal ? validationPassed / validationTotal : 0,
  };
}

test("Prisma PostgreSQL integration checks", { skip: !databaseUrl || !postgresIntegrationEnabled }, async () => {
  assert.equal(isDisposableLocalDatabase, true, "PostgreSQL integration tests require only the dedicated localhost risklens_perf_test database on port 55432.");
  const prisma = new PrismaClient();
  const customerId = `TEST-CUS-${Date.now()}`;
  const accountId = `TEST-ACC-${Date.now()}`;
  const eventTime = new Date("2026-01-01T00:00:00.000Z");

  try {
    await prisma.customer.create({ data: { id: customerId, fullName: "Schema Test Customer", countryCode: "US" } });
    await prisma.account.create({
      data: {
        id: accountId,
        accountType: "CHECKING",
        status: "OPEN",
        currency: "USD",
        currentBalance: new Prisma.Decimal("100.00"),
        overdraftLimit: new Prisma.Decimal("0.00"),
        openedAt: eventTime,
        owners: { create: { customerId, ownershipType: "PRIMARY", effectiveFrom: eventTime } },
      },
    });
    const transaction = await prisma.transaction.create({
      data: {
        id: `TEST-TXN-${Date.now()}`,
        customerId,
        accountId,
        transactionType: "CREDIT",
        status: "POSTED",
        amount: new Prisma.Decimal("0.10"),
        balanceBefore: new Prisma.Decimal("100.00"),
        balanceAfter: new Prisma.Decimal("100.10"),
        currency: "USD",
        occurredAt: eventTime,
      },
    });
    assert.equal(transaction.amount.toFixed(2), "0.10");
    const first = await prisma.accountEvent.create({ data: { accountId, eventType: "CREATED", occurredAt: eventTime } });
    const second = await prisma.accountEvent.create({ data: { accountId, eventType: "BALANCE_ADJUSTED", occurredAt: new Date("2026-01-02T00:00:00.000Z") } });
    assert.notEqual(first.id, second.id);
    await assert.rejects(() => prisma.accountOwner.create({ data: { accountId: `missing-${Date.now()}`, customerId, ownershipType: "INVALID", effectiveFrom: eventTime } }));
  } finally {
    // Account events are append-only; this entire guarded database is disposable.
    await prisma.$disconnect();
  }
});

test("PostgreSQL administrator recovery is one-time, atomic, and audited", { skip: !databaseUrl || !postgresIntegrationEnabled }, async () => {
  assert.equal(isDisposableLocalDatabase, true, "Recovery integration tests require only the dedicated localhost risklens_perf_test database on port 55432.");
  const originalRecoverySecret = process.env.ADMIN_RECOVERY_SECRET;
  const originalRecoveryExpiry = process.env.ADMIN_RECOVERY_EXPIRES_AT;
  const originalBootstrapSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
  process.env.JWT_SECRET = "risklens-local-postgres-integration-secret";
  process.env.ADMIN_RECOVERY_SECRET = randomBytes(32).toString("hex");
  process.env.ADMIN_RECOVERY_EXPIRES_AT = new Date(Date.now() + 60 * 60_000).toISOString();
  process.env.ADMIN_BOOTSTRAP_SECRET = "local-only-bootstrap-secret-for-test";

  const prisma = new PrismaClient();
  const app = await createPostgresApp();
  const suffix = randomUUID();
  const adminEmail = `recovery-admin-${suffix}@integration.risklens.test`;
  const concurrentEmail = `recovery-concurrent-${suffix}@integration.risklens.test`;
  const analystEmail = `recovery-analyst-${suffix}@integration.risklens.test`;
  const originalPassword = "Local integration password 2026!";
  const newPassword = "Recovered local password 2026!";
  const originalHash = bcrypt.hashSync(originalPassword, 4);
  const adminId = randomUUID();
  const concurrentAdminId = randomUUID();
  const analystId = randomUUID();
  const reviewerId = randomUUID();
  try {
    await prisma.user.createMany({ data: [
      { id: adminId, email: adminEmail, name: "Recovery Test Administrator", role: "ADMIN", status: "ACTIVE", passwordHash: originalHash },
      { id: concurrentAdminId, email: concurrentEmail, name: "Concurrent Recovery Administrator", role: "ADMIN", status: "ACTIVE", passwordHash: originalHash },
      { id: analystId, email: analystEmail, name: "Recovery Test Analyst", role: "ANALYST", status: "ACTIVE", passwordHash: originalHash },
      { id: reviewerId, email: `reviewer-${suffix}@integration.risklens.test`, name: "Recovery Test Reviewer", role: "COMPLIANCE_REVIEWER", status: "ACTIVE", passwordHash: originalHash },
    ] });

    const oldLogin = await request(app).post("/api/auth/login").send({ email: adminEmail, password: originalPassword });
    assert.equal(oldLogin.status, 200);
    const administratorProfile = await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${oldLogin.body.token}` });
    assert.equal(administratorProfile.status, 200);
    assert.deepEqual(administratorProfile.body.user, { id: adminId, email: adminEmail, name: "Recovery Test Administrator", role: "ADMIN", status: "ACTIVE" });
    assert.equal("passwordHash" in administratorProfile.body.user, false);
    const analystLogin = await request(app).post("/api/auth/login").send({ email: analystEmail, password: originalPassword });
    const analystProfile = await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${analystLogin.body.token}` });
    assert.equal(analystProfile.body.user.role, "ANALYST");
    const reviewerEmail = `reviewer-${suffix}@integration.risklens.test`;
    const reviewerLogin = await request(app).post("/api/auth/login").send({ email: reviewerEmail, password: originalPassword });
    const reviewerProfile = await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${reviewerLogin.body.token}` });
    assert.equal(reviewerProfile.body.user.role, "COMPLIANCE_REVIEWER");
    const expiredToken = jwt.sign({ sub: adminId, email: adminEmail, name: "Recovery Test Administrator", role: "ADMIN", authVersion: 0 }, process.env.JWT_SECRET!, { expiresIn: -1 });
    assert.equal((await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${expiredToken}` })).status, 401);
    assert.equal((await request(app).get("/api/auth/me").set({ Authorization: "Bearer invalid-token" })).status, 401);
    await prisma.user.update({ where: { id: analystId }, data: { status: "DISABLED", authVersion: { increment: 1 } } });
    assert.equal((await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${analystLogin.body.token}` })).status, 401);
    await prisma.user.update({ where: { id: analystId }, data: { status: "ACTIVE", authVersion: { increment: 1 } } });
    const recoverySecret = process.env.ADMIN_RECOVERY_SECRET;
    const recoveryRequest = (email: string, secret = recoverySecret, password = newPassword) => request(app)
      .post("/api/admin/recover")
      .send({ recoverySecret: secret, email, password });

    assert.equal((await recoveryRequest(adminEmail, "incorrect-local-recovery-secret" )).status, 401);
    assert.equal((await recoveryRequest(`unknown-${suffix}@integration.risklens.test`)).status, 401);
    assert.equal((await recoveryRequest(analystEmail)).status, 401);

    const recovered = await recoveryRequest(adminEmail);
    assert.equal(recovered.status, 200, JSON.stringify(recovered.body));
    assert.equal(recovered.body.user.role, "ADMIN");
    assert.equal("passwordHash" in recovered.body.user, false);
    assert.equal((await recoveryRequest(adminEmail)).status, 401, "A consumed authorization must not be replayable.");
    assert.equal((await recoveryRequest(adminEmail)).status, 429, "Administrator recovery is limited to five attempts per 15 minutes per client IP.");
    assert.equal((await request(app).get("/api/auth/me").set({ Authorization: `Bearer ${oldLogin.body.token}` })).status, 401);

    const newLogin = await request(app).post("/api/auth/login").send({ email: adminEmail, password: newPassword });
    assert.equal(newLogin.status, 200, "The recovered password must authenticate normally.");
    const recoveryAudit = await prisma.auditEvent.findFirst({
      where: { entityId: adminId, eventType: "UPDATED", details: { path: ["action"], equals: "ADMIN_PASSWORD_RECOVERY" } },
      select: { id: true, entityId: true, actorId: true, details: true },
    });
    assert.ok(recoveryAudit, "Recovery must persist an audit row in the same transaction.");
    assert.equal(recoveryAudit.actorId, null, "Break-glass recovery is attributed as a system-authorized event, not another user.");
    assert.deepEqual(recoveryAudit.details, { action: "ADMIN_PASSWORD_RECOVERY", authorization: "ONE_TIME_RECOVERY_SECRET" });

    process.env.ADMIN_RECOVERY_SECRET = randomBytes(32).toString("hex");
    const concurrentSecret = process.env.ADMIN_RECOVERY_SECRET;
    const concurrentApp = await createPostgresApp();
    const concurrentRequest = () => request(concurrentApp).post("/api/admin/recover").send({
      recoverySecret: concurrentSecret,
      email: concurrentEmail,
      password: "Concurrent recovery password 2026!",
    });
    const concurrentResults = await Promise.all([concurrentRequest(), concurrentRequest()]);
    assert.deepEqual(concurrentResults.map((result) => result.status).sort(), [200, 401]);
    const concurrentLogin = await request(concurrentApp).post("/api/auth/login").send({ email: concurrentEmail, password: "Concurrent recovery password 2026!" });
    assert.equal(concurrentLogin.status, 200);

    const bootstrap = await request(app).post("/api/admin/bootstrap").send({
      secret: process.env.ADMIN_BOOTSTRAP_SECRET,
      email: `new-bootstrap-${suffix}@integration.risklens.test`,
      name: "Must Not Be Created",
      password: newPassword,
    });
    assert.equal(bootstrap.status, 409, "Existing bootstrap remains first-admin-only.");
    assert.equal(await prisma.user.count({ where: { email: `new-bootstrap-${suffix}@integration.risklens.test` } }), 0);

    process.env.ADMIN_RECOVERY_EXPIRES_AT = new Date(Date.now() - 1000).toISOString();
    assert.equal((await request(concurrentApp).post("/api/admin/recover").send({ recoverySecret, email: concurrentEmail, password: newPassword })).status, 503);
    delete process.env.ADMIN_RECOVERY_SECRET;
    assert.equal((await request(concurrentApp).post("/api/admin/recover").send({ recoverySecret, email: concurrentEmail, password: newPassword })).status, 503);
  } finally {
    if (originalRecoverySecret === undefined) delete process.env.ADMIN_RECOVERY_SECRET;
    else process.env.ADMIN_RECOVERY_SECRET = originalRecoverySecret;
    if (originalRecoveryExpiry === undefined) delete process.env.ADMIN_RECOVERY_EXPIRES_AT;
    else process.env.ADMIN_RECOVERY_EXPIRES_AT = originalRecoveryExpiry;
    if (originalBootstrapSecret === undefined) delete process.env.ADMIN_BOOTSTRAP_SECRET;
    else process.env.ADMIN_BOOTSTRAP_SECRET = originalBootstrapSecret;
    await prisma.$disconnect();
  }
});

test("PostgreSQL overview aggregation matches prior transaction-level evaluation semantics", { skip: !databaseUrl || !postgresIntegrationEnabled }, async () => {
  assert.equal(isDisposableLocalDatabase, true, "Overview integration tests require only the dedicated localhost risklens_perf_test database on port 55432.");
  const prisma = new PrismaClient();
  const app = await createPostgresApp();
  const suffix = randomUUID();
  const eventTime = new Date("2026-01-01T00:00:00.000Z");
  const customerId = `EVAL-CUS-${suffix}`;
  const accountId = `EVAL-ACC-${suffix}`;
  const ruleId = randomUUID();
  const userId = randomUUID();
  const transactionIds = ["TP", "FN", "FP", "TN"].map(label => `EVAL-TXN-${label}-${suffix}`);
  const alertIds = [`EVAL-ALERT-TP-1-${suffix}`, `EVAL-ALERT-TP-2-${suffix}`, `EVAL-ALERT-FP-1-${suffix}`, `EVAL-ALERT-FP-2-${suffix}`];
  const validationCheckNames = [`EVAL-PASS-${suffix}`, `EVAL-FAIL-${suffix}`];
  try {
    await prisma.customer.create({ data: { id: customerId, fullName: "Evaluation Test Customer", countryCode: "US" } });
    await prisma.account.create({
      data: {
        id: accountId,
        accountType: "CHECKING",
        status: "OPEN",
        currency: "USD",
        currentBalance: new Prisma.Decimal("1000.00"),
        overdraftLimit: new Prisma.Decimal("0.00"),
        openedAt: eventTime,
      },
    });
    await prisma.riskRule.create({
      data: { id: ruleId, ruleCode: `EVAL-RULE-${suffix}`, version: 1, name: "Evaluation fixture rule", description: "Local parity test only.", severity: "HIGH", weight: 40, effectiveFrom: eventTime },
    });
    await prisma.transaction.createMany({ data: transactionIds.map(id => ({
      id,
      customerId,
      accountId,
      transactionType: "DEBIT",
      status: "POSTED",
      amount: new Prisma.Decimal("1.00"),
      balanceBefore: new Prisma.Decimal("1000.00"),
      balanceAfter: new Prisma.Decimal("999.00"),
      currency: "USD",
      occurredAt: eventTime,
    })) });
    await prisma.groundTruthLabel.createMany({ data: [
      { transactionId: transactionIds[0], scenarioCode: "EVAL_POSITIVE", isSuspicious: true, expectedRuleCode: `EVAL-RULE-${suffix}`, labelSource: "LOCAL_PARITY_FIXTURE" },
      { transactionId: transactionIds[1], scenarioCode: "EVAL_POSITIVE", isSuspicious: true, expectedRuleCode: `EVAL-RULE-${suffix}`, labelSource: "LOCAL_PARITY_FIXTURE" },
      { transactionId: transactionIds[2], scenarioCode: "EVAL_NEGATIVE", isSuspicious: false, expectedRuleCode: `EVAL-RULE-${suffix}`, labelSource: "LOCAL_PARITY_FIXTURE" },
      { transactionId: transactionIds[3], scenarioCode: "EVAL_NEGATIVE", isSuspicious: false, expectedRuleCode: null, labelSource: "LOCAL_PARITY_FIXTURE" },
    ] });
    await prisma.alert.createMany({ data: [0, 1, 2, 3].map(index => ({
      id: alertIds[index],
      customerId,
      accountId,
      transactionId: index < 2 ? transactionIds[0] : transactionIds[2],
      riskRuleId: ruleId,
      evaluationVersion: index % 2 === 0 ? "fixture-v1" : "fixture-v2",
      riskScore: 50,
      priority: "HIGH",
      status: "OPEN",
      explanation: "Controlled local evaluation fixture.",
      detectedAt: eventTime,
    })) });
    await prisma.alertEvidence.createMany({ data: [alertIds[0], alertIds[2]].map(alertId => ({ alertId, evidenceType: "RULE_MATCH", description: "Controlled evidence fixture." })) });
    await prisma.validationResult.createMany({ data: [
      { checkName: validationCheckNames[0], status: "PASSED", message: "Controlled passing fixture." },
      { checkName: validationCheckNames[1], status: "FAILED", message: "Controlled failing fixture." },
    ] });
    await prisma.user.create({
      data: { id: userId, email: `overview-${suffix}@integration.risklens.test`, name: "Overview Test Administrator", role: "ADMIN", status: "ACTIVE", passwordHash: bcrypt.hashSync("Overview local password 2026!", 4) },
    });

    const login = await request(app).post("/api/auth/login").send({ email: `overview-${suffix}@integration.risklens.test`, password: "Overview local password 2026!" });
    assert.equal(login.status, 200);
    const response = await request(app).get("/api/overview").set({ Authorization: `Bearer ${login.body.token}` });
    assert.equal(response.status, 200, JSON.stringify(response.body));

    const [labels, alerts, evidenceAlerts, validationTotals, latestRun] = await Promise.all([
      prisma.groundTruthLabel.findMany({ select: { transactionId: true, scenarioCode: true, isSuspicious: true, expectedRuleCode: true } }),
      prisma.alert.findMany({ select: { id: true, transactionId: true, riskRule: { select: { ruleCode: true } } } }),
      prisma.alertEvidence.groupBy({ by: ["alertId"] }),
      prisma.validationResult.groupBy({ by: ["status"], _count: { _all: true } }),
      prisma.generationRun.findFirst({ orderBy: { startedAt: "desc" }, select: { startedAt: true, completedAt: true } }),
    ]);
    const expectedMetrics = previousEvaluationMetrics(labels, alerts, evidenceAlerts, validationTotals, latestRun);
    const actualMetrics = {
      ...response.body.evaluation,
      ruleMetrics: [...response.body.evaluation.ruleMetrics].sort((left: { ruleCode: string }, right: { ruleCode: string }) => left.ruleCode.localeCompare(right.ruleCode)),
    };
    expectedMetrics.ruleMetrics.sort((left, right) => left.ruleCode.localeCompare(right.ruleCode));
    assert.deepEqual(actualMetrics, expectedMetrics);
    assert.equal(response.body.evaluation.evidenceCompleteness, 0.5);
    assert.equal(response.body.evaluation.ruleMetrics.find((item: { ruleCode: string }) => item.ruleCode === `EVAL-RULE-${suffix}`).precision, 0.5);
    assert.equal(response.body.evaluation.scenarioCoverage.EVAL_POSITIVE, 0.5);
    assert.equal("groundTruthLabels" in response.body, false);
  } finally {
    try {
      // Delete ordinary fixtures child-first; this test creates no append-only event or audit records.
      await prisma.$transaction([
        prisma.alertEvidence.deleteMany({ where: { alertId: { in: alertIds } } }),
        prisma.alert.deleteMany({ where: { id: { in: alertIds } } }),
        prisma.groundTruthLabel.deleteMany({ where: { transactionId: { in: transactionIds } } }),
        prisma.validationResult.deleteMany({ where: { checkName: { in: validationCheckNames } } }),
        prisma.transaction.deleteMany({ where: { id: { in: transactionIds } } }),
        prisma.user.deleteMany({ where: { id: userId } }),
        prisma.riskRule.deleteMany({ where: { id: ruleId } }),
        prisma.account.deleteMany({ where: { id: accountId } }),
        prisma.customer.deleteMany({ where: { id: customerId } }),
      ]);

      const remainingFixtureCounts = await Promise.all([
        prisma.customer.count({ where: { id: customerId } }),
        prisma.account.count({ where: { id: accountId } }),
        prisma.riskRule.count({ where: { id: ruleId } }),
        prisma.transaction.count({ where: { id: { in: transactionIds } } }),
        prisma.groundTruthLabel.count({ where: { transactionId: { in: transactionIds } } }),
        prisma.alert.count({ where: { id: { in: alertIds } } }),
        prisma.alertEvidence.count({ where: { alertId: { in: alertIds } } }),
        prisma.validationResult.count({ where: { checkName: { in: validationCheckNames } } }),
        prisma.user.count({ where: { id: userId } }),
      ]);
      assert.deepEqual(remainingFixtureCounts, Array(9).fill(0), "Overview evaluation fixtures must be fully cleaned up.");
    } finally {
      await prisma.$disconnect();
    }
  }
});
