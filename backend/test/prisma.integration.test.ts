import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
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

test("Prisma PostgreSQL integration checks", { skip: !databaseUrl || !postgresIntegrationEnabled }, async () => {
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
    await prisma.$transaction([
      prisma.accountEvent.deleteMany({ where: { accountId } }),
      prisma.transaction.deleteMany({ where: { accountId } }),
      prisma.accountOwner.deleteMany({ where: { accountId } }),
      prisma.account.deleteMany({ where: { id: accountId } }),
      prisma.customer.deleteMany({ where: { id: customerId } }),
    ]);
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
  try {
    await prisma.user.createMany({ data: [
      { id: adminId, email: adminEmail, name: "Recovery Test Administrator", role: "ADMIN", status: "ACTIVE", passwordHash: originalHash },
      { id: concurrentAdminId, email: concurrentEmail, name: "Concurrent Recovery Administrator", role: "ADMIN", status: "ACTIVE", passwordHash: originalHash },
      { id: analystId, email: analystEmail, name: "Recovery Test Analyst", role: "ANALYST", status: "ACTIVE", passwordHash: originalHash },
    ] });

    const oldLogin = await request(app).post("/api/auth/login").send({ email: adminEmail, password: originalPassword });
    assert.equal(oldLogin.status, 200);
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
