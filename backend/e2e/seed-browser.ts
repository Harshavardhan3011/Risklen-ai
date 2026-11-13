import bcrypt from "bcryptjs";
import { Prisma, PrismaClient } from "@prisma/client";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required.");
const target = new URL(databaseUrl);
if (!["127.0.0.1", "localhost", "::1"].includes(target.hostname) || target.port !== "55432" || target.pathname !== "/risklens_perf_test") {
  throw new Error("Refusing to seed anything except the disposable loopback risklens_perf_test database.");
}
const password = process.env.RISKLEN_E2E_PASSWORD;
if (!password || password.length < 12) throw new Error("Set RISKLEN_E2E_PASSWORD to a local disposable test password of at least 12 characters.");

const prisma = new PrismaClient();
const analystId = "00000000-0000-4000-8000-000000000a91";
const adminId = "00000000-0000-4000-8000-000000000a92";
const customerId = "PW-CUS-000001";
const accountId = "PW-ACC-CUS-000001-01";
const merchantId = "PW-MER-000001";
const ruleId = "00000000-0000-4000-8000-000000000b01";
const transactionId = "PW-TXN-2026-00000001";
const alertId = "PW-ALT-2026-000001";
const caseId = "PW-CASE-2026-000001";
const passwordHash = bcrypt.hashSync(password, 4);
const now = new Date();

try {
  for (const user of [
    { id: analystId, email: "browser.analyst@risklens.test", name: "Test Analyst", role: "ANALYST" as const },
    { id: adminId, email: "browser.admin@risklens.test", name: "Test Administrator", role: "ADMIN" as const },
    { id: "00000000-0000-4000-8000-000000000a93", email: "browser.customer@risklens.test", name: "Test Customer", role: "CUSTOMER" as const },
  ]) {
    await prisma.user.upsert({ where: { email: user.email }, create: { ...user, status: "ACTIVE", passwordHash }, update: { ...user, status: "ACTIVE", passwordHash } });
  }
  await prisma.customer.upsert({ where: { id: customerId }, create: { id: customerId, fullName: "Synthetic Browser Customer", email: "browser.customer@risklens.test", countryCode: "US" }, update: { fullName: "Synthetic Browser Customer", email: "browser.customer@risklens.test", countryCode: "US" } });
  await prisma.account.upsert({ where: { id: accountId }, create: { id: accountId, accountType: "CHECKING", status: "OPEN", currency: "USD", currentBalance: new Prisma.Decimal("900.00"), overdraftLimit: new Prisma.Decimal("0.00"), openedAt: new Date("2026-01-01T00:00:00Z") }, update: { status: "OPEN", currentBalance: new Prisma.Decimal("900.00"), overdraftLimit: new Prisma.Decimal("0.00") } });
  await prisma.accountOwner.upsert({ where: { accountId_customerId_effectiveFrom: { accountId, customerId, effectiveFrom: new Date("2026-01-01T00:00:00Z") } }, create: { accountId, customerId, ownershipType: "PRIMARY", effectiveFrom: new Date("2026-01-01T00:00:00Z") }, update: { ownershipType: "PRIMARY" } });
  await prisma.merchant.upsert({ where: { id: merchantId }, create: { id: merchantId, name: "Synthetic Browser Merchant", categoryCode: "7995", countryCode: "US", riskRating: "HIGH" }, update: { riskRating: "HIGH" } });
  await prisma.riskRule.upsert({ where: { id: ruleId }, create: { id: ruleId, ruleCode: "PW-RULE-001", version: 1, name: "Browser fixture risk rule", description: "Synthetic browser-only fixture.", severity: "HIGH", weight: 35, enabled: true, effectiveFrom: new Date("2026-01-01T00:00:00Z") }, update: { enabled: true } });
  await prisma.transaction.upsert({ where: { id: transactionId }, create: { id: transactionId, customerId, accountId, merchantId, transactionType: "DEBIT", status: "POSTED", amount: new Prisma.Decimal("100.00"), balanceBefore: new Prisma.Decimal("1000.00"), balanceAfter: new Prisma.Decimal("900.00"), currency: "USD", occurredAt: now, postedAt: now, reference: "browser-fixture-transaction" }, update: { status: "POSTED", occurredAt: now, postedAt: now } });
  await prisma.alert.upsert({ where: { id: alertId }, create: { id: alertId, customerId, accountId, transactionId, riskRuleId: ruleId, evaluationVersion: "PW-RULE-001:v1", riskScore: 88, priority: "CRITICAL", status: "OPEN", explanation: "Synthetic high-risk merchant activity for browser verification.", detectedAt: now }, update: { riskScore: 88, priority: "CRITICAL", status: "OPEN", closedAt: null, detectedAt: now } });
  await prisma.alertEvidence.upsert({ where: { id: "00000000-0000-4000-8000-000000000b02" }, create: { id: "00000000-0000-4000-8000-000000000b02", alertId, evidenceType: "RULE_MATCH", sourceId: transactionId, description: "High-risk merchant category matched the synthetic rule.", value: { ruleCode: "PW-RULE-001" } }, update: { description: "High-risk merchant category matched the synthetic rule." } });
  await prisma.case.upsert({ where: { id: caseId }, create: { id: caseId, status: "NEW", assignedToId: analystId, openedAt: now }, update: { status: "NEW", disposition: null, closedAt: null, assignedToId: analystId, openedAt: now } });
  await prisma.caseAlert.upsert({ where: { caseId_alertId: { caseId, alertId } }, create: { caseId, alertId }, update: {} });
  if (!await prisma.caseEvent.findFirst({ where: { caseId } })) await prisma.caseEvent.create({ data: { caseId, eventType: "CREATED", actorId: analystId, details: { source: "local-playwright-fixture" } } });
  console.log("Seeded isolated synthetic browser fixtures.");
} finally {
  await prisma.$disconnect();
}
