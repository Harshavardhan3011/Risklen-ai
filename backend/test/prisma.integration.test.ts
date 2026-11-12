import assert from "node:assert/strict";
import { test } from "node:test";
import { PrismaClient, Prisma } from "@prisma/client";

const databaseUrl = process.env.DATABASE_URL;
const postgresIntegrationEnabled = process.env.RUN_POSTGRES_INTEGRATION_TESTS === "true";

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
