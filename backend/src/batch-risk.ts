import { Prisma } from "@prisma/client";
import { randomUUID } from "node:crypto";
import { prisma } from "./prisma.js";
import { assessTransaction, type RiskAssessment, type RiskRuleDefinition } from "./risk-engine.js";

type TransactionWithContext = Prisma.TransactionGetPayload<{
  include: { account: true; merchant: true; device: true; transferLinks: true };
}>;

export type BatchRiskResult = {
  runId: string;
  status: "COMPLETED" | "FAILED";
  totalProcessed: number;
  failedRecords: number;
  alertCount: number;
  elapsedMs: number;
};

function contextFor(transaction: TransactionWithContext, recentTransactions: Array<{ amount: Prisma.Decimal; merchantId: string | null; occurredAt: Date; status: string }>) {
  return {
    transaction: {
      id: transaction.id,
      amount: Number(transaction.amount),
      balanceAfter: Number(transaction.balanceAfter),
      transactionType: transaction.transactionType,
      status: transaction.status,
      currency: transaction.currency,
      occurredAt: transaction.occurredAt,
    },
    account: {
      status: transaction.account.status,
      currentBalance: Number(transaction.account.currentBalance),
      overdraftLimit: Number(transaction.account.overdraftLimit),
    },
    merchant: transaction.merchant ? { riskRating: transaction.merchant.riskRating } : null,
    device: transaction.device ? { firstSeenAt: transaction.device.firstSeenAt } : null,
    recentTransactions: recentTransactions.map(item => ({
      amount: Number(item.amount),
      merchantId: item.merchantId,
      occurredAt: item.occurredAt,
      status: item.status,
    })),
    transferLinks: transaction.transferLinks.map(link => ({
      sourceAccountId: link.sourceAccountId,
      targetAccountId: link.targetAccountId,
      amount: Number(link.amount),
      currency: link.currency,
    })),
  };
}

async function assessOne(transaction: TransactionWithContext, rules: RiskRuleDefinition[]) {
  const recent = await prisma.transaction.findMany({
    where: {
      accountId: transaction.accountId,
      id: { not: transaction.id },
      occurredAt: {
        gte: new Date(transaction.occurredAt.getTime() - 30 * 60_000),
        lte: transaction.occurredAt,
      },
    },
    select: { amount: true, merchantId: true, occurredAt: true, status: true },
  });
  return assessTransaction(contextFor(transaction, recent), rules);
}

async function persistAssessment(
  transaction: TransactionWithContext,
  rules: Array<{ id: string; ruleCode: string; version: number }>,
  assessment: RiskAssessment,
  actorId: string,
) {
  return prisma.$transaction(async tx => {
    let alertCount = 0;
    for (const finding of assessment.findings) {
      const rule = rules.find(item => item.ruleCode === finding.ruleCode);
      if (!rule) continue;
      const evaluationVersion = `${rule.ruleCode}:v${rule.version}`;
      const existing = await tx.alert.findUnique({
        where: {
          riskRuleId_transactionId_evaluationVersion: {
            riskRuleId: rule.id,
            transactionId: transaction.id,
            evaluationVersion,
          },
        },
      });
      if (existing) continue;
      const alert = await tx.alert.create({
        data: {
          id: randomUUID(),
          customerId: transaction.customerId,
          accountId: transaction.accountId,
          transactionId: transaction.id,
          riskRuleId: rule.id,
          evaluationVersion,
          riskScore: assessment.score,
          priority: assessment.priority,
          status: "OPEN",
          explanation: finding.evidence,
          detectedAt: transaction.occurredAt,
        },
      });
      await tx.alertEvidence.create({
        data: {
          alertId: alert.id,
          evidenceType: "RULE_MATCH",
          sourceId: transaction.id,
          description: finding.evidence,
          value: { ruleCode: finding.ruleCode, score: finding.score },
        },
      });
      await tx.alertEvent.create({
        data: { alertId: alert.id, actorId, eventType: "CREATED", details: { ruleCode: finding.ruleCode, evaluationVersion } },
      });
      await tx.auditEvent.create({
        data: { entityType: "ALERT", entityId: alert.id, actorId, eventType: "CREATED", details: { transactionId: transaction.id, ruleCode: finding.ruleCode } },
      });
      alertCount += 1;
    }
    return alertCount;
  });
}

export async function runBatchRiskAssessment(actorId: string, requestedBatchSize = 100, maxTransactions?: number): Promise<BatchRiskResult> {
  const batchSize = Math.min(250, Math.max(1, Math.floor(requestedBatchSize)));
  const startedAt = Date.now();
  const run = await prisma.generationRun.create({
    data: {
      seed: BigInt(0),
      scale: "RISK_ASSESSMENT",
      status: "STARTED",
      sourceChecksum: "runtime-risk-engine",
      metadata: { batchSize, maxTransactions: maxTransactions ?? null, totalProcessed: 0, failedRecords: 0, alertCount: 0 },
    },
  });
  let cursor: string | undefined;
  let totalProcessed = 0;
  let failedRecords = 0;
  let alertCount = 0;
  try {
    const rules = await prisma.riskRule.findMany({
      where: { enabled: true },
      orderBy: [{ ruleCode: "asc" }, { version: "desc" }],
      select: { id: true, ruleCode: true, version: true, weight: true, threshold: true, enabled: true },
    });
    const definitions = rules.map(rule => ({ ruleCode: rule.ruleCode, weight: rule.weight, threshold: rule.threshold ? Number(rule.threshold) : null, enabled: rule.enabled }));
    while (maxTransactions === undefined || totalProcessed < maxTransactions) {
      const remaining = maxTransactions === undefined ? batchSize : Math.min(batchSize, maxTransactions - totalProcessed);
      const transactions = await prisma.transaction.findMany({
        orderBy: { id: "asc" },
        take: remaining,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        include: { account: true, merchant: true, device: true, transferLinks: true },
      });
      if (!transactions.length) break;
      for (const transaction of transactions) {
        try {
          const assessment = await assessOne(transaction, definitions);
          alertCount += await persistAssessment(transaction, rules, assessment, actorId);
        } catch {
          failedRecords += 1;
        }
        totalProcessed += 1;
      }
      cursor = transactions[transactions.length - 1].id;
      await prisma.generationRun.update({
        where: { id: run.id },
        data: { metadata: { batchSize, maxTransactions: maxTransactions ?? null, totalProcessed, failedRecords, alertCount } },
      });
      if (transactions.length < remaining) break;
    }
    const elapsedMs = Date.now() - startedAt;
    await prisma.generationRun.update({
      where: { id: run.id },
      data: { status: failedRecords ? "FAILED" : "COMPLETED", completedAt: new Date(), metadata: { batchSize, maxTransactions: maxTransactions ?? null, totalProcessed, failedRecords, alertCount, elapsedMs } },
    });
    return { runId: run.id, status: failedRecords ? "FAILED" : "COMPLETED", totalProcessed, failedRecords, alertCount, elapsedMs };
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    await prisma.generationRun.update({
      where: { id: run.id },
      data: { status: "FAILED", completedAt: new Date(), metadata: { batchSize, maxTransactions: maxTransactions ?? null, totalProcessed, failedRecords, alertCount, elapsedMs, error: error instanceof Error ? error.message : "Batch processing failed" } },
    });
    throw error;
  }
}
