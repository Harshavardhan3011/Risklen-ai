import assert from "node:assert/strict";
import { test } from "node:test";
import { assessTransaction, type RiskContext } from "../src/risk-engine.js";

const now = new Date("2026-01-01T00:00:00Z");
const context: RiskContext = {
  transaction: { id: "TXN-1", amount: 500, balanceAfter: -200, transactionType: "DEBIT", status: "POSTED", currency: "USD", occurredAt: now },
  account: { status: "CLOSED", currentBalance: 0, overdraftLimit: 100 },
  merchant: { riskRating: "HIGH" },
  device: { firstSeenAt: new Date("2025-12-31T23:30:00Z") },
  recentTransactions: [
    { amount: 100, merchantId: "M1", occurredAt: new Date("2025-12-31T23:55:00Z"), status: "DECLINED" },
    { amount: 100, merchantId: "M1", occurredAt: new Date("2025-12-31T23:56:00Z"), status: "DECLINED" },
    { amount: 100, merchantId: "M1", occurredAt: new Date("2025-12-31T23:57:00Z"), status: "POSTED" },
    { amount: 100, merchantId: "M1", occurredAt: new Date("2025-12-31T23:58:00Z"), status: "POSTED" },
    { amount: 100, merchantId: "M1", occurredAt: new Date("2025-12-31T23:59:00Z"), status: "POSTED" },
  ],
  transferLinks: [
    { sourceAccountId: "A", targetAccountId: "B", amount: 10, currency: "USD" },
    { sourceAccountId: "B", targetAccountId: "A", amount: 11, currency: "USD" },
  ],
};

test("risk engine evaluates all nine rules once and caps the score", () => {
  const assessment = assessTransaction(context, Array.from({ length: 9 }, (_, index) => ({ ruleCode: `R00${index + 1}`, weight: 20, enabled: true })));
  assert.equal(assessment.score, 100);
  assert.equal(assessment.priority, "CRITICAL");
  assert.deepEqual(assessment.findings.map(finding => finding.ruleCode), ["R001", "R002", "R005", "R006", "R007", "R008", "R009"]);
  assert.ok(assessment.findings.every(finding => finding.evidence.length > 0));
});

test("risk engine detects dormant reactivation and circular transfers", () => {
  const assessment = assessTransaction({
    ...context,
    account: { ...context.account, status: "DORMANT" },
    transferLinks: [
      { sourceAccountId: "A", targetAccountId: "B", amount: 10, currency: "USD" },
      { sourceAccountId: "B", targetAccountId: "A", amount: 10, currency: "USD" },
    ],
  }, [
    { ruleCode: "R003", weight: 30, enabled: true },
    { ruleCode: "R004", weight: 25, enabled: true },
  ]);
  assert.deepEqual(assessment.findings.map(finding => finding.ruleCode), ["R003", "R004"]);
});

test("risk engine excludes disabled rules and preserves score bands", () => {
  const assessment = assessTransaction({ ...context, recentTransactions: [] }, [
    { ruleCode: "R005", weight: 49, enabled: true },
    { ruleCode: "R008", weight: 10, enabled: false },
  ]);
  assert.equal(assessment.score, 49);
  assert.equal(assessment.priority, "MEDIUM");
  assert.deepEqual(assessment.findings.map(finding => finding.ruleCode), ["R005"]);
});
