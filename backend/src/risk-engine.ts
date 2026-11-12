export type RiskRuleDefinition = {
  ruleCode: string;
  weight: number;
  threshold?: number | null;
  enabled: boolean;
};

export type RiskContext = {
  transaction: {
    id: string;
    amount: number;
    balanceAfter: number;
    transactionType: string;
    status: string;
    currency: string;
    occurredAt: Date;
  };
  account: {
    status: string;
    currentBalance: number;
    overdraftLimit: number;
  };
  merchant: { riskRating: string | null } | null;
  device: { firstSeenAt: Date } | null;
  recentTransactions: Array<{ amount: number; merchantId: string | null; occurredAt: Date; status: string }>;
  transferLinks: Array<{ sourceAccountId: string; targetAccountId: string; amount: number; currency: string }>;
};

export type RiskFinding = {
  ruleCode: string;
  score: number;
  evidence: string;
};

export type RiskAssessment = {
  score: number;
  priority: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  findings: RiskFinding[];
};

function withinMinutes(left: Date, right: Date, minutes: number): boolean {
  return Math.abs(left.getTime() - right.getTime()) <= minutes * 60_000;
}

function priority(score: number): RiskAssessment["priority"] {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

export function assessTransaction(context: RiskContext, definitions: RiskRuleDefinition[]): RiskAssessment {
  const findings: RiskFinding[] = [];
  const add = (ruleCode: string, evidence: string) => {
    const definition = definitions.find(rule => rule.ruleCode === ruleCode && rule.enabled);
    if (definition && !findings.some(finding => finding.ruleCode === ruleCode)) {
      findings.push({ ruleCode, score: Math.max(0, definition.weight), evidence });
    }
  };
  const recent = context.recentTransactions.filter(transaction => withinMinutes(transaction.occurredAt, context.transaction.occurredAt, 10));
  if (recent.length >= 5) add("R001", `${recent.length + 1} transactions occurred within a ten-minute window.`);
  const averageAmount = context.recentTransactions.length ? context.recentTransactions.reduce((sum, transaction) => sum + transaction.amount, 0) / context.recentTransactions.length : 0;
  if (context.device && (context.transaction.occurredAt.getTime() - context.device.firstSeenAt.getTime()) < 24 * 60 * 60_000 && context.transaction.amount > averageAmount * 2) {
    add("R002", "The transaction uses a device observed within the last 24 hours and is more than twice the recent average amount.");
  }
  const hasReciprocalTransfer = context.transferLinks.some(left => context.transferLinks.some(right =>
    left.sourceAccountId === right.targetAccountId
    && left.targetAccountId === right.sourceAccountId
    && left.currency === right.currency
    && left.amount === right.amount));
  if (hasReciprocalTransfer) add("R003", "Transfer legs contain reciprocal account endpoints with matching amount and currency.");
  if (context.account.status === "DORMANT") add("R004", "The transaction reactivates an account marked DORMANT.");
  if (context.account.status === "CLOSED") add("R005", "The transaction targets an account marked CLOSED.");
  if (context.transaction.transactionType === "DEBIT" && context.transaction.balanceAfter < -context.account.overdraftLimit) {
    add("R006", `The debit balance ${context.transaction.balanceAfter.toFixed(2)} exceeds the overdraft limit.`);
  }
  if (context.transferLinks.length > 1 && new Set(context.transferLinks.map(link => `${link.amount}:${link.currency}`)).size > 1) {
    add("R007", "Transfer legs do not reconcile to one amount and currency.");
  }
  if (context.merchant?.riskRating === "HIGH" || context.merchant?.riskRating === "CRITICAL") {
    add("R008", `The merchant risk rating is ${context.merchant.riskRating}.`);
  }
  const repeatedAttempts = context.recentTransactions.filter(transaction =>
    transaction.status === "DECLINED" && withinMinutes(transaction.occurredAt, context.transaction.occurredAt, 30));
  if (repeatedAttempts.length >= 2) add("R009", `${repeatedAttempts.length + 1} declined attempts occurred within thirty minutes.`);
  const score = Math.min(100, findings.reduce((total, finding) => total + finding.score, 0));
  return { score, priority: priority(score), findings };
}
