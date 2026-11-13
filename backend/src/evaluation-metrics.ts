import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";

export type EvaluationMetrics = {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
  falsePositiveRate: number;
  ruleMetrics: Array<{ ruleCode: string; precision: number; recall: number }>;
  scenarioCoverage: Record<string, number>;
  alertsPer1000Transactions: number;
  processingTimeSeconds: number | null;
  evaluationUnit: string;
  matchingMethodology: string;
  evidenceCompleteness: number;
  validationPassRate: number;
};

type AggregateRow = {
  truePositives: bigint;
  falsePositives: bigint;
  falseNegatives: bigint;
  trueNegatives: bigint;
  predictedTransactions: bigint;
  transactionUniverse: bigint;
  evaluatedAlerts: bigint;
  evaluatedAlertsWithEvidence: bigint;
  validationTotal: bigint;
  validationPassed: bigint;
  processingTimeSeconds: number | null;
  ruleMetrics: Array<{ ruleCode: string; precision: number; recall: number }>;
  scenarioCoverage: Record<string, number>;
};

const evaluationSql = `
WITH label_rows AS MATERIALIZED (
  SELECT "transactionId", "scenarioCode", "isSuspicious", "expectedRuleCode"
  FROM "evaluation"."ground_truth_labels"
), label_universe AS MATERIALIZED (
  SELECT "transactionId", bool_or("isSuspicious") AS positive
  FROM label_rows
  GROUP BY "transactionId"
), predicted AS MATERIALIZED (
  SELECT DISTINCT a."transactionId"
  FROM "public"."alerts" a
  JOIN label_universe u ON u."transactionId" = a."transactionId"
), outcomes AS (
  SELECT u.positive, (p."transactionId" IS NOT NULL) AS predicted
  FROM label_universe u
  LEFT JOIN predicted p USING ("transactionId")
), evaluated_alerts AS MATERIALIZED (
  SELECT a."id", a."transactionId", r."ruleCode"
  FROM "public"."alerts" a
  JOIN label_universe u ON u."transactionId" = a."transactionId"
  JOIN "public"."risk_rules" r ON r."id" = a."riskRuleId"
), rule_codes AS (
  SELECT DISTINCT "expectedRuleCode" AS rule_code
  FROM label_rows
  WHERE "expectedRuleCode" IS NOT NULL AND "expectedRuleCode" <> ''
), rule_expected AS (
  SELECT DISTINCT "expectedRuleCode" AS rule_code, "transactionId"
  FROM label_rows
  WHERE "isSuspicious" = TRUE AND "expectedRuleCode" IS NOT NULL AND "expectedRuleCode" <> ''
), rule_predicted AS (
  SELECT DISTINCT "ruleCode" AS rule_code, "transactionId"
  FROM evaluated_alerts
), rule_outcomes AS (
  SELECT COALESCE(e.rule_code, p.rule_code) AS rule_code,
         e."transactionId" AS expected_transaction,
         p."transactionId" AS predicted_transaction
  FROM rule_expected e
  FULL OUTER JOIN rule_predicted p
    ON p.rule_code = e.rule_code AND p."transactionId" = e."transactionId"
), rule_counts AS (
  SELECT c.rule_code,
         count(*) FILTER (WHERE o.expected_transaction IS NOT NULL AND o.predicted_transaction IS NOT NULL) AS tp,
         count(*) FILTER (WHERE o.expected_transaction IS NULL AND o.predicted_transaction IS NOT NULL) AS fp,
         count(*) FILTER (WHERE o.expected_transaction IS NOT NULL AND o.predicted_transaction IS NULL) AS fn
  FROM rule_codes c
  LEFT JOIN rule_outcomes o ON o.rule_code = c.rule_code
  GROUP BY c.rule_code
), scenario_counts AS (
  SELECT l."scenarioCode" AS scenario_code,
         count(*) FILTER (WHERE l."isSuspicious") AS expected,
         count(*) FILTER (WHERE l."isSuspicious" AND p."transactionId" IS NOT NULL) AS found
  FROM label_rows l
  LEFT JOIN predicted p ON p."transactionId" = l."transactionId"
  GROUP BY l."scenarioCode"
), evidence_counts AS (
  SELECT count(*) AS total,
         count(*) FILTER (WHERE e."alertId" IS NOT NULL) AS covered
  FROM evaluated_alerts a
  LEFT JOIN (SELECT DISTINCT "alertId" FROM "public"."alert_evidence") e ON e."alertId" = a."id"
), validation_counts AS (
  SELECT count(*) AS total, count(*) FILTER (WHERE "status" = 'PASSED') AS passed
  FROM "public"."validation_results"
), latest_run AS (
  SELECT CASE WHEN "completedAt" IS NULL THEN NULL
              ELSE extract(epoch FROM ("completedAt" - "startedAt"))::double precision END AS elapsed
  FROM "public"."generation_runs"
  ORDER BY "startedAt" DESC
  LIMIT 1
), overall AS (
  SELECT count(*) FILTER (WHERE positive AND predicted) AS tp,
         count(*) FILTER (WHERE NOT positive AND predicted) AS fp,
         count(*) FILTER (WHERE positive AND NOT predicted) AS fn,
         count(*) FILTER (WHERE NOT positive AND NOT predicted) AS tn,
         count(*) FILTER (WHERE predicted) AS predicted_count,
         count(*) AS universe_count
  FROM outcomes
)
SELECT o.tp AS "truePositives", o.fp AS "falsePositives",
       o.fn AS "falseNegatives", o.tn AS "trueNegatives",
       o.predicted_count AS "predictedTransactions", o.universe_count AS "transactionUniverse",
       ec.total AS "evaluatedAlerts", ec.covered AS "evaluatedAlertsWithEvidence",
       vc.total AS "validationTotal", vc.passed AS "validationPassed",
       lr.elapsed AS "processingTimeSeconds",
       COALESCE((SELECT jsonb_agg(jsonb_build_object(
         'ruleCode', rc.rule_code,
         'precision', CASE WHEN rc.tp + rc.fp = 0 THEN 0 ELSE rc.tp::double precision / (rc.tp + rc.fp) END,
         'recall', CASE WHEN rc.tp + rc.fn = 0 THEN 0 ELSE rc.tp::double precision / (rc.tp + rc.fn) END
       ) ORDER BY rc.rule_code) FROM rule_counts rc), '[]'::jsonb) AS "ruleMetrics",
       COALESCE((SELECT jsonb_object_agg(sc.scenario_code,
         CASE WHEN sc.expected = 0 THEN 1 ELSE sc.found::double precision / sc.expected END
       ) FROM scenario_counts sc), '{}'::jsonb) AS "scenarioCoverage"
FROM overall o
CROSS JOIN evidence_counts ec
CROSS JOIN validation_counts vc
LEFT JOIN latest_run lr ON TRUE
`;

function integer(value: bigint | number | string): number {
  return typeof value === "bigint" ? Number(value) : Number(value);
}

export function evaluationMetricsFromAggregate(row: AggregateRow): EvaluationMetrics {
  const tp = integer(row.truePositives);
  const fp = integer(row.falsePositives);
  const fn = integer(row.falseNegatives);
  const tn = integer(row.trueNegatives);
  const predicted = integer(row.predictedTransactions);
  const universe = integer(row.transactionUniverse);
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    accuracy: universe ? (tp + tn) / universe : 0,
    falsePositiveRate: fp + tn ? fp / (fp + tn) : 0,
    ruleMetrics: row.ruleMetrics,
    scenarioCoverage: row.scenarioCoverage,
    alertsPer1000Transactions: universe ? (predicted / universe) * 1000 : 0,
    processingTimeSeconds: row.processingTimeSeconds,
    evaluationUnit: "transaction ID within the ground-truth universe; duplicate alerts count once",
    matchingMethodology: "Exact alert.transactionId to evaluation.ground_truth_labels.transactionId matching; labels are never returned by operational APIs.",
    evidenceCompleteness: integer(row.evaluatedAlerts) ? integer(row.evaluatedAlertsWithEvidence) / integer(row.evaluatedAlerts) : 0,
    validationPassRate: integer(row.validationTotal) ? integer(row.validationPassed) / integer(row.validationTotal) : 0,
  };
}

export async function evaluationMetrics(): Promise<EvaluationMetrics> {
  let cacheRevision: bigint | null = null;
  try {
    const [cached] = await prisma.$queryRaw<Array<{ revision: bigint; payload: EvaluationMetrics | null }>>`
      SELECT "revision", "payload"
      FROM "evaluation"."evaluation_metric_cache"
      WHERE "singleton" = TRUE
      LIMIT 1
    `;
    if (cached?.payload) return cached.payload;
    if (cached) cacheRevision = cached.revision;
  } catch (error) {
    const prismaError = error as { code?: string; meta?: { code?: string }; message?: string };
    const missingCacheTable = prismaError.code === "P2010" && prismaError.meta?.code === "42P01";
    if (!missingCacheTable) throw error;
  }

  const [row] = await prisma.$queryRaw<AggregateRow[]>(Prisma.raw(evaluationSql));
  if (!row) throw new Error("Evaluation metrics query returned no result");
  const metrics = evaluationMetricsFromAggregate(row);
  if (cacheRevision !== null) {
    await prisma.$executeRaw`
      UPDATE "evaluation"."evaluation_metric_cache"
      SET "payload" = ${JSON.stringify(metrics)}::jsonb
      WHERE "singleton" = TRUE AND "revision" = ${cacheRevision}
    `;
  }
  return metrics;
}
