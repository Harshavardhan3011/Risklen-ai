import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluationMetricsFromAggregate } from "../src/evaluation-metrics.js";

test("aggregate result preserves set-based evaluation semantics with duplicate alerts", () => {
  const labels = [
    { transactionId: "t1", scenarioCode: "A", isSuspicious: true, expectedRuleCode: "R1" },
    { transactionId: "t1", scenarioCode: "B", isSuspicious: false, expectedRuleCode: "R1" },
    { transactionId: "t2", scenarioCode: "A", isSuspicious: false, expectedRuleCode: "R1" },
    { transactionId: "t3", scenarioCode: "B", isSuspicious: true, expectedRuleCode: "R2" },
    { transactionId: "t4", scenarioCode: "A", isSuspicious: false, expectedRuleCode: null },
  ];
  const alerts = [
    { id: "a1", transactionId: "t1", ruleCode: "R1", hasEvidence: true },
    { id: "a2", transactionId: "t1", ruleCode: "R1", hasEvidence: false },
    { id: "a3", transactionId: "t2", ruleCode: "R2", hasEvidence: true },
    { id: "a4", transactionId: "outside", ruleCode: "R2", hasEvidence: true },
  ];

  // Reference the prior implementation's distinct transaction sets and row-based scenario coverage.
  const positive = new Set(labels.filter((label) => label.isSuspicious).map((label) => label.transactionId));
  const universe = new Set(labels.map((label) => label.transactionId));
  const predicted = new Set(alerts.map((alert) => alert.transactionId).filter((id) => universe.has(id)));
  const tp = [...predicted].filter((id) => positive.has(id)).length;
  const fp = [...predicted].filter((id) => !positive.has(id)).length;
  const fn = [...positive].filter((id) => !predicted.has(id)).length;
  const evaluatedAlerts = alerts.filter((alert) => universe.has(alert.transactionId));
  const ruleMetrics = ["R1", "R2"].map((ruleCode) => {
    const expected = new Set(labels.filter((label) => label.expectedRuleCode === ruleCode && label.isSuspicious).map((label) => label.transactionId));
    const rulePredicted = new Set(evaluatedAlerts.filter((alert) => alert.ruleCode === ruleCode).map((alert) => alert.transactionId));
    const ruleTp = [...rulePredicted].filter((id) => expected.has(id)).length;
    const ruleFp = [...rulePredicted].filter((id) => !expected.has(id)).length;
    const ruleFn = [...expected].filter((id) => !rulePredicted.has(id)).length;
    return { ruleCode, precision: ruleTp + ruleFp ? ruleTp / (ruleTp + ruleFp) : 0, recall: ruleTp + ruleFn ? ruleTp / (ruleTp + ruleFn) : 0 };
  });
  const scenarioCoverage = Object.fromEntries(["A", "B"].map((scenarioCode) => {
    const expected = labels.filter((label) => label.scenarioCode === scenarioCode && label.isSuspicious);
    const found = expected.filter((label) => predicted.has(label.transactionId));
    return [scenarioCode, expected.length ? found.length / expected.length : 1];
  }));
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;

  const aggregateResult = evaluationMetricsFromAggregate({
    truePositives: 1n,
    falsePositives: 1n,
    falseNegatives: 1n,
    trueNegatives: 1n,
    predictedTransactions: BigInt(predicted.size),
    transactionUniverse: BigInt(universe.size),
    evaluatedAlerts: BigInt(evaluatedAlerts.length),
    evaluatedAlertsWithEvidence: 2n,
    validationTotal: 2n,
    validationPassed: 1n,
    processingTimeSeconds: 2.5,
    ruleMetrics,
    scenarioCoverage,
  });

  assert.deepEqual([aggregateResult.truePositives, aggregateResult.falsePositives, aggregateResult.falseNegatives], [tp, fp, fn]);
  assert.equal(aggregateResult.trueNegatives, universe.size - tp - fp - fn);
  assert.equal(aggregateResult.precision, precision);
  assert.equal(aggregateResult.recall, recall);
  assert.equal(aggregateResult.f1, 0.5);
  assert.equal(aggregateResult.accuracy, 0.5);
  assert.deepEqual(aggregateResult.ruleMetrics, ruleMetrics);
  assert.deepEqual(aggregateResult.scenarioCoverage, scenarioCoverage);
  assert.equal(aggregateResult.evidenceCompleteness, 2 / evaluatedAlerts.length);
  assert.equal(aggregateResult.alertsPer1000Transactions, (predicted.size / universe.size) * 1000);
  assert.equal(aggregateResult.validationPassRate, 0.5);
  assert.equal(aggregateResult.processingTimeSeconds, 2.5);
});
