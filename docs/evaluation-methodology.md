# Evaluation methodology

Ground truth is generated into `evaluation/ground_truth_labels.*` and is never copied into operational transaction metadata, alert text, or operational SQL. Labels are derived deterministically from the generator's seeded scenario assignment and documented `SUSPICIOUS_SCENARIOS` rule set. No label is used as an operational risk input.

Evaluation unit: unique transaction ID. Any alert whose `transactionId` matches a labeled transaction is a positive prediction; duplicate alerts for a transaction count once for overall confusion-matrix metrics. TP, FP, FN, and TN are set intersections over prediction and label IDs. Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2PR/(P+R), accuracy = (TP+TN)/all labeled transactions, and false-positive rate = FP/(FP+TN). A zero denominator yields 0.

Per-rule predictions use the alert's `riskRuleId`; per-rule expected positives use the label's `expectedRuleCode`. Scenario coverage is the share of positive labels for a scenario that have at least one alert. Evidence completeness is the share of alerts with at least one evidence row. Evaluation labels remain separate from analyst-facing APIs and operational risk records.

For the seed-20261022 full export, the report records TP 819, FP 181, FN 0, TN 99,000; precision 0.819, recall 1.0, F1 0.9004947774, accuracy 0.99819, false-positive rate 0.0018249463, evidence completeness 1.0. These are generated dataset evaluation results, not production performance or fraud-loss outcomes.
