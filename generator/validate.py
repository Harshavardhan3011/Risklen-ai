"""Validate RiskLens exports and calculate data-driven evaluation metrics."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from .generate import RULES, TARGETS, risk_band, stable_uuid
from .import_postgres import OPERATIONAL_ORDER, validate_evaluation_rows, validate_foreign_keys, validate_rows


def read_rows(directory: Path, name: str, folder: str = "operational") -> List[dict]:
    path = directory / folder / f"{name}.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def ids_unique(rows: Sequence[Mapping[str, str]], key: str) -> bool:
    values = [row.get(key, "") for row in rows]
    return all(values) and len(values) == len(set(values))


def check_references(rows: Sequence[Mapping[str, str]], key: str, values: set) -> bool:
    return all(row.get(key, "") in values for row in rows)


def validate_transfers(
    transfers: Sequence[Mapping[str, str]],
    transactions: Sequence[Mapping[str, str]],
    accounts: Sequence[Mapping[str, str]],
) -> List[dict]:
    transaction_map = {row["id"]: row for row in transactions}
    account_ids = {row["id"] for row in accounts}
    grouped: Dict[str, List[Mapping[str, str]]] = defaultdict(list)
    failures: List[dict] = []
    seen_legs = set()

    for transfer in transfers:
        reference = transfer.get("legReference", "")
        if not reference:
            failures.append({"reference": reference, "reason": "missing transfer reference"})
            continue
        grouped[reference].append(transfer)
        leg_key = (
            transfer.get("transactionId"),
            transfer.get("sourceAccountId"),
            transfer.get("targetAccountId"),
        )
        if leg_key in seen_legs:
            failures.append({"reference": reference, "reason": "duplicate transfer leg"})
        seen_legs.add(leg_key)
        transaction = transaction_map.get(transfer.get("transactionId"))
        if transaction is None:
            failures.append({"reference": reference, "reason": "missing referenced transaction"})
        else:
            if transfer.get("amount") != transaction.get("amount"):
                failures.append(
                    {
                        "reference": reference,
                        "reason": "transfer amount does not match transaction amount",
                        "transferId": transfer.get("id"),
                    }
                )
            if transfer.get("currency") != transaction.get("currency"):
                failures.append(
                    {
                        "reference": reference,
                        "reason": "transfer currency does not match transaction currency",
                        "transferId": transfer.get("id"),
                    }
                )
        for field in ("sourceAccountId", "targetAccountId"):
            if transfer.get(field) not in account_ids:
                failures.append(
                    {
                        "reference": reference,
                        "reason": f"missing referenced account: {field}",
                        "transferId": transfer.get("id"),
                    }
                )

    for reference, legs in grouped.items():
        if len(legs) != 2:
            failures.append(
                {
                    "reference": reference,
                    "reason": f"expected exactly 2 transfer legs, found {len(legs)}",
                }
            )
            continue
        first, second = legs
        if first.get("amount") != second.get("amount"):
            failures.append({"reference": reference, "reason": "transfer leg amounts do not reconcile"})
        if first.get("currency") != second.get("currency"):
            failures.append({"reference": reference, "reason": "transfer leg currencies do not match"})
        if not (
            first.get("sourceAccountId") == second.get("targetAccountId")
            and first.get("targetAccountId") == second.get("sourceAccountId")
        ):
            failures.append({"reference": reference, "reason": "transfer endpoints are not reciprocal"})
    return failures


def validate_negative_fixture(fixture: Mapping[str, str]) -> str | None:
    fixture_type = fixture.get("type")
    if fixture_type == "closed_account_transaction":
        return fixture.get("expectedError") if fixture.get("accountStatus") == "CLOSED" and fixture.get("transactionStatus") != "DECLINED" else None
    if fixture_type == "negative_balance_without_overdraft":
        return fixture.get("expectedError") if Decimal(fixture.get("balanceAfter", "0")) < -Decimal(fixture.get("overdraftLimit", "0")) else None
    if fixture_type == "mismatched_transfer_legs":
        return fixture.get("expectedError") if fixture.get("sourceAmount") != fixture.get("targetAmount") else None
    if fixture_type == "alert_without_transaction":
        return fixture.get("expectedError") if not fixture.get("transactionId") else None
    if fixture_type == "case_disposition_before_alert":
        return fixture.get("expectedError") if fixture.get("dispositionAt", "") < fixture.get("alertCreatedAt", "") else None
    return None


def evaluate(alerts: Sequence[Mapping[str, str]], ground_truth: Sequence[Mapping[str, str]], transactions: Sequence[Mapping[str, str]], evidence: Sequence[Mapping[str, str]], validation_pass_rate: float = 0.0) -> dict:
    truth = {row["transactionId"]: row["isSuspicious"].lower() == "true" for row in ground_truth}
    predicted = {row["transactionId"] for row in alerts}
    actual_positive = {transaction_id for transaction_id, suspicious in truth.items() if suspicious}
    tp = len(predicted & actual_positive)
    fp = len(predicted - actual_positive)
    fn = len(actual_positive - predicted)
    tn = len(set(truth) - predicted - actual_positive)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    by_rule = {}
    for rule_code in RULES:
        rule_predicted = {row["transactionId"] for row in alerts if row.get("riskRuleId") == stable_uuid("rule", int(rule_code[1:]))}
        rule_tp = len(rule_predicted & actual_positive)
        rule_fp = len(rule_predicted - actual_positive)
        rule_truth = {row["transactionId"] for row in ground_truth if row.get("expectedRuleCode") == rule_code}
        rule_fn = len(rule_truth - rule_predicted)
        by_rule[rule_code] = {
            "precision": rule_tp / (rule_tp + rule_fp) if rule_tp + rule_fp else 0.0,
            "recall": rule_tp / (rule_tp + rule_fn) if rule_tp + rule_fn else 0.0,
            "alerts": len(rule_predicted),
        }
    scenario_coverage = {}
    scenarios = sorted({row["scenarioCode"] for row in ground_truth})
    for scenario in scenarios:
        expected = {row["transactionId"] for row in ground_truth if row["scenarioCode"] == scenario and row["isSuspicious"].lower() == "true"}
        scenario_coverage[scenario] = len(expected & predicted) / len(expected) if expected else 1.0
    return {
        "evaluationUnit": "transaction: an alert is a positive prediction when its transactionId matches a ground-truth transaction.",
        "matchingMethod": "Exact transaction ID matching; multiple alerts for one transaction count once.",
        "truePositives": tp,
        "falsePositives": fp,
        "falseNegatives": fn,
        "trueNegatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "falsePositiveRate": false_positive_rate,
        "accuracy": (tp + tn) / len(truth) if truth else 0.0,
        "ruleMetrics": by_rule,
        "scenarioDetectionCoverage": scenario_coverage,
        "alertsPer1000Transactions": len(alerts) * 1000 / len(transactions) if transactions else 0.0,
        "evidenceCompleteness": len({row["alertId"] for row in evidence}) / len(alerts) if alerts else 1.0,
        "validationPassRate": validation_pass_rate,
    }


def validate(directory: Path) -> dict:
    manifest = json.loads((directory / "generation-manifest.json").read_text(encoding="utf-8"))
    operational_names = [
        "users", "customers", "kyc_profiles", "accounts", "account_owners",
        "merchants", "devices", "customer_devices", "transactions", "transfer_links",
        "risk_rules", "alerts", "cases", "case_alerts", "analyst_actions",
        "alert_evidence", "account_events", "alert_events", "case_events",
        "audit_events", "generation_runs", "validation_results",
    ]
    data = {name: read_rows(directory, name) for name in operational_names}
    ground_truth = read_rows(directory, "ground_truth_labels", "evaluation")
    fixtures = read_rows(directory, "negative_fixtures", "negative-fixtures")
    customers = data["customers"]
    accounts = data["accounts"]
    transactions = data["transactions"]
    alerts = data["alerts"]
    checks: List[dict] = []

    def add(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    expected = TARGETS if manifest["scale"] == "full" else {
        "customers": 50, "accounts": 70, "merchants": 20,
        "devices": 30, "transactions": 1000, "alerts": 100,
    }
    for name, count in expected.items():
        add(f"{name}_count", len(data[name]) == count, f"expected {count}, actual {len(data[name])}")
    schema_errors: List[str] = []
    for entity in OPERATIONAL_ORDER:
        validate_rows(entity, data[entity], schema_errors)
    validate_foreign_keys(data, schema_errors)
    add("schema_types_enums_and_all_foreign_keys", not schema_errors, json.dumps(schema_errors[:10]))
    for name, key in (
        ("customers", "id"), ("accounts", "id"),
        ("merchants", "id"), ("devices", "id"), ("devices", "fingerprintHash"),
        ("transactions", "id"), ("alerts", "id"), ("risk_rules", "id"),
    ):
        add(f"{name}_{key}_unique", ids_unique(data[name], key))

    add("account_id_format", all(__import__("re").fullmatch(r"ACC-CUS-\d{6}-\d{2}", row["id"]) for row in accounts))
    add("account_ids_unique", ids_unique(accounts, "id"))
    add("generated_user_state", len(data["users"]) == 10 and all(row["role"] == "ANALYST" and row["status"] == "PENDING" for row in data["users"]))
    add("customer_id_format", all(__import__("re").fullmatch(r"CUS-\d{6}", row["id"]) for row in customers))
    add("transaction_id_format", all(__import__("re").fullmatch(r"TXN-2026-\d{8}", row["id"]) for row in transactions))
    add("alert_id_format", all(__import__("re").fullmatch(r"ALT-2026-\d{6}", row["id"]) for row in alerts))
    add("case_id_format", all(__import__("re").fullmatch(r"CASE-2026-\d{6}", row["id"]) for row in data["cases"]))
    customer_ids = {row["id"] for row in customers}
    account_ids = {row["id"] for row in accounts}
    merchant_ids = {row["id"] for row in data["merchants"]}
    device_ids = {row["id"] for row in data["devices"]}
    transaction_ids = {row["id"] for row in transactions}
    alert_ids = {row["id"] for row in alerts}
    case_ids = {row["id"] for row in data["cases"]}
    user_ids = {row["id"] for row in data["users"]}
    rule_ids = {row["id"] for row in data["risk_rules"]}
    add("account_customer_references", check_references(data["account_owners"], "customerId", customer_ids))
    add("account_references", check_references(data["account_owners"], "accountId", account_ids))
    add("kyc_customer_references", check_references(data["kyc_profiles"], "customerId", customer_ids))
    add("customer_device_references", check_references(data["customer_devices"], "customerId", customer_ids) and check_references(data["customer_devices"], "deviceId", device_ids))
    add("transaction_references", check_references(transactions, "customerId", customer_ids) and check_references(transactions, "accountId", account_ids) and all(not row["merchantId"] or row["merchantId"] in merchant_ids for row in transactions) and all(not row["deviceId"] or row["deviceId"] in device_ids for row in transactions))
    add("transfer_references", check_references(data["transfer_links"], "transactionId", transaction_ids) and check_references(data["transfer_links"], "sourceAccountId", account_ids) and check_references(data["transfer_links"], "targetAccountId", account_ids))
    add("alert_references", check_references(alerts, "transactionId", transaction_ids) and check_references(alerts, "accountId", account_ids) and check_references(alerts, "customerId", customer_ids) and check_references(alerts, "riskRuleId", rule_ids))
    add("case_alert_references", check_references(data["case_alerts"], "caseId", case_ids) and check_references(data["case_alerts"], "alertId", alert_ids))
    add("analyst_action_references", check_references(data["analyst_actions"], "caseId", case_ids) and check_references(data["analyst_actions"], "actorId", user_ids))
    add("evidence_references", check_references(data["alert_evidence"], "alertId", alert_ids))
    transfer_failures = validate_transfers(
        data["transfer_links"], transactions, accounts
    )
    add(
        "transfer_reconciliation",
        not transfer_failures,
        json.dumps(transfer_failures, sort_keys=True),
    )

    financial_ok = True
    temporal_ok = True
    account_map = {row["id"]: row for row in accounts}
    for row in transactions:
        try:
            before, amount, after = Decimal(row["balanceBefore"]), Decimal(row["amount"]), Decimal(row["balanceAfter"])
        except InvalidOperation:
            financial_ok = False
            continue
        if row["status"] == "DECLINED":
            financial_ok = financial_ok and before == after
        elif row["transactionType"] == "DEBIT":
            financial_ok = financial_ok and after == before - amount
        else:
            financial_ok = financial_ok and after == before + amount
        financial_ok = financial_ok and after >= Decimal("0.00")
        if row["occurredAt"] < account_map[row["accountId"]]["openedAt"]:
            temporal_ok = False
        if account_map[row["accountId"]]["status"] == "CLOSED" and row["status"] != "DECLINED":
            temporal_ok = False
    add("financial_reconciliation", financial_ok)
    add("temporal_constraints", temporal_ok)
    by_account: Dict[str, List[Mapping[str, str]]] = defaultdict(list)
    for row in transactions:
        by_account[row["accountId"]].append(row)
    balances_ok = True
    for account_index, account in enumerate(accounts, 1):
        movements = sorted(by_account[account["id"]], key=lambda row: row["occurredAt"])
        expected_start = Decimal("1000.00") + Decimal(((account_index - 1) % 500) * 10)
        balance = expected_start
        for movement in movements:
            if Decimal(movement["balanceBefore"]) != balance:
                balances_ok = False
            balance = Decimal(movement["balanceAfter"])
        if movements and Decimal(account["currentBalance"]) != balance:
            balances_ok = False
    add("account_balance_reconciliation", balances_ok)
    add("transfer_currency_consistency", all(row["currency"] == "USD" for row in data["transfer_links"]))
    add("risk_rules_complete", len(data["risk_rules"]) == 9 and {row["ruleCode"] for row in data["risk_rules"]} == set(RULES))
    add("alert_scores_and_bands", all(0 <= int(row["riskScore"]) <= 100 and risk_band(int(row["riskScore"])) == row["priority"] for row in alerts))
    add("alert_evidence_complete", {row["id"] for row in alerts} == {row["alertId"] for row in data["alert_evidence"]})
    leaked = any("scenario" in str(row.get("metadata", "")).lower() or "scenarioCode" in row for name in operational_names for row in data[name])
    add("ground_truth_isolated", all(row.get("labelSource") == "scenario-membership" for row in ground_truth) and not leaked, "Operational rows must not contain scenario labels.")
    gt_errors: List[str] = []
    validate_evaluation_rows(ground_truth, gt_errors)
    add("ground_truth_integrity", not gt_errors and check_references(ground_truth, "transactionId", transaction_ids) and all(not row.get("customerId") or row["customerId"] in customer_ids for row in ground_truth), json.dumps(gt_errors[:10]))
    transaction_by_id = {row["id"]: row for row in transactions}
    alerts_match = all(alert["customerId"] == transaction_by_id[alert["transactionId"]]["customerId"] and alert["accountId"] == transaction_by_id[alert["transactionId"]]["accountId"] for alert in alerts)
    add("alert_matches_triggering_transaction", alerts_match)
    posted_states = all((row["status"] == "POSTED") == bool(row.get("postedAt")) for row in transactions)
    add("transaction_posting_timestamps", posted_states)
    case_map = {row["id"]: row for row in data["cases"]}
    alert_map = {row["id"]: row for row in alerts}
    case_alert_times_ok = all(case_map[link["caseId"]]["openedAt"] <= alert_map[link["alertId"]]["detectedAt"] and (not case_map[link["caseId"]].get("closedAt") or case_map[link["caseId"]]["closedAt"] >= alert_map[link["alertId"]]["createdAt"]) for link in data["case_alerts"])
    add("case_alert_lifecycle_order", case_alert_times_ok)
    action_times_ok = all(row["createdAt"] >= case_map[row["caseId"]]["openedAt"] for row in data["analyst_actions"])
    add("analyst_action_lifecycle_order", action_times_ok)
    detected = [validate_negative_fixture(fixture) for fixture in fixtures]
    add("negative_fixtures_rejected", len(detected) == 5 and all(detected) and all(found == fixture["expectedError"] for found, fixture in zip(detected, fixtures)))
    validation_pass_rate = sum(1 for check in checks if check["passed"]) / len(checks) if checks else 0.0
    metrics = evaluate(alerts, ground_truth, transactions, data["alert_evidence"], validation_pass_rate)
    report = {
        "passed": all(check["passed"] for check in checks),
        "scale": manifest["scale"],
        "checks": checks,
        "negativeFixtures": [{"fixtureId": fixture["fixtureId"], "type": fixture["type"], "transactionId": fixture.get("transactionId"), "rejected": found is not None, "detected": found is not None, "detectedError": found, "expectedError": fixture["expectedError"]} for fixture, found in zip(fixtures, detected)],
        "transferFailures": transfer_failures,
        "metrics": metrics,
    }
    (directory / "validation-report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    (directory / "evaluation-report.json").write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate RiskLens exports and calculate evaluation metrics.")
    parser.add_argument("--input", type=Path, default=Path("data/full"))
    args = parser.parse_args()
    report = validate(args.input)
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
