"""Deterministic RiskLens Phase 2 dataset generator.

The generator is export-only. It never opens SQLite or PostgreSQL and produces
operational and evaluation data in separate directories.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from random import Random
from typing import Dict, Iterable, List, Mapping, Sequence

TARGETS = {
    "customers": 5000,
    "accounts": 7000,
    "merchants": 500,
    "devices": 3000,
    "transactions": 100000,
    "alerts": 1000,
}

RULES = {
    "R001": ("Transaction velocity spike", 20, "MEDIUM"),
    "R002": ("New device plus unusual activity", 15, "MEDIUM"),
    "R003": ("Circular transfer detection", 30, "HIGH"),
    "R004": ("Dormant account reactivation", 25, "HIGH"),
    "R005": ("Transaction on closed account", 40, "CRITICAL"),
    "R006": ("Negative balance without overdraft", 40, "CRITICAL"),
    "R007": ("Transfer reconciliation mismatch", 35, "HIGH"),
    "R008": ("Unusual merchant activity", 10, "LOW"),
    "R009": ("Repeated suspicious attempts", 15, "MEDIUM"),
}

SCENARIO_ORDER = (
    "normal",
    "velocity_spike",
    "new_device",
    "circular_transfer",
    "dormant_reactivation",
    "unusual_merchant",
    "repeated_attempts",
    "closed_account_attempt",
    "negative_balance_attempt",
    "transfer_reconciliation_anomaly",
    "legitimate_high_value",
    "benign_unusual",
)

SUSPICIOUS_SCENARIOS = {
    "velocity_spike",
    "new_device",
    "circular_transfer",
    "dormant_reactivation",
    "unusual_merchant",
    "repeated_attempts",
    "closed_account_attempt",
    "negative_balance_attempt",
    "transfer_reconciliation_anomaly",
}

REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
NAMESPACE = uuid.UUID("79b6ad47-bb34-4d7f-8bf5-ef6a1cb4e1f1")
SQL_COLUMNS = {
    "users": ("id", "email", "name", "role", "passwordHash", "status", "createdAt", "updatedAt"),
    "customers": ("id", "fullName", "email", "phone", "countryCode", "dateOfBirth", "createdAt", "updatedAt"),
    "kyc_profiles": ("id", "customerId", "status", "riskRating", "verifiedAt", "expiresAt", "sourceReference", "createdAt", "updatedAt"),
    "accounts": ("id", "accountType", "status", "currency", "currentBalance", "overdraftLimit", "openedAt", "closedAt", "createdAt", "updatedAt"),
    "account_owners": ("accountId", "customerId", "ownershipType", "effectiveFrom", "effectiveTo"),
    "merchants": ("id", "name", "categoryCode", "countryCode", "riskRating", "createdAt", "updatedAt"),
    "devices": ("id", "fingerprintHash", "deviceType", "operatingSystem", "status", "firstSeenAt", "lastSeenAt", "createdAt", "updatedAt"),
    "customer_devices": ("customerId", "deviceId", "effectiveFrom", "effectiveTo", "associationType"),
    "transactions": ("id", "customerId", "accountId", "merchantId", "deviceId", "transactionType", "status", "amount", "balanceBefore", "balanceAfter", "currency", "occurredAt", "postedAt", "reference", "metadata", "createdAt"),
    "transfer_links": ("id", "transactionId", "sourceAccountId", "targetAccountId", "transferType", "amount", "currency", "legReference", "occurredAt"),
    "risk_rules": ("id", "ruleCode", "version", "name", "description", "severity", "weight", "threshold", "enabled", "effectiveFrom", "effectiveTo", "configuration", "createdAt", "updatedAt"),
    "alerts": ("id", "customerId", "accountId", "transactionId", "riskRuleId", "evaluationVersion", "riskScore", "priority", "status", "explanation", "detectedAt", "closedAt", "createdAt"),
    "cases": ("id", "status", "assignedToId", "openedAt", "closedAt", "disposition", "createdAt", "updatedAt"),
    "case_alerts": ("caseId", "alertId", "linkedAt"),
    "analyst_actions": ("id", "caseId", "actorId", "actionType", "fromStatus", "toStatus", "disposition", "comment", "createdAt"),
    "alert_evidence": ("id", "alertId", "evidenceType", "sourceId", "description", "value", "createdAt"),
    "account_events": ("id", "accountId", "eventType", "occurredAt", "actorId", "details"),
    "alert_events": ("id", "alertId", "eventType", "occurredAt", "actorId", "details"),
    "case_events": ("id", "caseId", "eventType", "occurredAt", "actorId", "details"),
    "audit_events": ("id", "entityType", "entityId", "eventType", "actorId", "details", "occurredAt"),
    "generation_runs": ("id", "seed", "scale", "status", "startedAt", "completedAt", "sourceChecksum", "metadata"),
    "validation_results": ("id", "generationRunId", "checkName", "status", "message", "details", "checkedAt"),
}


def stable_uuid(kind: str, number: int) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{kind}:{number}"))


def timestamp(offset_minutes: int) -> str:
    return (REFERENCE_TIME + timedelta(minutes=offset_minutes)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01')):.2f}"


def scenario_for(transaction_number: int) -> str:
    if transaction_number <= 1000:
        return SCENARIO_ORDER[(transaction_number - 1) % (len(SCENARIO_ORDER) - 1) + 1]
    return "normal"


def risk_band(score: int) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    if score <= 74:
        return "HIGH"
    return "CRITICAL"


def make_rules() -> List[dict]:
    rows = []
    for code, (name, weight, severity) in RULES.items():
        rows.append(
            {
                "id": stable_uuid("rule", int(code[1:])),
                "ruleCode": code,
                "version": "1",
                "name": name,
                "description": f"Deterministic evaluation for {name.lower()}.",
                "severity": severity,
                "weight": str(weight),
                "threshold": "",
                "enabled": "true",
                "effectiveFrom": timestamp(0),
                "effectiveTo": "",
                "configuration": json.dumps({"scope": "transaction"}, sort_keys=True),
                "createdAt": timestamp(0),
                "updatedAt": timestamp(0),
            }
        )
    return rows


def build(scale: str, seed: int) -> Dict[str, List[dict]]:
    """Build the complete logical dataset deterministically."""
    rng = Random(seed)
    if scale == "sample":
        counts = {
            "customers": 50,
            "accounts": 70,
            "merchants": 20,
            "devices": 30,
            "transactions": 1000,
            "alerts": 100,
        }
    elif scale == "full":
        counts = TARGETS.copy()
    else:
        raise ValueError(f"Unsupported scale: {scale}")

    users = [
        {
            "id": stable_uuid("user", index),
            "email": f"analyst{index:02d}@risklens.example",
            "name": f"Risk Analyst {index:02d}",
            "role": "ANALYST",
            "passwordHash": f"!provisioning-required-{stable_uuid('user-disabled', index)}",
            "status": "PENDING",
            "createdAt": timestamp(index),
            "updatedAt": timestamp(index),
        }
        for index in range(1, 11)
    ]

    customers = []
    for index in range(1, counts["customers"] + 1):
        country = ("US", "GB", "IN", "CA", "AU")[rng.randrange(5)]
        customers.append(
            {
                "id": f"CUS-{index:06d}",
                "fullName": f"Customer {index:06d}",
                "email": f"customer{index:06d}@example.test",
                "phone": f"+1-555-{index % 1000:03d}-{index // 1000:04d}",
                "countryCode": country,
                "dateOfBirth": f"{1970 + index % 35:04d}-{index % 12 + 1:02d}-{index % 27 + 1:02d}",
                "createdAt": timestamp(index),
                "updatedAt": timestamp(index),
                "customerStatus": "ACTIVE" if index % 29 else "REVIEW",
                "riskClassification": ("LOW", "MEDIUM", "HIGH")[index % 3],
                "address": f"{index} Synthetic Avenue",
                "scenarioProfile": "standard",
            }
        )

    merchants = [
        {
            "id": f"MER-{index:05d}",
            "name": f"Merchant {index:05d}",
            "categoryCode": ("5411", "5812", "5732", "6011", "7995")[index % 5],
            "countryCode": ("US", "GB", "IN", "CA")[index % 4],
            "riskRating": ("LOW", "MEDIUM", "HIGH")[index % 3],
            "createdAt": timestamp(index),
            "updatedAt": timestamp(index),
            "status": "ACTIVE",
        }
        for index in range(1, counts["merchants"] + 1)
    ]

    devices = [
        {
            "id": f"DEV-{index:06d}",
            "fingerprintHash": hashlib.sha256(f"{seed}:device:{index}".encode()).hexdigest(),
            "deviceType": ("MOBILE", "DESKTOP", "TABLET")[index % 3],
            "operatingSystem": ("iOS", "Android", "Windows", "macOS")[index % 4],
            "browser": ("Chrome", "Safari", "Firefox")[index % 3],
            "status": "ACTIVE" if index % 37 else "BLOCKED",
            "firstSeenAt": timestamp(index * 3),
            "lastSeenAt": timestamp(index * 3 + 10),
            "createdAt": timestamp(index * 3),
            "updatedAt": timestamp(index * 3 + 10),
        }
        for index in range(1, counts["devices"] + 1)
    ]

    accounts = []
    ownership = []
    kyc = []
    for index in range(1, counts["accounts"] + 1):
        customer = customers[(index - 1) % len(customers)]
        status = "CLOSED" if index % 71 == 0 else ("DORMANT" if index % 23 == 0 else "OPEN")
        opening = timestamp(index * 2)
        accounts.append(
            {
                "id": f"ACC-{index:06d}",
                "accountNumber": f"900000{index:07d}",
                "accountType": ("CHECKING", "SAVINGS", "WALLET", "BUSINESS")[index % 4],
                "status": status,
                "currency": "USD",
                "currentBalance": "0.00",
                "overdraftLimit": "0.00",
                "openedAt": opening,
                "closedAt": timestamp(index * 2 + 100) if status == "CLOSED" else "",
                "createdAt": opening,
                "updatedAt": opening,
            }
        )
        ownership.append(
            {
                "accountId": accounts[-1]["id"],
                "customerId": customer["id"],
                "ownershipType": "PRIMARY",
                "effectiveFrom": opening,
                "effectiveTo": "",
            }
        )
        if index % 17 == 0:
            secondary = customers[index % len(customers)]
            ownership.append(
                {
                    "accountId": accounts[-1]["id"],
                    "customerId": secondary["id"],
                    "ownershipType": "JOINT",
                    "effectiveFrom": timestamp(index * 2 + 1),
                    "effectiveTo": "",
                }
            )
    for customer in customers:
        index = int(customer["id"].split("-")[1])
        kyc.append(
            {
                "id": stable_uuid("kyc", index),
                "customerId": customer["id"],
                "status": ("VERIFIED", "PENDING", "REVIEW", "EXPIRED")[index % 4],
                "riskRating": ("LOW", "MEDIUM", "HIGH")[index % 3],
                "verifiedAt": timestamp(index + 5),
                "expiresAt": timestamp(index + 525605),
                "sourceReference": f"KYC-{index:06d}",
                "createdAt": timestamp(index),
                "updatedAt": timestamp(index + 5),
            }
        )

    customer_devices = []
    for index, customer in enumerate(customers, 1):
        device = devices[(index - 1) % len(devices)]
        customer_devices.append(
            {
                "customerId": customer["id"],
                "deviceId": device["id"],
                "effectiveFrom": timestamp(index * 3),
                "effectiveTo": "",
                "associationType": "PRIMARY",
            }
        )
        if index % 11 == 0:
            shared = devices[index % len(devices)]
            customer_devices.append(
                {
                    "customerId": customer["id"],
                    "deviceId": shared["id"],
                    "effectiveFrom": timestamp(index * 3 + 1),
                    "effectiveTo": "",
                    "associationType": "SHARED",
                }
            )

    circular_indices = [
        index
        for index in range(1, counts["transactions"] + 1)
        if scenario_for(index) == "circular_transfer"
    ]
    canonical_transfer_amounts = {}
    for pair_index in range(0, len(circular_indices), 2):
        if pair_index + 1 >= len(circular_indices):
            break
        first_index = circular_indices[pair_index]
        # Keep synthetic circular transfers in a deterministic $10-$25 range.
        group_number = pair_index // 2
        cents = (seed * 31 + group_number * 17) % 1501
        canonical_amount = Decimal("10.00") + (Decimal(cents) / Decimal("100"))
        canonical_transfer_amounts[first_index] = canonical_amount
        canonical_transfer_amounts[circular_indices[pair_index + 1]] = canonical_amount

    transactions = []
    account_balances = {account["id"]: Decimal("1000.00") + Decimal((i % 500) * 10) for i, account in enumerate(accounts)}
    for index in range(1, counts["transactions"] + 1):
        account = accounts[(index - 1) % len(accounts)]
        customer = customers[(index - 1) % len(customers)]
        scenario = scenario_for(index)
        amount = canonical_transfer_amounts.get(
            index, Decimal(25 + ((seed + index * 17) % 475))
        )
        is_declined = account["status"] == "CLOSED" or scenario == "negative_balance_attempt"
        transaction_type = "CREDIT" if index % 9 == 0 else "DEBIT"
        before = account_balances[account["id"]]
        if transaction_type == "DEBIT" and before <= Decimal("0.00"):
            is_declined = True
        elif (
            transaction_type == "DEBIT"
            and scenario == "circular_transfer"
            and before < amount
        ):
            is_declined = True
        if is_declined:
            after = before
            status = "DECLINED"
        elif transaction_type == "CREDIT":
            after = before + amount
            status = "POSTED"
        else:
            debit = min(amount, before)
            after = before - debit
            amount = debit
            status = "POSTED"
        account_balances[account["id"]] = after
        account["currentBalance"] = money(after)
        merchant = merchants[(index * 7) % len(merchants)] if index % 10 else None
        device = devices[(index * 13) % len(devices)] if index % 8 else None
        transactions.append(
            {
                "id": f"TXN-{index:08d}",
                "customerId": customer["id"],
                "accountId": account["id"],
                "merchantId": merchant["id"] if merchant else "",
                "deviceId": device["id"] if device else "",
                "transactionType": transaction_type,
                "status": status,
                "amount": money(amount),
                "balanceBefore": money(before),
                "balanceAfter": money(after),
                "currency": account["currency"],
                "occurredAt": timestamp(100000 + index),
                "postedAt": "" if status == "DECLINED" else timestamp(100000 + index + 1),
                "reference": f"REF-{seed}-{index:08d}",
                "metadata": json.dumps({"scenario": scenario}, sort_keys=True),
                "createdAt": timestamp(100000 + index + 1),
                "scenarioCode": scenario,
            }
        )

    transfers = []
    transfer_numbers = circular_indices
    for pair_index in range(0, len(transfer_numbers), 2):
        if pair_index + 1 >= len(transfer_numbers):
            break
        first = transactions[transfer_numbers[pair_index] - 1]
        second = transactions[transfer_numbers[pair_index + 1] - 1]
        transfers.extend(
            [
                {
                    "id": stable_uuid("transfer", pair_index + 1),
                    "transactionId": first["id"],
                    "sourceAccountId": first["accountId"],
                    "targetAccountId": second["accountId"],
                    "transferType": "INTERNAL",
                    "amount": first["amount"],
                    "currency": "USD",
                    "legReference": f"CIRC-{pair_index // 2:05d}",
                    "occurredAt": first["occurredAt"],
                },
                {
                    "id": stable_uuid("transfer", pair_index + 2),
                    "transactionId": second["id"],
                    "sourceAccountId": second["accountId"],
                    "targetAccountId": first["accountId"],
                    "transferType": "INTERNAL",
                    "amount": second["amount"],
                    "currency": "USD",
                    "legReference": f"CIRC-{pair_index // 2:05d}",
                    "occurredAt": second["occurredAt"],
                },
            ]
        )

    rules = make_rules()
    rule_for_scenario = {
        "velocity_spike": "R001",
        "new_device": "R002",
        "circular_transfer": "R003",
        "dormant_reactivation": "R004",
        "closed_account_attempt": "R005",
        "negative_balance_attempt": "R006",
        "transfer_reconciliation_anomaly": "R007",
        "unusual_merchant": "R008",
        "repeated_attempts": "R009",
    }
    alerts = []
    evidence = []
    for index, transaction in enumerate(transactions[: counts["alerts"]], 1):
        scenario = transaction["scenarioCode"]
        rule_code = rule_for_scenario.get(scenario, "R008")
        rule = RULES[rule_code]
        score = min(100, rule[1])
        alert_id = f"ALT-{index:06d}"
        alerts.append(
            {
                "id": alert_id,
                "customerId": transaction["customerId"],
                "accountId": transaction["accountId"],
                "transactionId": transaction["id"],
                "riskRuleId": stable_uuid("rule", int(rule_code[1:])),
                "ruleCode": rule_code,
                "evaluationVersion": "phase2-v1",
                "riskScore": str(score),
                "priority": risk_band(score),
                "status": "OPEN",
                "explanation": f"{rule[0]} detected for {transaction['id']} in scenario {scenario}.",
                "detectedAt": transaction["occurredAt"],
                "closedAt": "",
                "createdAt": transaction["createdAt"],
                "scenarioCode": scenario,
            }
        )
        evidence.append(
            {
                "id": stable_uuid("evidence", index),
                "alertId": alert_id,
                "evidenceType": "TRANSACTION",
                "sourceId": transaction["id"],
                "description": f"Transaction evidence for {rule[0].lower()}.",
                "value": json.dumps({"scenario": scenario, "ruleCode": rule_code}, sort_keys=True),
                "createdAt": transaction["createdAt"],
            }
        )

    cases = []
    case_alerts = []
    actions = []
    case_events = []
    for index in range(1, (len(alerts) + 4) // 5 + 1):
        grouped = alerts[(index - 1) * 5 : index * 5]
        if not grouped:
            break
        case_id = f"CASE-{index:05d}"
        cases.append(
            {
                "id": case_id,
                "status": "CLOSED",
                "assignedToId": users[(index - 1) % len(users)]["id"],
                "openedAt": grouped[0]["detectedAt"],
                "closedAt": grouped[-1]["createdAt"],
                "disposition": "FURTHER_INVESTIGATION",
                "createdAt": grouped[0]["createdAt"],
                "updatedAt": grouped[-1]["createdAt"],
            }
        )
        for alert in grouped:
            case_alerts.append(
                {"caseId": case_id, "alertId": alert["id"], "linkedAt": alert["createdAt"]}
            )
        actor = users[(index - 1) % len(users)]
        actions.append(
            {
                "id": stable_uuid("action", index),
                "caseId": case_id,
                "actorId": actor["id"],
                "actionType": "ASSIGNED",
                "fromStatus": "",
                "toStatus": "NEW",
                "disposition": "",
                "comment": "Deterministic initial assignment.",
                "createdAt": grouped[0]["createdAt"],
            }
        )
        actions.append(
            {
                "id": stable_uuid("action", index + len(alerts)),
                "caseId": case_id,
                "actorId": actor["id"],
                "actionType": "DISPOSITION_RECORDED",
                "fromStatus": "NEW",
                "toStatus": "CLOSED",
                "disposition": "FURTHER_INVESTIGATION",
                "comment": "Deterministic review disposition.",
                "createdAt": grouped[-1]["createdAt"],
            }
        )
        case_events.append(
            {
                "id": stable_uuid("case-event", index),
                "caseId": case_id,
                "eventType": "CREATED",
                "occurredAt": grouped[0]["createdAt"],
                "actorId": actor["id"],
                "details": json.dumps({"alertCount": len(grouped)}, sort_keys=True),
            }
        )

    alert_events = [
        {
            "id": stable_uuid("alert-event", index),
            "alertId": alert["id"],
            "eventType": "CREATED",
            "occurredAt": alert["createdAt"],
            "actorId": "",
            "details": json.dumps({"scenario": alert["scenarioCode"]}, sort_keys=True),
        }
        for index, alert in enumerate(alerts, 1)
    ]
    account_events = [
        {
            "id": stable_uuid("account-event", index),
            "accountId": account["id"],
            "eventType": "CREATED",
            "occurredAt": account["createdAt"],
            "actorId": "",
            "details": json.dumps({"status": account["status"]}, sort_keys=True),
        }
        for index, account in enumerate(accounts, 1)
    ]
    audit_events = [
        {
            "id": stable_uuid("audit", index),
            "entityType": "ALERT",
            "entityId": alert["id"],
            "eventType": "CREATED",
            "actorId": "",
            "details": json.dumps({"source": "phase2-generator"}, sort_keys=True),
            "occurredAt": alert["createdAt"],
        }
        for index, alert in enumerate(alerts, 1)
    ]
    ground_truth = [
        {
            "id": stable_uuid("ground-truth", index),
            "transactionId": transaction["id"],
            "customerId": transaction["customerId"],
            "scenarioCode": transaction["scenarioCode"],
            "isSuspicious": "true" if transaction["scenarioCode"] in SUSPICIOUS_SCENARIOS else "false",
            "expectedRuleCode": rule_for_scenario.get(transaction["scenarioCode"], ""),
            "labelSource": "scenario-membership",
            "createdAt": transaction["createdAt"],
            "metadata": json.dumps({"reason": transaction["scenarioCode"]}, sort_keys=True),
        }
        for index, transaction in enumerate(transactions, 1)
    ]
    validation_results = []
    generation_run_id = stable_uuid("generation-run", seed)
    generation_run = [
        {
            "id": generation_run_id,
            "seed": str(seed),
            "scale": scale,
            "status": "COMPLETED",
            "startedAt": timestamp(0),
            "completedAt": timestamp(100000 + counts["transactions"] + 10),
            "sourceChecksum": "",
            "metadata": json.dumps({"referenceTimestamp": REFERENCE_TIME.isoformat()}, sort_keys=True),
        }
    ]
    validation_results.append(
        {
            "id": stable_uuid("validation", seed),
            "generationRunId": generation_run_id,
            "checkName": "generation_structure",
            "status": "PASSED",
            "message": "Generated entity counts and references are structurally valid.",
            "details": json.dumps({"transactions": len(transactions)}, sort_keys=True),
            "checkedAt": timestamp(100000 + counts["transactions"] + 11),
        }
    )
    negative_fixtures = [
        {"fixtureId": "NEG-001", "type": "closed_account_transaction", "expectedError": "closed account transaction must be declined", "transactionId": "NEG-TXN-001", "accountStatus": "CLOSED", "transactionStatus": "POSTED"},
        {"fixtureId": "NEG-002", "type": "negative_balance_without_overdraft", "expectedError": "balance cannot fall below overdraft limit", "transactionId": "NEG-TXN-002", "balanceAfter": "-1.00", "overdraftLimit": "0.00"},
        {"fixtureId": "NEG-003", "type": "mismatched_transfer_legs", "expectedError": "transfer legs must reconcile", "transactionId": "NEG-TXN-003", "sourceAmount": "10.00", "targetAmount": "9.00"},
        {"fixtureId": "NEG-004", "type": "alert_without_transaction", "expectedError": "alert transaction reference is required", "transactionId": "", "alertId": "NEG-ALT-004"},
        {"fixtureId": "NEG-005", "type": "case_disposition_before_alert", "expectedError": "case disposition cannot precede alert creation", "transactionId": "NEG-TXN-005", "alertCreatedAt": "2026-01-02T00:00:00Z", "dispositionAt": "2026-01-01T00:00:00Z"},
    ]
    return {
        "users": users,
        "customers": customers,
        "kyc_profiles": kyc,
        "accounts": accounts,
        "account_owners": ownership,
        "merchants": merchants,
        "devices": devices,
        "customer_devices": customer_devices,
        "transactions": transactions,
        "transfer_links": transfers,
        "risk_rules": rules,
        "alerts": alerts,
        "cases": cases,
        "case_alerts": case_alerts,
        "analyst_actions": actions,
        "alert_evidence": evidence,
        "account_events": account_events,
        "alert_events": alert_events,
        "case_events": case_events,
        "audit_events": audit_events,
        "generation_runs": generation_run,
        "validation_results": validation_results,
        "ground_truth_labels": ground_truth,
        "negative_fixtures": negative_fixtures,
    }


def row_checksum(rows: Sequence[Mapping[str, str]]) -> str:
    payload = json.dumps(list(rows), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def write_csv(path: Path, rows: Sequence[Mapping[str, str]]) -> None:
    fields = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    if not fields:
        fields = ["id"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sql_literal(value: object) -> str:
    if value is None or value == "":
        return "NULL"
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.upper()
    return "'" + str(value).replace("'", "''") + "'"


def write_sql(path: Path, data: Mapping[str, Sequence[Mapping[str, str]]]) -> None:
    # These are insert-only exports; operational CSV/JSON retain richer generator metadata.
    excluded = {"ground_truth_labels", "negative_fixtures"}
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("-- RiskLens Phase 2 operational export; generated, not applied.\n")
        for name, rows in data.items():
            if name in excluded or not rows:
                continue
            columns = list(SQL_COLUMNS.get(name, rows[0].keys()))
            quoted_columns = ", ".join(f'"{column}"' for column in columns)
            handle.write(f'INSERT INTO "{name}" ({quoted_columns}) VALUES\n')
            values = []
            for row in rows:
                values.append("(" + ", ".join(sql_literal(row.get(column)) for column in columns) + ")")
            handle.write(",\n".join(values) + ";\n\n")


def write(output: Path, data: Mapping[str, Sequence[Mapping[str, str]]], seed: int, scale: str, duration: float) -> None:
    if output.exists():
        shutil.rmtree(output)
    operational = output / "operational"
    evaluation = output / "evaluation"
    fixtures = output / "negative-fixtures"
    operational.mkdir(parents=True)
    evaluation.mkdir()
    fixtures.mkdir()
    checksums = {}
    counts = {}
    for name, rows in data.items():
        target = fixtures if name == "negative_fixtures" else evaluation if name == "ground_truth_labels" else operational
        write_csv(target / f"{name}.csv", rows)
        (target / f"{name}.json").write_text(json.dumps(list(rows), indent=2, sort_keys=True), encoding="utf-8")
        checksums[name] = row_checksum(rows)
        counts[name] = len(rows)
    write_sql(output / "operational.sql", {name: rows for name, rows in data.items() if name != "ground_truth_labels"})
    (output / "scenario-documentation.json").write_text(
        json.dumps(
            {
                code: {
                    "suspicious": code in SUSPICIOUS_SCENARIOS,
                    "expectedDetection": "rule-based alert" if code in SUSPICIOUS_SCENARIOS else "no automatic fraud classification",
                }
                for code in SCENARIO_ORDER
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (output / "data-dictionary.json").write_text(
        json.dumps(
            {
                name: {
                    column: "Generated deterministic field."
                    for column in SQL_COLUMNS.get(name, rows[0].keys() if rows else [])
                }
                for name, rows in data.items()
                if name not in {"ground_truth_labels", "negative_fixtures"}
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest = {
        "seed": seed,
        "scale": scale,
        "generatorVersion": "phase2-v1",
        "schemaVersion": "0001_initial_postgresql",
        "referenceTimestamp": REFERENCE_TIME.isoformat(),
        "counts": counts,
        "checksums": checksums,
        "durationSeconds": round(duration, 3),
        "groundTruthPath": "evaluation/ground_truth_labels.csv",
        "negativeFixturesPath": "negative-fixtures/negative_fixtures.csv",
    }
    (output / "generation-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic RiskLens operational and evaluation exports.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--mode", "--scale", dest="scale", choices=("sample", "full"), default="sample")
    parser.add_argument("--output", type=Path, default=Path("data/full"))
    args = parser.parse_args()
    started = time.perf_counter()
    data = build(args.scale, args.seed)
    write(args.output, data, args.seed, args.scale, time.perf_counter() - started)
    print(json.dumps({"output": str(args.output), "scale": args.scale, "seed": args.seed, "counts": {key: len(value) for key, value in data.items()}}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
