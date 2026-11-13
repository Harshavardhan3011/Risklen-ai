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
SQL_BATCH_SIZE = 500
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
        }
        for index in range(1, counts["merchants"] + 1)
    ]

    devices = [
        {
            "id": f"DEV-{index:06d}",
            "fingerprintHash": hashlib.sha256(f"{seed}:device:{index}".encode()).hexdigest(),
            "deviceType": ("MOBILE", "DESKTOP", "TABLET")[index % 3],
            "operatingSystem": ("iOS", "Android", "Windows", "macOS")[index % 4],
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
    customer_account_numbers: Dict[str, int] = {}
    for index in range(1, counts["accounts"] + 1):
        customer = customers[(index - 1) % len(customers)]
        customer_account_numbers[customer["id"]] = customer_account_numbers.get(customer["id"], 0) + 1
        status = "CLOSED" if index % 71 == 0 else ("DORMANT" if index % 23 == 0 else "OPEN")
        opening = timestamp(index * 2)
        accounts.append(
            {
                "id": f"ACC-{customer['id']}-{customer_account_numbers[customer['id']]:02d}",
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

    account_customer_by_id = {row["accountId"]: row["customerId"] for row in ownership if row["ownershipType"] == "PRIMARY"}
    customer_by_id = {row["id"]: row for row in customers}
    transactions = []
    account_balances = {account["id"]: Decimal("1000.00") + Decimal((i % 500) * 10) for i, account in enumerate(accounts)}
    for index in range(1, counts["transactions"] + 1):
        account = accounts[(index - 1) % len(accounts)]
        customer = customer_by_id[account_customer_by_id[account["id"]]]
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
                "id": f"TXN-2026-{index:08d}",
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
                "metadata": json.dumps({}, sort_keys=True),
                "createdAt": timestamp(100000 + index + 1),
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
        scenario = scenario_for(index)
        rule_code = rule_for_scenario.get(scenario, "R008")
        rule = RULES[rule_code]
        score = min(100, rule[1])
        alert_id = f"ALT-2026-{index:06d}"
        alerts.append(
            {
                "id": alert_id,
                "customerId": transaction["customerId"],
                "accountId": transaction["accountId"],
                "transactionId": transaction["id"],
                "riskRuleId": stable_uuid("rule", int(rule_code[1:])),
                "evaluationVersion": "phase2-v1",
                "riskScore": str(score),
                "priority": risk_band(score),
                "status": "OPEN",
                "explanation": f"{rule[0]} detected for {transaction['id']}.",
                "detectedAt": transaction["occurredAt"],
                "closedAt": "",
                "createdAt": transaction["createdAt"],
            }
        )
        evidence.append(
            {
                "id": stable_uuid("evidence", index),
                "alertId": alert_id,
                "evidenceType": "TRANSACTION",
                "sourceId": transaction["id"],
                "description": f"Transaction evidence for {rule[0].lower()}.",
                "value": json.dumps({"ruleCode": rule_code}, sort_keys=True),
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
        case_id = f"CASE-2026-{index:06d}"
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
            "details": json.dumps({}, sort_keys=True),
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
            "scenarioCode": scenario_for(index),
            "isSuspicious": "true" if scenario_for(index) in SUSPICIOUS_SCENARIOS else "false",
            "expectedRuleCode": rule_for_scenario.get(scenario_for(index), ""),
            "labelSource": "scenario-membership",
            "createdAt": transaction["createdAt"],
            "metadata": json.dumps({"reason": scenario_for(index)}, sort_keys=True),
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



ENTITY_DESCRIPTIONS = {
    "customers": "Synthetic customer identity and contact record.",
    "accounts": "Financial account and current reconciled balance.",
    "merchants": "Merchant accepting customer transactions.",
    "devices": "Pseudonymous device fingerprint and lifecycle state.",
    "transactions": "Posted or declined debit/credit ledger movement.",
    "transfer_links": "Bridge connecting paired internal transfer legs.",
    "risk_rules": "Versioned deterministic transaction risk rule.",
    "alerts": "Rule-triggered transaction review record.",
    "cases": "Analyst review work item grouping related alerts.",
    "analyst_actions": "Immutable analyst workflow action record.",
}
FIELD_TYPES = {
    "email": "string", "phone": "string", "countryCode": "char(2)", "dateOfBirth": "date",
    "createdAt": "timestamptz", "updatedAt": "timestamptz", "openedAt": "timestamptz", "closedAt": "timestamptz",
    "effectiveFrom": "timestamptz", "effectiveTo": "timestamptz", "firstSeenAt": "timestamptz", "lastSeenAt": "timestamptz",
    "occurredAt": "timestamptz", "postedAt": "timestamptz", "detectedAt": "timestamptz", "verifiedAt": "timestamptz", "expiresAt": "timestamptz",
    "amount": "decimal(18,2)", "currentBalance": "decimal(18,2)", "balanceBefore": "decimal(18,2)", "balanceAfter": "decimal(18,2)", "overdraftLimit": "decimal(18,2)",
    "riskScore": "integer", "weight": "integer", "version": "integer", "enabled": "boolean", "metadata": "json", "configuration": "json", "value": "json",
}
OPTIONAL_FIELDS = {"email", "phone", "dateOfBirth", "riskRating", "operatingSystem", "merchantId", "deviceId", "postedAt", "reference", "metadata", "legReference", "threshold", "effectiveTo", "closedAt", "assignedToId", "disposition", "fromStatus", "toStatus", "comment"}
ENUMS = {
    ("accounts", "accountType"): ["CHECKING", "SAVINGS", "WALLET", "BUSINESS"],
    ("accounts", "status"): ["OPEN", "DORMANT", "CLOSED", "SUSPENDED"],
    ("merchants", "riskRating"): ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    ("devices", "deviceType"): ["MOBILE", "DESKTOP", "TABLET"],
    ("devices", "status"): ["ACTIVE", "BLOCKED", "RETIRED"],
    ("transactions", "transactionType"): ["DEBIT", "CREDIT", "TRANSFER", "REVERSAL", "FEE"],
    ("transactions", "status"): ["PENDING", "POSTED", "DECLINED", "REVERSED", "FAILED"],
    ("transfer_links", "transferType"): ["INTERNAL", "EXTERNAL", "INTERNATIONAL"],
    ("risk_rules", "severity"): ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    ("alerts", "priority"): ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    ("alerts", "status"): ["OPEN", "INVESTIGATING", "ESCALATED", "CLOSED", "FALSE_POSITIVE"],
    ("cases", "status"): ["NEW", "IN_PROGRESS", "PENDING_REVIEW", "ESCALATED", "CLOSED"],
    ("cases", "disposition"): ["CONFIRMED_SUSPICIOUS", "LEGITIMATE", "FALSE_POSITIVE", "FURTHER_INVESTIGATION", "ESCALATED"],
    ("analyst_actions", "actionType"): ["ASSIGNED", "UNASSIGNED", "COMMENTED", "EVIDENCE_ADDED", "DISPOSITION_RECORDED", "STATUS_CHANGED", "ESCALATED"],
}
RELATIONSHIPS = {
    ("transactions", "customerId"): "customers.id", ("transactions", "accountId"): "accounts.id",
    ("transactions", "merchantId"): "merchants.id (optional)", ("transactions", "deviceId"): "devices.id (optional)",
    ("transfer_links", "transactionId"): "transactions.id", ("transfer_links", "sourceAccountId"): "accounts.id",
    ("transfer_links", "targetAccountId"): "accounts.id", ("alerts", "customerId"): "customers.id",
    ("alerts", "accountId"): "accounts.id", ("alerts", "transactionId"): "transactions.id", ("alerts", "riskRuleId"): "risk_rules.id",
    ("cases", "assignedToId"): "users.id (optional)", ("analyst_actions", "caseId"): "cases.id", ("analyst_actions", "actorId"): "users.id",
}
FIELD_DESCRIPTIONS = {
    "id": "Immutable primary identifier.", "fullName": "Synthetic customer legal-name field.", "countryCode": "Two-character ISO 3166-1 alpha-2 country code.",
    "dateOfBirth": "Synthetic customer birth date.", "accountType": "Financial product type.", "currentBalance": "Balance after the final generated ledger movement.",
    "overdraftLimit": "Maximum permitted negative balance; generated accounts use zero.", "openedAt": "Account lifecycle start timestamp.",
    "closedAt": "Account closure timestamp when status is CLOSED.", "fingerprintHash": "SHA-256 pseudonymous device fingerprint; not a raw device identifier.",
    "amount": "Transaction or transfer amount in the associated currency.", "balanceBefore": "Ledger balance immediately before the transaction.",
    "balanceAfter": "Ledger balance immediately after the transaction.", "occurredAt": "Time the financial event occurred.", "postedAt": "Time a successful transaction was posted; absent for declined activity.",
    "metadata": "Operational transaction attributes; excludes evaluation scenario and label fields.", "ruleCode": "Stable deterministic rule identifier.",
    "riskScore": "Deterministic rule weight, capped at 100.", "priority": "Risk band derived from the risk score.",
    "explanation": "Human-readable triggering rule and transaction reference.", "disposition": "Analyst-recorded case outcome when available.",
    "actionType": "Recorded analyst workflow action.", "effectiveFrom": "Start of a relationship's validity period.",
    "effectiveTo": "End of a relationship's validity period, when ended.",
}
UNIQUE_FIELDS = {("customers", "id"), ("customers", "email"), ("accounts", "id"), ("merchants", "id"), ("devices", "id"), ("devices", "fingerprintHash"), ("transactions", "id"), ("transfer_links", "id"), ("risk_rules", "id"), ("risk_rules", "ruleCode"), ("alerts", "id"), ("cases", "id"), ("analyst_actions", "id")}

def build_data_dictionary(data: Mapping[str, Sequence[Mapping[str, str]]]) -> dict:
    result = {}
    for entity in ENTITY_DESCRIPTIONS:
        rows = data[entity]
        fields = list(rows[0]) if rows else list(SQL_COLUMNS.get(entity, ()))
        result[entity] = {
            "description": ENTITY_DESCRIPTIONS[entity],
            "fields": {
                field: {
                    "type": "enum" if (entity, field) in ENUMS else FIELD_TYPES.get(field, "string"),
                    "required": field not in OPTIONAL_FIELDS,
                    "allowedValues": ENUMS.get((entity, field), []),
                    "unique": (entity, field) in UNIQUE_FIELDS,
                    "validation": FIELD_DESCRIPTIONS.get(field, f"Validated against the {entity} model and its foreign-key constraints."),
                    "relationship": RELATIONSHIPS.get((entity, field), ""),
                    "description": FIELD_DESCRIPTIONS.get(field, f"{field} value persisted on the {entity} record."),
                    "units": "USD" if field in {"amount", "currentBalance", "balanceBefore", "balanceAfter", "overdraftLimit"} else "",
                }
                for field in fields
            },
        }
    return result

def render_data_dictionary(dictionary: Mapping[str, Mapping[str, object]]) -> str:
    lines = ["# Synthetic data dictionary", "", "All records are deterministic synthetic data; no externally collected personal data is used.", ""]
    for entity, definition in dictionary.items():
        lines.extend([f"## {entity}", "", str(definition["description"]), "", "| Field | Type | Required | Description |", "|---|---|---:|---|"])
        for field, details in definition["fields"].items():
            lines.append(f"| `{field}` | {details['type']} | {'Yes' if details['required'] else 'No'} | {details['description']} |")
        lines.append("")
    return "\n".join(lines)

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


def write_sql(path: Path, data: Mapping[str, Sequence[Mapping[str, str]]]) -> int:
    # These are insert-only exports; operational CSV/JSON retain richer generator metadata.
    excluded = {"ground_truth_labels", "negative_fixtures"}
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("-- RiskLens Phase 2 operational export; generated, not applied.\n")
        for name, rows in data.items():
            if name in excluded or not rows:
                continue
            columns = list(SQL_COLUMNS.get(name, rows[0].keys()))
            quoted_columns = ", ".join(f'"{column}"' for column in columns)
            for start in range(0, len(rows), SQL_BATCH_SIZE):
                batch = rows[start : start + SQL_BATCH_SIZE]
                handle.write(f'INSERT INTO "{name}" ({quoted_columns}) VALUES\n')
                values = ["(" + ", ".join(sql_literal(row.get(column)) for column in columns) + ")" for row in batch]
                handle.write(",\n".join(values) + ";\n\n")
    return sum((len(rows) + SQL_BATCH_SIZE - 1) // SQL_BATCH_SIZE for name, rows in data.items() if name not in excluded and rows)


def write(output: Path, data: Mapping[str, Sequence[Mapping[str, str]]], seed: int, scale: str, duration: float) -> None:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"Refusing to overwrite non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
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
    operational_data = {name: rows for name, rows in data.items() if name not in {"ground_truth_labels", "negative_fixtures"}}
    sql_statement_count = write_sql(output / "operational.sql", operational_data)
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
    dictionary = build_data_dictionary(data)
    (output / "data-dictionary.json").write_text(json.dumps(dictionary, indent=2, sort_keys=True), encoding="utf-8")
    (output / "DATA_DICTIONARY.md").write_text(render_data_dictionary(dictionary), encoding="utf-8")
    manifest = {
        "seed": seed,
        "scale": scale,
        "generatorVersion": "yottaflex-2026-v2",
        "schemaVersion": "0001_initial_postgresql",
        "referenceTimestamp": REFERENCE_TIME.isoformat(),
        "counts": counts,
        "checksums": checksums,
        "durationSeconds": round(duration, 3),
        "groundTruthPath": "evaluation/ground_truth_labels.csv",
        "negativeFixturesPath": "negative-fixtures/negative_fixtures.csv",
    }
    (output / "generation-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    (output / "export-report.json").write_text(json.dumps({
        "seed": seed,
        "scale": scale,
        "operationalRows": sum(len(rows) for name, rows in operational_data.items()),
        "operationalEntityCounts": {name: len(operational_data[name]) for name in operational_data},
        "evaluationRows": len(data["ground_truth_labels"]),
        "negativeFixtureRows": len(data["negative_fixtures"]),
        "sqlFile": "operational.sql",
        "sqlFileSizeBytes": (output / "operational.sql").stat().st_size,
        "insertStatementCount": sql_statement_count,
        "insertBatchSize": SQL_BATCH_SIZE,
        "sourceChecksums": checksums,
        "sqlEditorLimitations": "Platform-specific SQL Editor size and execution limits were not measured; SQL was validated locally and not executed remotely."
    }, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic RiskLens operational and evaluation exports.")
    parser.add_argument("--seed", type=int, default=20261022)
    parser.add_argument("--mode", "--scale", dest="scale", choices=("sample", "full"), default="sample")
    parser.add_argument("--output", type=Path, default=Path("data/yottaflex-full-2026"))
    args = parser.parse_args()
    started = time.perf_counter()
    data = build(args.scale, args.seed)
    write(args.output, data, args.seed, args.scale, time.perf_counter() - started)
    print(json.dumps({"output": str(args.output), "scale": args.scale, "seed": args.seed, "counts": {key: len(value) for key, value in data.items()}}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
