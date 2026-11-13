"""Prepare and optionally execute a guarded PostgreSQL dataset import.

Dry-run is the default and performs no database connection. Execution requires
both --execute and --confirm-import, and uses one atomic transaction for
operational and evaluation data. Negative fixtures are never imported.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

OPERATIONAL_ORDER = (
    "users",
    "customers",
    "kyc_profiles",
    "accounts",
    "account_owners",
    "merchants",
    "devices",
    "customer_devices",
    "transactions",
    "transfer_links",
    "risk_rules",
    "alerts",
    "cases",
    "case_alerts",
    "analyst_actions",
    "alert_evidence",
    "account_events",
    "alert_events",
    "case_events",
    "audit_events",
    "generation_runs",
    "validation_results",
)

UUID_COLUMNS = {
    "users": ("id",),
    "kyc_profiles": ("id",),
    "risk_rules": ("id",),
    "alerts": ("riskRuleId",),
    "cases": ("assignedToId",),
    "analyst_actions": ("id", "actorId"),
    "alert_evidence": ("id",),
    "account_events": ("id", "actorId"),
    "alert_events": ("id", "actorId"),
    "case_events": ("id", "actorId"),
    "audit_events": ("id", "actorId"),
    "generation_runs": ("id",),
    "validation_results": ("id", "generationRunId"),
}

DECIMAL_COLUMNS = {
    "accounts": ("currentBalance", "overdraftLimit"),
    "transactions": ("amount", "balanceBefore", "balanceAfter"),
    "transfer_links": ("amount",),
    "risk_rules": ("threshold",),
}

JSON_COLUMNS = {
    "transactions": ("metadata",),
    "risk_rules": ("configuration",),
    "alert_evidence": ("value",),
    "account_events": ("details",),
    "alert_events": ("details",),
    "case_events": ("details",),
    "audit_events": ("details",),
    "generation_runs": ("metadata",),
    "validation_results": ("details",),
}

ENUM_VALUES = {
    ("users", "role"): {"ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"},
    ("users", "status"): {"PENDING", "ACTIVE", "DISABLED", "LOCKED"},
    ("kyc_profiles", "status"): {"PENDING", "VERIFIED", "REVIEW", "REJECTED", "EXPIRED"},
    ("accounts", "accountType"): {"CHECKING", "SAVINGS", "WALLET", "BUSINESS"},
    ("accounts", "status"): {"OPEN", "DORMANT", "CLOSED", "SUSPENDED"},
    ("devices", "status"): {"ACTIVE", "BLOCKED", "RETIRED"},
    ("transactions", "transactionType"): {"DEBIT", "CREDIT", "TRANSFER", "REVERSAL", "FEE"},
    ("transactions", "status"): {"PENDING", "POSTED", "DECLINED", "REVERSED", "FAILED"},
    ("transfer_links", "transferType"): {"INTERNAL", "EXTERNAL", "INTERNATIONAL"},
    ("risk_rules", "severity"): {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
    ("alerts", "priority"): {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
    ("alerts", "status"): {"OPEN", "INVESTIGATING", "ESCALATED", "CLOSED", "FALSE_POSITIVE"},
    ("cases", "status"): {"NEW", "IN_PROGRESS", "PENDING_REVIEW", "ESCALATED", "CLOSED"},
    ("cases", "disposition"): {"CONFIRMED_SUSPICIOUS", "LEGITIMATE", "FALSE_POSITIVE", "FURTHER_INVESTIGATION", "ESCALATED"},
    ("analyst_actions", "actionType"): {"ASSIGNED", "UNASSIGNED", "COMMENTED", "EVIDENCE_ADDED", "DISPOSITION_RECORDED", "STATUS_CHANGED", "ESCALATED"},
    ("analyst_actions", "fromStatus"): {"NEW", "IN_PROGRESS", "PENDING_REVIEW", "ESCALATED", "CLOSED"},
    ("analyst_actions", "toStatus"): {"NEW", "IN_PROGRESS", "PENDING_REVIEW", "ESCALATED", "CLOSED"},
    ("analyst_actions", "disposition"): {"CONFIRMED_SUSPICIOUS", "LEGITIMATE", "FALSE_POSITIVE", "FURTHER_INVESTIGATION", "ESCALATED"},
    ("alert_evidence", "evidenceType"): {"TRANSACTION", "ACCOUNT", "CUSTOMER", "DEVICE", "MERCHANT", "TRANSFER", "RULE_MATCH", "SYSTEM"},
    ("generation_runs", "status"): {"STARTED", "COMPLETED", "FAILED"},
    ("validation_results", "status"): {"PASSED", "FAILED", "WARNING"},
}

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
DECIMAL_RE = re.compile(r"^-?\d{1,16}\.\d{2}$")
INSERT_RE = re.compile(r'^INSERT INTO "([^"]+)" \(([^)]+)\) VALUES', re.MULTILINE)
COMPOSITE_KEYS = {
    "account_owners": ("accountId", "customerId", "effectiveFrom"),
    "customer_devices": ("customerId", "deviceId", "effectiveFrom"),
    "case_alerts": ("caseId", "alertId"),
    "risk_rules": ("ruleCode", "version"),
    "alerts": ("riskRuleId", "transactionId", "evaluationVersion"),
    "transfer_links": ("transactionId", "sourceAccountId", "targetAccountId"),
}


def row_checksum(rows: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(list(rows), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def load_rows(directory: Path, entity: str) -> List[dict]:
    path = directory / "operational" / f"{entity}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def split_sql_statements(sql: str) -> List[str]:
    sql = re.sub(r"(?m)^\s*--[^\r\n]*(?:\r?\n|$)", "", sql)
    statements: List[str] = []
    start = 0
    in_string = False
    index = 0
    while index < len(sql):
        char = sql[index]
        if char == "'" and (index == 0 or sql[index - 1] != "\\"):
            if in_string and index + 1 < len(sql) and sql[index + 1] == "'":
                index += 2
                continue
            in_string = not in_string
        elif char == ";" and not in_string:
            statement = sql[start:index + 1].strip()
            if statement:
                statements.append(statement)
            start = index + 1
        index += 1
    trailing = sql[start:].strip()
    if trailing:
        statements.append(trailing)
    return statements


def validate_rows(entity: str, rows: Sequence[Mapping[str, Any]], errors: List[str]) -> None:
    primary_keys = set()
    composite_keys = set()
    for row_number, row in enumerate(rows, start=2):
        primary_key = row.get("id")
        if primary_key is not None:
            if primary_key in primary_keys:
                errors.append(f"{entity} duplicate primary key at row {row_number}: {primary_key}")
            primary_keys.add(primary_key)
        composite_columns = COMPOSITE_KEYS.get(entity)
        if composite_columns:
            composite = tuple(row.get(column) for column in composite_columns)
            if composite in composite_keys:
                errors.append(f"{entity} duplicate composite key at row {row_number}")
            composite_keys.add(composite)
        for column in UUID_COLUMNS.get(entity, ()):
            value = row.get(column)
            if value not in (None, "") and not UUID_RE.fullmatch(str(value)):
                errors.append(f"{entity}.{column} row {row_number} is not a UUID")
        for column in DECIMAL_COLUMNS.get(entity, ()):
            value = row.get(column)
            if value not in (None, ""):
                try:
                    decimal_value = Decimal(str(value))
                    if not DECIMAL_RE.fullmatch(str(value)) or decimal_value.as_tuple().exponent != -2:
                        raise InvalidOperation
                    if abs(decimal_value) >= Decimal("10000000000000000"):
                        raise InvalidOperation
                except InvalidOperation:
                    errors.append(f"{entity}.{column} row {row_number} is not Decimal(18,2)")
        for column in JSON_COLUMNS.get(entity, ()):
            value = row.get(column)
            if value not in (None, ""):
                try:
                    json.loads(value)
                except (TypeError, json.JSONDecodeError):
                    errors.append(f"{entity}.{column} row {row_number} is not valid JSON")
        for (enum_entity, column), values in ENUM_VALUES.items():
            if enum_entity == entity and row.get(column) not in (None, "") and row[column] not in values:
                errors.append(f"{entity}.{column} row {row_number} has invalid enum value")
        for column, value in row.items():
            if value not in (None, "") and (column.endswith("At") or column in {"occurredAt", "postedAt"}):
                try:
                    datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"{entity}.{column} row {row_number} is not a valid timestamp")


def validate_foreign_keys(data: Mapping[str, Sequence[Mapping[str, Any]]], errors: List[str]) -> None:
    ids = {entity: {row.get("id") for row in rows} for entity, rows in data.items()}
    references = {
        "kyc_profiles": (("customerId", "customers"),),
        "account_owners": (("accountId", "accounts"), ("customerId", "customers")),
        "customer_devices": (("customerId", "customers"), ("deviceId", "devices")),
        "transactions": (("customerId", "customers"), ("accountId", "accounts"), ("merchantId", "merchants"), ("deviceId", "devices")),
        "transfer_links": (("transactionId", "transactions"), ("sourceAccountId", "accounts"), ("targetAccountId", "accounts")),
        "alerts": (("customerId", "customers"), ("accountId", "accounts"), ("transactionId", "transactions"), ("riskRuleId", "risk_rules")),
        "cases": (("assignedToId", "users"),),
        "case_alerts": (("caseId", "cases"), ("alertId", "alerts")),
        "analyst_actions": (("caseId", "cases"), ("actorId", "users")),
        "alert_evidence": (("alertId", "alerts"),),
        "account_events": (("accountId", "accounts"), ("actorId", "users")),
        "alert_events": (("alertId", "alerts"), ("actorId", "users")),
        "case_events": (("caseId", "cases"), ("actorId", "users")),
        "audit_events": (("actorId", "users"),),
        "validation_results": (("generationRunId", "generation_runs"),),
    }
    for entity, entity_references in references.items():
        for row_number, row in enumerate(data.get(entity, ()), start=2):
            for column, target in entity_references:
                value = row.get(column)
                if value not in (None, "") and value not in ids.get(target, set()):
                    errors.append(f"{entity}.{column} row {row_number} references missing {target}")


def validate_evaluation_rows(rows: Sequence[Mapping[str, Any]], errors: List[str]) -> None:
    primary_keys = set()
    composite_keys = set()
    for row_number, row in enumerate(rows, start=2):
        identifier = row.get("id")
        if identifier in primary_keys:
            errors.append(f"ground_truth_labels duplicate primary key at row {row_number}")
        primary_keys.add(identifier)
        if identifier not in (None, "") and not UUID_RE.fullmatch(str(identifier)):
            errors.append(f"ground_truth_labels.id row {row_number} is not a UUID")
        composite = (row.get("transactionId"), row.get("scenarioCode"))
        if composite in composite_keys:
            errors.append(f"ground_truth_labels duplicate transaction/scenario key at row {row_number}")
        composite_keys.add(composite)
        if row.get("isSuspicious") not in {"true", "false", True, False}:
            errors.append(f"ground_truth_labels.isSuspicious row {row_number} is not boolean")
        try:
            datetime.fromisoformat(str(row["createdAt"]).replace("Z", "+00:00"))
        except (KeyError, ValueError):
            errors.append(f"ground_truth_labels.createdAt row {row_number} is not a valid timestamp")
        if row.get("metadata") not in (None, ""):
            try:
                json.loads(row["metadata"])
            except (TypeError, json.JSONDecodeError):
                errors.append(f"ground_truth_labels.metadata row {row_number} is not valid JSON")


def run_atomic(connection: Any, operation: Any) -> Any:
    """Run an operation inside one driver transaction and explicitly rollback failures."""
    try:
        with connection.transaction():
            return operation(connection)
    except BaseException:
        rollback = getattr(connection, "rollback", None)
        if callable(rollback):
            rollback()
        raise


def build_report(directory: Path) -> dict:
    manifest = json.loads((directory / "generation-manifest.json").read_text(encoding="utf-8"))
    errors: List[str] = []
    data = {entity: load_rows(directory, entity) for entity in OPERATIONAL_ORDER}
    for entity, rows in data.items():
        expected_count = manifest["counts"].get(entity)
        expected_checksum = manifest["checksums"].get(entity)
        if expected_count != len(rows):
            errors.append(f"{entity} count mismatch")
        if expected_checksum != row_checksum(rows):
            errors.append(f"{entity} checksum mismatch")
        csv_path = directory / "operational" / f"{entity}.csv"
        with csv_path.open(newline="", encoding="utf-8") as handle:
            if sum(1 for _ in csv.DictReader(handle)) != len(rows):
                errors.append(f"{entity} CSV count mismatch")
        validate_rows(entity, rows, errors)
    validate_foreign_keys(data, errors)

    sql = (directory / "operational.sql").read_text(encoding="utf-8")
    statements = split_sql_statements(sql)
    sql_tables = [match.group(1) for match in INSERT_RE.finditer(sql)]
    legacy_order = list(OPERATIONAL_ORDER)
    expected_batched_order = [entity for entity in OPERATIONAL_ORDER for _ in range((len(data[entity]) + 499) // 500)]
    legacy_sql = sql_tables == legacy_order and len(statements) == len(legacy_order)
    batched_sql = sql_tables == expected_batched_order and len(statements) == len(expected_batched_order)
    if not (legacy_sql or batched_sql):
        errors.append("operational SQL batches/count/order do not match the dependency order")
    if re.search(r"\b(DROP|DELETE|TRUNCATE|UPDATE|ALTER|CREATE)\b", sql, re.IGNORECASE):
        errors.append("operational SQL contains a destructive or schema-changing command")

    users = data["users"]
    if any(row.get("role") != "ANALYST" or row.get("status") != "PENDING" for row in users):
        errors.append("generated users are not inert ANALYST/PENDING records")
    if len({row.get("passwordHash") for row in users}) != len(users):
        errors.append("generated user provisioning markers are not unique")
    ground_truth = json.loads((directory / "evaluation" / "ground_truth_labels.json").read_text(encoding="utf-8"))
    expected_ground_truth_count = manifest["counts"].get("ground_truth_labels")
    if expected_ground_truth_count != len(ground_truth):
        errors.append("ground_truth_labels count mismatch")
    if manifest["checksums"].get("ground_truth_labels") != row_checksum(ground_truth):
        errors.append("ground_truth_labels checksum mismatch")
    validate_evaluation_rows(ground_truth, errors)
    fixtures = json.loads((directory / "negative-fixtures" / "negative_fixtures.json").read_text(encoding="utf-8"))
    if manifest["counts"].get("negative_fixtures") != len(fixtures):
        errors.append("negative fixture count mismatch")
    return {
        "passed": not errors,
        "errors": errors,
        "operational_rows": sum(len(rows) for rows in data.values()),
        "operational_entities": len(OPERATIONAL_ORDER),
        "evaluation_rows": len(ground_truth),
        "negative_fixture_rows": len(fixtures),
        "sql_statements": len(statements),
        "insert_order": list(sql_tables),
        "transaction_strategy": "one transaction covering operational and evaluation data; rollback on any failure",
        "checksums_verified": not any("checksum" in error for error in errors),
    }


def normalize_psycopg_database_url(database_url: str) -> str:
    """Remove Prisma-only schema configuration from the psycopg URL."""
    parts = urlsplit(database_url)

    if parts.scheme not in ("postgres", "postgresql"):
        raise ValueError("DATABASE_URL must use postgres or postgresql scheme")

    params = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() != "schema"
    ]

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(params),
        parts.fragment,
    ))


def verify_target_preflight(cursor: Any) -> None:
    # Fail safely instead of waiting indefinitely for concurrent writers.
    cursor.execute("SET LOCAL lock_timeout = '15s'")

    lock_targets = [
        f'"public"."{table}"'
        for table in OPERATIONAL_ORDER
    ]
    lock_targets.append('"evaluation"."ground_truth_labels"')

    cursor.execute(
        "LOCK TABLE "
        + ", ".join(lock_targets)
        + " IN SHARE ROW EXCLUSIVE MODE"
    )

    migration_rows = cursor.execute(
        'SELECT "migration_name" FROM "_prisma_migrations" '
        'WHERE "migration_name" IN (%s, %s) AND "finished_at" IS NOT NULL',
        ("0001_initial_postgresql", "0002_user_status"),
    ).fetchall()
    applied = {row[0] for row in migration_rows}
    if applied != {"0001_initial_postgresql", "0002_user_status"}:
        raise RuntimeError("Target migration history is not exactly compatible with migrations 0001 and 0002")

    required_columns = {
        ("public", "users", "passwordHash"),
        ("public", "users", "status"),
        ("evaluation", "ground_truth_labels", "transactionId"),
    }
    columns = {
        tuple(row)
        for row in cursor.execute(
            "SELECT table_schema, table_name, column_name FROM information_schema.columns "
            "WHERE (table_schema, table_name, column_name) IN "
            "((%s, %s, %s), (%s, %s, %s), (%s, %s, %s))",
            (
                "public", "users", "passwordHash",
                "public", "users", "status",
                "evaluation", "ground_truth_labels", "transactionId",
            ),
        ).fetchall()
    }
    if not required_columns.issubset(columns):
        raise RuntimeError("Target schema is missing required 0001/0002 import columns")

    for table in OPERATIONAL_ORDER:
        count = cursor.execute(f'SELECT COUNT(*) FROM "public"."{table}"').fetchone()[0]
        if count:
            raise RuntimeError(f"Target table public.{table} is not empty ({count} rows)")
    evaluation_count = cursor.execute('SELECT COUNT(*) FROM "evaluation"."ground_truth_labels"').fetchone()[0]
    if evaluation_count:
        raise RuntimeError(f"Target table evaluation.ground_truth_labels is not empty ({evaluation_count} rows)")


def execute_import(directory: Path, database_url: str) -> None:
    try:
        import psycopg
    except ImportError as error:
        raise RuntimeError("psycopg is required only when explicitly executing an import") from error
    report = build_report(directory)
    if not report["passed"]:
        raise ValueError(json.dumps(report, sort_keys=True))
    statements = split_sql_statements((directory / "operational.sql").read_text(encoding="utf-8"))
    ground_truth = json.loads((directory / "evaluation" / "ground_truth_labels.json").read_text(encoding="utf-8"))

    with psycopg.connect(normalize_psycopg_database_url(database_url)) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                verify_target_preflight(cursor)
                for statement in statements:
                    cursor.execute(statement)
                for row in ground_truth:
                    cursor.execute(
                        'INSERT INTO "evaluation"."ground_truth_labels" '
                        '("id", "transactionId", "customerId", "scenarioCode", "isSuspicious", '
                        '"expectedRuleCode", "labelSource", "createdAt", "metadata") '
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            row["id"],
                            row["transactionId"],
                            row.get("customerId") or None,
                            row["scenarioCode"],
                            row["isSuspicious"].lower() == "true" if isinstance(row["isSuspicious"], str) else row["isSuspicious"],
                            row.get("expectedRuleCode") or None,
                            row["labelSource"],
                            row["createdAt"],
                            row.get("metadata") or None,
                        ),
                    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Dry-run or explicitly execute the guarded RiskLens PostgreSQL import.")
    parser.add_argument("--input", type=Path, default=Path("data/phase2-full"))
    parser.add_argument("--database-url")
    parser.add_argument("--execute", action="store_true", help="Enable database execution; omitted by default.")
    parser.add_argument("--confirm-import", action="store_true", help="Required with --execute.")
    args = parser.parse_args()
    report = build_report(args.input)
    if args.execute:
        if not args.confirm_import:
            raise SystemExit("--confirm-import is required with --execute")
        if not args.database_url:
            raise SystemExit("--database-url is required with --execute")
        execute_import(args.input, args.database_url)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
