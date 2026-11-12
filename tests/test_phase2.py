import json
from pathlib import Path

from generator.generate import TARGETS, build, row_checksum, write
from generator.validate import validate, validate_transfers


def test_same_seed_is_reproducible():
    first = build("sample", 42)
    second = build("sample", 42)
    assert {name: row_checksum(rows) for name, rows in first.items()} == {
        name: row_checksum(rows) for name, rows in second.items()
    }


def test_different_seed_changes_dataset():
    assert row_checksum(build("sample", 42)["transactions"]) != row_checksum(
        build("sample", 43)["transactions"]
    )


def test_circular_transfer_amounts_vary_and_reconcile():
    data = build("sample", 42)
    transactions = {row["id"]: row for row in data["transactions"]}
    grouped = {}
    for transfer in data["transfer_links"]:
        grouped.setdefault(transfer["legReference"], []).append(transfer)

    amounts = set()
    for legs in grouped.values():
        assert len(legs) == 2
        assert legs[0]["amount"] == legs[1]["amount"]
        assert legs[0]["amount"] == transactions[legs[0]["transactionId"]]["amount"]
        assert legs[1]["amount"] == transactions[legs[1]["transactionId"]]["amount"]
        amounts.add(legs[0]["amount"])

    assert len(amounts) > 1


def test_generated_users_are_inert_provisioning_records():
    data = build("full", 42)
    users = data["users"]
    assert len(users) == 10
    assert all(user["status"] == "PENDING" for user in users)
    assert all(user["passwordHash"].startswith("!provisioning-required-") for user in users)
    assert len({user["passwordHash"] for user in users}) == len(users)
    assert all(user["passwordHash"] != "phase2-fixture-password-hash" for user in users)


def test_full_fixed_counts():
    data = build("full", 42)
    assert {name: len(data[name]) for name in TARGETS} == TARGETS
    assert len(data["risk_rules"]) == 9
    assert len(data["negative_fixtures"]) == 5


def test_sample_exports_validate(tmp_path: Path):
    data = build("sample", 42)
    write(tmp_path, data, 42, "sample", 0.1)
    report = validate(tmp_path)
    assert report["passed"] is True
    assert all(fixture["rejected"] for fixture in report["negativeFixtures"])
    assert (tmp_path / "operational.sql").exists()
    assert json.loads((tmp_path / "evaluation-report.json").read_text())["f1"] >= 0


def _transfer_fixture():
    transactions = [
        {"id": "TX-A", "amount": "10.00", "currency": "USD"},
        {"id": "TX-B", "amount": "10.00", "currency": "USD"},
    ]
    accounts = [{"id": "ACC-A"}, {"id": "ACC-B"}]
    transfers = [
        {
            "id": "LINK-A",
            "transactionId": "TX-A",
            "sourceAccountId": "ACC-A",
            "targetAccountId": "ACC-B",
            "amount": "10.00",
            "currency": "USD",
            "legReference": "CIRC-TEST",
        },
        {
            "id": "LINK-B",
            "transactionId": "TX-B",
            "sourceAccountId": "ACC-B",
            "targetAccountId": "ACC-A",
            "amount": "10.00",
            "currency": "USD",
            "legReference": "CIRC-TEST",
        },
    ]
    return transactions, accounts, transfers


def test_transfer_validator_accepts_reconciled_pair():
    transactions, accounts, transfers = _transfer_fixture()
    assert validate_transfers(transfers, transactions, accounts) == []


def test_transfer_validator_rejects_each_invariant():
    variants = []

    transactions, accounts, transfers = _transfer_fixture()
    unequal = [dict(row) for row in transfers]
    unequal[1]["amount"] = "9.00"
    variants.append((unequal, "transfer leg amounts do not reconcile"))

    transactions, accounts, transfers = _transfer_fixture()
    different_currency = [dict(row) for row in transfers]
    different_currency[1]["currency"] = "EUR"
    transactions[1]["currency"] = "EUR"
    variants.append((different_currency, "transfer leg currencies do not match"))

    transactions, accounts, transfers = _transfer_fixture()
    non_reciprocal = [dict(row) for row in transfers]
    non_reciprocal[1]["targetAccountId"] = "ACC-B"
    variants.append((non_reciprocal, "transfer endpoints are not reciprocal"))

    transactions, accounts, transfers = _transfer_fixture()
    missing_transaction = [dict(row) for row in transfers]
    missing_transaction[1]["transactionId"] = "TX-MISSING"
    variants.append((missing_transaction, "missing referenced transaction"))

    transactions, accounts, transfers = _transfer_fixture()
    missing_account = [dict(row) for row in transfers]
    missing_account[0]["sourceAccountId"] = "ACC-MISSING"
    variants.append((missing_account, "missing referenced account: sourceAccountId"))

    transactions, accounts, transfers = _transfer_fixture()
    duplicate = [dict(row) for row in transfers]
    duplicate.append(dict(duplicate[0]))
    variants.append((duplicate, "duplicate transfer leg"))

    transactions, accounts, transfers = _transfer_fixture()
    incorrect_transaction_amount = [dict(row) for row in transfers]
    incorrect_transaction_amount[0]["amount"] = "11.00"
    variants.append((incorrect_transaction_amount, "transfer amount does not match transaction amount"))

    for candidate, expected_reason in variants:
        transactions, accounts, _ = _transfer_fixture()
        failures = validate_transfers(candidate, transactions, accounts)
        assert expected_reason in {failure["reason"] for failure in failures}

