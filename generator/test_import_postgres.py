from __future__ import annotations

import pytest

from .import_postgres import build_report, run_atomic


def test_full_export_dry_run_passes():
    report = build_report(__import__("pathlib").Path("data/phase2-full"))
    assert report["passed"], report["errors"]
    assert report["operational_rows"] == 146276
    assert report["evaluation_rows"] == 100000
    assert report["negative_fixture_rows"] == 5
    assert report["sql_statements"] == 22


class FakeTransaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeConnection:
    def __init__(self):
        self.rollback_called = False

    def transaction(self):
        return FakeTransaction(self)

    def rollback(self):
        self.rollback_called = True


def test_atomic_operation_rolls_back_on_failure():
    connection = FakeConnection()
    with pytest.raises(RuntimeError, match="import failure"):
        run_atomic(connection, lambda _: (_ for _ in ()).throw(RuntimeError("import failure")))
    assert connection.rollback_called
