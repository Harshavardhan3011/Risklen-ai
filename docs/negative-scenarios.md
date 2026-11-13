# Negative scenario fixtures

The generator creates these deliberately invalid records only in `negative-fixtures/`. They are not inserted into operational CSV or SQL. `generator.validate` evaluates the violated invariant and records both the expected and detected error in `validation-report.json`.

| Fixture | Invalid condition | Expected validation result |
|---|---|---|
| NEG-001 | A posted transaction references a closed account. | Reject: closed-account transaction must be declined. |
| NEG-002 | A transaction ends below its zero overdraft limit. | Reject: balance cannot fall below the overdraft limit. |
| NEG-003 | Paired transfer legs have different amounts. | Reject: transfer legs must reconcile. |
| NEG-004 | An alert has no triggering transaction reference. | Reject: alert transaction reference is required. |
| NEG-005 | A case disposition predates its alert. | Reject: disposition cannot precede alert creation. |

Each fixture has its own `NEG-*` identifier and a traceable `NEG-TXN-*` or `NEG-ALT-*` reference. The full validation report records actual detection results.
