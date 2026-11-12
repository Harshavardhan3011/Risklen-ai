import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { test } from "node:test";
import {
  authenticatePostgresUser,
  validatePostgresToken,
  type PostgresAuthRecord,
  type PostgresAuthStore,
} from "../src/postgres-auth.js";

const secret = "test-postgres-auth-secret";

function makeStore(record: PostgresAuthRecord): { store: PostgresAuthStore; records: Map<string, PostgresAuthRecord> } {
  const records = new Map([[record.id, record]]);
  return {
    records,
    store: {
      async findByEmail(email) {
        return [...records.values()].find((user) => user.email === email) ?? null;
      },
      async findById(id) {
        return records.get(id) ?? null;
      },
    },
  };
}

function activeRecord(): PostgresAuthRecord {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "postgres-user@example.test",
    name: "Postgres User",
    role: "ANALYST",
    passwordHash: bcrypt.hashSync("correct password 123", 12),
    status: "ACTIVE",
    authVersion: 0,
  };
}

test("PostgreSQL authentication accepts ACTIVE bcrypt users", async () => {
  const { store } = makeStore(activeRecord());
  const result = await authenticatePostgresUser(store, "postgres-user@example.test", "correct password 123", secret);
  assert.ok(result);
  assert.equal(result.user.authVersion, 0);
  assert.equal("passwordHash" in result.user, false);
});

test("PostgreSQL authentication rejects missing and disabled users", async () => {
  const record = activeRecord();
  const { store, records } = makeStore(record);
  assert.equal(await authenticatePostgresUser(store, "missing@example.test", "correct password 123", secret), null);
  records.set(record.id, { ...record, status: "DISABLED" });
  assert.equal(await authenticatePostgresUser(store, record.email, "correct password 123", secret), null);
});

test("PostgreSQL token validation rejects missing users and role changes", async () => {
  const record = activeRecord();
  const { store, records } = makeStore(record);
  const result = await authenticatePostgresUser(store, record.email, "correct password 123", secret);
  assert.ok(result);

  records.delete(record.id);
  await assert.rejects(() => validatePostgresToken(store, result.token, secret), /Invalid or expired token/);

  records.set(record.id, { ...record, role: "ADMIN", authVersion: 1 });
  await assert.rejects(() => validatePostgresToken(store, result.token, secret), /Invalid or expired token/);
});

test("PostgreSQL token validation rejects password and status changes", async () => {
  const record = activeRecord();
  const { store, records } = makeStore(record);
  const result = await authenticatePostgresUser(store, record.email, "correct password 123", secret);
  assert.ok(result);

  records.set(record.id, { ...record, passwordHash: bcrypt.hashSync("replacement password 123", 12), authVersion: 1 });
  await assert.rejects(() => validatePostgresToken(store, result.token, secret), /Invalid or expired token/);

  records.set(record.id, { ...record, status: "LOCKED", authVersion: 1 });
  await assert.rejects(() => validatePostgresToken(store, result.token, secret), /Invalid or expired token/);
});
