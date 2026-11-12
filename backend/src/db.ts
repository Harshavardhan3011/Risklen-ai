import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import bcrypt from "bcryptjs";

export type Alert = {
  id: string; customerId: string; accountId: string; transactionId: string;
  ruleId: string; ruleName: string; score: number; priority: string;
  explanation: string; status: string; createdAt: string;
};

const configuredPath = process.env.RISKLENS_DB;
const testDirectory = process.env.NODE_ENV === "test" ? mkdtempSync(join(tmpdir(), "risklens-test-")) : null;
const databasePath = configuredPath ?? (testDirectory ? join(testDirectory, "risklens.db") : "risklens.db");
if (testDirectory && !existsSync(databasePath) && existsSync("risklens.db")) {
  copyFileSync("risklens.db", databasePath);
}
const db = new Database(databasePath);
if (testDirectory) {
  db.exec("DELETE FROM users");
  process.once("exit", () => {
    db.close();
    rmSync(testDirectory, { recursive: true, force: true });
  });
}
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS _risklens_migrations (id TEXT PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', auth_version INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, account_id TEXT NOT NULL, transaction_id TEXT NOT NULL, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL, score INTEGER NOT NULL, priority TEXT NOT NULL, explanation TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, status TEXT NOT NULL, disposition TEXT, assigned_to TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(alert_id) REFERENCES alerts(id));
CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);
`);

export type MigrationDefinition = {
  id: string;
  name: string;
  up: () => void;
};

const migrations: MigrationDefinition[] = [
  {
    id: "0001_user_status",
    name: "Add user account status",
    up: () => {
      const columns = db.prepare("PRAGMA table_info(users)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "status")) {
        db.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'PENDING'");
      }
    },
  },
  {
    id: "0002_user_auth_version",
    name: "Add user authentication version",
    up: () => {
      const columns = db.prepare("PRAGMA table_info(users)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "auth_version")) {
        db.exec("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0");
      }
    },
  },
];

export function runMigrations(definitions: MigrationDefinition[] = migrations): void {
  const applied = db.prepare("SELECT id FROM _risklens_migrations").all() as Array<{ id: string }>;
  const appliedIds = new Set(applied.map((migration) => migration.id));
  for (const migration of definitions) {
    if (appliedIds.has(migration.id)) continue;
    db.transaction(() => {
      migration.up();
      db.prepare("INSERT INTO _risklens_migrations (id, name, applied_at) VALUES (?, ?, ?)")
        .run(migration.id, migration.name, new Date().toISOString());
    })();
  }
}

runMigrations();

const now = () => new Date().toISOString();
export type UserStatus = "PENDING" | "ACTIVE" | "DISABLED" | "LOCKED";
export type UserRecord = {
  id: string;
  email: string;
  name: string;
  role: string;
  status: UserStatus;
  password: string;
  authVersion: number;
};

export function createUser(input: {
  email: string;
  name: string;
  role?: string;
  password: string;
  status?: UserStatus;
}): Omit<UserRecord, "password"> {
  if (Buffer.byteLength(input.password, "utf8") > 72) {
    throw new RangeError("Password must be 72 UTF-8 bytes or fewer");
  }
  const user = {
    id: randomUUID(),
    email: input.email,
    name: input.name,
    role: input.role ?? "ANALYST",
    password: bcrypt.hashSync(input.password, 12),
    status: input.status ?? "PENDING",
    authVersion: 0,
  };
  db.prepare("INSERT INTO users (id, email, name, role, password, status, auth_version) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
    user.id,
    user.email,
    user.name,
    user.role,
    user.password,
    user.status,
    user.authVersion,
  );
  return { id: user.id, email: user.email, name: user.name, role: user.role, status: user.status, authVersion: user.authVersion };
}

export function findUserByEmail(email: string): UserRecord | undefined {
  return db.prepare("SELECT id, email, name, role, status, password, auth_version AS authVersion FROM users WHERE email = ?").get(email) as UserRecord | undefined;
}

export function findUserById(id: string): UserRecord | undefined {
  return db.prepare("SELECT id, email, name, role, status, password, auth_version AS authVersion FROM users WHERE id = ?").get(id) as UserRecord | undefined;
}

export function listUsers(): Array<Omit<UserRecord, "password">> {
  return db.prepare("SELECT id, email, name, role, status, auth_version AS authVersion FROM users ORDER BY email").all() as Array<Omit<UserRecord, "password">>;
}

export function updateUserStatus(id: string, status: UserStatus): void {
  db.prepare("UPDATE users SET status = ?, auth_version = auth_version + 1 WHERE id = ?").run(status, id);
}

export function updateUserRole(id: string, role: string): void {
  db.prepare("UPDATE users SET role = ?, auth_version = auth_version + 1 WHERE id = ?").run(role, id);
}

export function updateUserPassword(id: string, password: string): void {
  if (Buffer.byteLength(password, "utf8") > 72) {
    throw new RangeError("Password must be 72 UTF-8 bytes or fewer");
  }
  db.prepare("UPDATE users SET password = ?, auth_version = auth_version + 1 WHERE id = ?")
    .run(bcrypt.hashSync(password, 12), id);
}

export function seedDatabase(): void {
  const count = db.prepare("SELECT COUNT(*) AS count FROM alerts").get() as { count: number };
  if (count.count > 0) return;
  const insertAlert = db.prepare(`INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const insertCase = db.prepare(`INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const insertAudit = db.prepare(`INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const seed = db.transaction(() => {
    const records: Alert[] = [
      { id: "ALT-2026-000001", customerId: "CUS-000041", accountId: "ACC-CUS-000041-01", transactionId: "TXN-2026-00000041", ruleId: "R001", ruleName: "High transaction velocity", score: 82, priority: "CRITICAL", explanation: "7 transactions from the same account occurred within 10 minutes, exceeding the configured threshold of 5.", status: "OPEN", createdAt: now() },
      { id: "ALT-2026-000002", customerId: "CUS-000208", accountId: "ACC-CUS-000208-01", transactionId: "TXN-2026-00000208", ruleId: "R002", ruleName: "New device with unusual activity", score: 61, priority: "HIGH", explanation: "The transaction used a device first observed 2 hours ago and is 4.2x the customer’s normal amount.", status: "OPEN", createdAt: now() },
      { id: "ALT-2026-000003", customerId: "CUS-000317", accountId: "ACC-CUS-000317-02", transactionId: "TXN-2026-00000317", ruleId: "R004", ruleName: "Dormant account reactivation", score: 46, priority: "MEDIUM", explanation: "A dormant account was reactivated after 184 days with a high-value transfer.", status: "INVESTIGATING", createdAt: now() }
    ];
    for (const alert of records) {
      insertAlert.run(alert.id, alert.customerId, alert.accountId, alert.transactionId, alert.ruleId, alert.ruleName, alert.score, alert.priority, alert.explanation, alert.status, alert.createdAt);
      insertCase.run(`CASE-2026-${alert.id.slice(-6)}`, alert.id, alert.status === "INVESTIGATING" ? "IN_PROGRESS" : "NEW", null, null, alert.createdAt, alert.createdAt);
      insertAudit.run(randomUUID(), "ALERT", alert.id, "CREATED", "system", JSON.stringify({ ruleId: alert.ruleId }), alert.createdAt);
    }
  });
  seed();
}
export function query<T>(sql: string, params: unknown[] = []): T[] { return db.prepare(sql).all(...params) as T[]; }
export function run(sql: string, params: unknown[] = []): void { db.prepare(sql).run(...params); }
export { db, now };
