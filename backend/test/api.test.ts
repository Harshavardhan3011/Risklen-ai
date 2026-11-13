import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import jwt from "jsonwebtoken";
import app from "../src/server.js";
import { getJwtSecret, signAuthToken } from "../src/auth.js";
import { createUser, db, findUserByEmail, runMigrations, updateUserPassword, updateUserRole, updateUserStatus, type MigrationDefinition } from "../src/db.js";
import request from "supertest";

test("health endpoint is available", async () => {
  const response = await request(app).get("/health");
  assert.equal(response.status, 200);
  assert.equal(response.body.status, "ok");
});

test("legacy SQLite schema is migrated, preserved, and idempotent", () => {
  const columns = db.prepare("PRAGMA table_info(users)").all() as Array<{ name: string }>;
  assert.deepEqual(columns.map((column) => column.name), ["id", "email", "name", "role", "password", "status", "auth_version"]);
  assert.equal((db.prepare("SELECT COUNT(*) AS count FROM _risklens_migrations").get() as { count: number }).count, 2);
  assert.equal((db.prepare("SELECT COUNT(*) AS count FROM alerts").get() as { count: number }).count, 3);
  runMigrations();
  assert.equal((db.prepare("SELECT COUNT(*) AS count FROM _risklens_migrations").get() as { count: number }).count, 2);
});

test("failed migrations roll back their schema changes", () => {
  const migrationId = "test_failed_migration";
  const migration: MigrationDefinition = {
    id: migrationId,
    name: "Test failed migration",
    up: () => {
      db.exec("CREATE TABLE migration_rollback_probe (id TEXT PRIMARY KEY)");
      throw new Error("intentional migration failure");
    },
  };
  assert.throws(() => runMigrations([migration]), /intentional migration failure/);
  assert.equal((db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'migration_rollback_probe'").get() as { count: number }).count, 0);
  assert.equal((db.prepare("SELECT COUNT(*) AS count FROM _risklens_migrations WHERE id = ?").get(migrationId) as { count: number }).count, 0);
});

test("active users authenticate with the correct password", async () => {
  createUser({ email: "active@example.test", name: "Active Analyst", password: "correct horse battery staple", status: "ACTIVE" });
  const response = await request(app).post("/api/auth/login").send({ email: "active@example.test", password: "correct horse battery staple" });
  assert.equal(response.status, 200);
  assert.equal(response.body.user.email, "active@example.test");
  assert.equal("password" in response.body.user, false);
  assert.equal("passwordHash" in response.body.user, false);
  assert.ok(response.body.token);
});

test("authenticated profile restoration returns persisted identity and rejects invalid sessions", async () => {
  const accounts = [
    { email: "me-admin@example.test", name: "Test Administrator", role: "ADMIN" },
    { email: "me-analyst@example.test", name: "Test Analyst", role: "ANALYST" },
    { email: "me-reviewer@example.test", name: "Test Reviewer", role: "COMPLIANCE_REVIEWER" },
  ] as const;
  for (const account of accounts) createUser({ ...account, password: "correct profile password", status: "ACTIVE" });

  for (const account of accounts) {
    const persistedUser = findUserByEmail(account.email);
    assert.ok(persistedUser);
    const token = signAuthToken({ id: persistedUser.id, email: persistedUser.email, name: persistedUser.name, role: persistedUser.role, authVersion: persistedUser.authVersion }, getJwtSecret());
    const profile = await request(app).get("/api/auth/me").set("Authorization", `Bearer ${token}`);
    assert.equal(profile.status, 200);
    assert.deepEqual(profile.body.user, {
      id: findUserByEmail(account.email)?.id,
      email: account.email,
      name: account.name,
      role: account.role,
      status: "ACTIVE",
    });
    assert.equal("password" in profile.body.user, false);
    assert.equal("passwordHash" in profile.body.user, false);
  }

  const analyst = findUserByEmail("me-analyst@example.test");
  assert.ok(analyst);
  const expiredToken = jwt.sign({ sub: analyst.id, email: analyst.email, name: analyst.name, role: analyst.role, authVersion: analyst.authVersion }, getJwtSecret(), { expiresIn: -1 });
  assert.equal((await request(app).get("/api/auth/me").set("Authorization", `Bearer ${expiredToken}`)).status, 401);

  const analystLogin = await request(app).post("/api/auth/login").send({ email: analyst.email, password: "correct profile password" });
  updateUserPassword(analyst.id, "replacement profile password");
  assert.equal((await request(app).get("/api/auth/me").set("Authorization", `Bearer ${analystLogin.body.token}`)).status, 401);
  assert.equal((await request(app).get("/api/auth/me")).status, 401);
});

test("incorrect passwords and inactive users are rejected", async () => {
  createUser({ email: "pending@example.test", name: "Pending Analyst", password: "pending password 123", status: "PENDING" });
  createUser({ email: "disabled@example.test", name: "Disabled Analyst", password: "disabled password 123", status: "DISABLED" });
  createUser({ email: "locked@example.test", name: "Locked Analyst", password: "locked password 123", status: "LOCKED" });
  db.prepare("INSERT INTO users (id, email, name, role, password, status, auth_version) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run("legacy-user", "legacy@example.test", "Legacy User", "ANALYST", "legacy-plaintext", "ACTIVE", 0);

  const responses = await Promise.all([
    request(app).post("/api/auth/login").send({ email: "active@example.test", password: "wrong password" }),
    request(app).post("/api/auth/login").send({ email: "pending@example.test", password: "pending password 123" }),
    request(app).post("/api/auth/login").send({ email: "disabled@example.test", password: "disabled password 123" }),
    request(app).post("/api/auth/login").send({ email: "locked@example.test", password: "locked password 123" }),
    request(app).post("/api/auth/login").send({ email: "legacy@example.test", password: "legacy-plaintext" }),
  ]);
  assert.deepEqual(responses.map((response) => response.status), [401, 401, 401, 401, 401]);
});

test("registration creates a pending account without issuing a token", async () => {
  const response = await request(app).post("/api/auth/register").send({
    email: "new-user@example.test",
    name: "New User",
    password: "a sufficiently long password",
  });
  assert.equal(response.status, 202);
  assert.deepEqual(response.body, { status: "pending_activation" });
});

test("registration rejects passwords over the bcrypt UTF-8 byte limit", async () => {
  const response = await request(app).post("/api/auth/register").send({
    email: "long-password@example.test",
    name: "Long Password",
    password: "é".repeat(37),
  });
  assert.equal(response.status, 400);
  assert.equal(response.body.error, "Password must be 72 UTF-8 bytes or fewer");
});

test("registration cannot self-assign an active administrator account", async () => {
  const response = await request(app).post("/api/auth/register").send({
    email: "attempted-admin@example.test",
    name: "Attempted Admin",
    password: "a sufficiently long password",
    role: "ADMIN",
    status: "ACTIVE",
  });
  assert.equal(response.status, 202);
  const user = findUserByEmail("attempted-admin@example.test");
  assert.equal(user?.role, "ANALYST");
  assert.equal(user?.status, "PENDING");
});

test("status, role, and password changes invalidate existing tokens", async () => {
  createUser({ email: "versioned@example.test", name: "Versioned User", password: "versioned password 123", status: "ACTIVE" });
  const secret = getJwtSecret();
  const initial = findUserByEmail("versioned@example.test");
  assert.ok(initial);
  const initialToken = signAuthToken({ id: initial.id, email: initial.email, name: initial.name, role: initial.role, authVersion: initial.authVersion }, secret);

  updateUserStatus(initial.id, "DISABLED");
  assert.equal((await request(app).get("/api/overview").set("Authorization", `Bearer ${initialToken}`)).status, 401);

  updateUserStatus(initial.id, "ACTIVE");
  const afterStatus = findUserByEmail(initial.email);
  assert.ok(afterStatus);
  const roleToken = signAuthToken({ id: afterStatus.id, email: afterStatus.email, name: afterStatus.name, role: afterStatus.role, authVersion: afterStatus.authVersion }, secret);
  updateUserRole(afterStatus.id, "COMPLIANCE_REVIEWER");
  assert.equal((await request(app).get("/api/overview").set("Authorization", `Bearer ${roleToken}`)).status, 401);

  updateUserRole(afterStatus.id, "ANALYST");
  const afterRole = findUserByEmail(initial.email);
  assert.ok(afterRole);
  const passwordToken = signAuthToken({ id: afterRole.id, email: afterRole.email, name: afterRole.name, role: afterRole.role, authVersion: afterRole.authVersion }, secret);
  updateUserPassword(afterRole.id, "replacement password 123");
  assert.equal((await request(app).get("/api/overview").set("Authorization", `Bearer ${passwordToken}`)).status, 401);
});

test("admin-only user listing rejects analysts and omits password fields", async () => {
  createUser({ email: "admin@example.test", name: "Administrator", role: "ADMIN", password: "admin password 123", status: "ACTIVE" });
  const secret = getJwtSecret();
  const analyst = findUserByEmail("active@example.test");
  const admin = findUserByEmail("admin@example.test");
  assert.ok(analyst);
  assert.ok(admin);
  const analystToken = signAuthToken({ id: analyst.id, email: analyst.email, name: analyst.name, role: analyst.role, authVersion: analyst.authVersion }, secret);
  const adminToken = signAuthToken({ id: admin.id, email: admin.email, name: admin.name, role: admin.role, authVersion: admin.authVersion }, secret);

  const analystResponse = await request(app).get("/api/users").set("Authorization", `Bearer ${analystToken}`);
  assert.equal(analystResponse.status, 403);
  const adminResponse = await request(app).get("/api/users").set("Authorization", `Bearer ${adminToken}`);
  assert.equal(adminResponse.status, 200);
  assert.equal(adminResponse.body.data.every((user: Record<string, unknown>) => !("password" in user) && !("passwordHash" in user)), true);
});

test("production JWT secrets must be configured and sufficiently long", () => {
  assert.throws(() => getJwtSecret("production", undefined));
  assert.throws(() => getJwtSecret("production", "too-short"));
  assert.equal(getJwtSecret("production", "a".repeat(32)), "a".repeat(32));
});

test("production startup refuses a missing JWT secret", () => {
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", "import './src/server.ts'"], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: "production", JWT_SECRET: "" },
    encoding: "utf8",
  });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, /JWT_SECRET/);
});
