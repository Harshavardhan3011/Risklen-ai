import express from "express";
import { randomUUID } from "node:crypto";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "./prisma.js";
import { evaluationMetrics } from "./evaluation-metrics.js";
import { authenticatePostgresUser, prismaAuthStore, validatePostgresToken } from "./postgres-auth.js";
import { getJwtSecret, type AuthUser } from "./auth.js";
import { assessTransaction } from "./risk-engine.js";
import { runBatchRiskAssessment } from "./batch-risk.js";
import { canAccessCustomerRecord, matchesExternalSecret, validProvisioningPassword } from "./access-control.js";

const pageParams = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  search: z.string().trim().max(120).optional(),
});

function safeUser(user: { id: string; email: string; name: string; role: string; status: string; authVersion: number }) {
  return { id: user.id, email: user.email, name: user.name, role: user.role, status: user.status, authVersion: user.authVersion };
}

function scoreBand(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

async function customerIdForUser(user: AuthUser): Promise<string | null> {
  const customer = await prisma.customer.findUnique({ where: { email: user.email }, select: { id: true } });
  return customer?.id ?? null;
}


export async function createPostgresApp() {
  const app = express();
  const jwtSecret = getJwtSecret();
  app.use(cors({ origin: process.env.FRONTEND_ORIGIN ?? "http://localhost:5173" }));
  app.use(express.json({ limit: "100kb" }));
  app.use(rateLimit({ windowMs: 60_000, limit: 120 }));
  const authRateLimit = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });

  app.get("/health", async (_req, res) => {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: "ok", service: "risklens-api", database: "postgresql", timestamp: new Date().toISOString() });
  });
  app.post("/api/auth/login", authRateLimit, async (req, res) => {
    const parsed = z.object({ email: z.string().email(), password: z.string().min(1) }).safeParse(req.body);
    if (!parsed.success) return res.status(401).json({ error: "Invalid credentials" });
    const result = await authenticatePostgresUser(prismaAuthStore, parsed.data.email, parsed.data.password, jwtSecret);
    if (!result) return res.status(401).json({ error: "Invalid credentials" });
    return res.json(result);
  });
  app.get("/api/auth/me", auth, async (_req, res) => {
    const identity = await prisma.user.findUnique({
      where: { id: (res.locals.user as AuthUser).id },
      select: { id: true, email: true, name: true, role: true },
    });
    if (!identity) return res.status(401).json({ error: "Invalid or expired token" });
    return res.json({ user: identity });
  });
  app.post("/api/auth/register", authRateLimit, async (req, res) => {
    const parsed = z.object({ email: z.string().email(), name: z.string().trim().min(1).max(120), password: z.string().min(12) }).safeParse(req.body);
    if (!parsed.success || Buffer.byteLength(parsed.data.password, "utf8") > 72) return res.status(400).json({ error: "Invalid registration details" });
    try {
      const user = await prisma.user.create({ data: { email: parsed.data.email, name: parsed.data.name, role: "ANALYST", status: "PENDING", passwordHash: bcrypt.hashSync(parsed.data.password, 12) } });
      return res.status(202).json({ status: "pending_activation", user: safeUser(user) });
    } catch (error) {
      if (error instanceof Error && error.message.includes("Unique constraint")) return res.status(409).json({ error: "Account already exists" });
      throw error;
    }
  });
  async function auth(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
    const token = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.slice(7) : undefined;
    if (!token) { res.status(401).json({ error: "Authentication required" }); return; }
    try { res.locals.user = await validatePostgresToken(prismaAuthStore, token, jwtSecret); next(); }
    catch { res.status(401).json({ error: "Invalid or expired token" }); }
  }
  function requireRole(...roles: string[]) {
    return (_req: express.Request, res: express.Response, next: express.NextFunction): void => {
      if (!roles.includes((res.locals.user as AuthUser).role)) { res.status(403).json({ error: "Forbidden" }); return; }
      next();
    };
  }
  app.post("/api/admin/bootstrap", authRateLimit, async (req, res) => {
    const parsed = z.object({ secret: z.string().min(1), email: z.string().email(), name: z.string().trim().min(1).max(120), password: z.string().min(12) }).safeParse(req.body);
    const configuredSecret = process.env.ADMIN_BOOTSTRAP_SECRET;
    if (!configuredSecret) return res.status(503).json({ error: "Administrator bootstrap is not configured" });
    if (!parsed.success || !validProvisioningPassword(parsed.data.password) || !matchesExternalSecret(parsed.data.secret, configuredSecret)) return res.status(401).json({ error: "Invalid bootstrap request" });
    if (await prisma.user.count({ where: { role: "ADMIN", status: "ACTIVE" } })) return res.status(409).json({ error: "An active administrator already exists" });
    try {
      const user = await prisma.user.create({ data: { email: parsed.data.email, name: parsed.data.name, role: "ADMIN", status: "ACTIVE", passwordHash: bcrypt.hashSync(parsed.data.password, 12) } });
      return res.status(201).json({ user: safeUser(user) });
    } catch (error) {
      if (error instanceof Error && error.message.includes("Unique constraint")) return res.status(409).json({ error: "Account already exists" });
      throw error;
    }
  });
  app.get("/api/users", auth, requireRole("ADMIN"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const [total, users] = await Promise.all([
      prisma.user.count(),
      prisma.user.findMany({
        orderBy: { email: "asc" },
        skip: (params.page - 1) * params.pageSize,
        take: params.pageSize,
        select: { id: true, email: true, name: true, role: true, status: true, authVersion: true },
      }),
    ]);
    return res.json({ data: users.map(safeUser), total, page: params.page, pageSize: params.pageSize });
  });
  app.patch("/api/users/:id/provision", auth, requireRole("ADMIN"), async (req, res) => {
    const parsed = z.object({ password: z.string().min(12), role: z.enum(["ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"]).optional(), status: z.enum(["PENDING", "ACTIVE", "DISABLED", "LOCKED"]).default("ACTIVE") }).safeParse(req.body);
    if (!parsed.success || !validProvisioningPassword(parsed.data.password)) return res.status(400).json({ error: "Invalid provisioning details" });
    const actorId = (res.locals.user as AuthUser).id;
    const user = await prisma.$transaction(async tx => {
      const existing = await tx.user.findUnique({ where: { id: String(req.params.id) } });
      if (!existing) return null;
      const updated = await tx.user.update({ where: { id: existing.id }, data: { passwordHash: bcrypt.hashSync(parsed.data.password, 12), role: parsed.data.role ?? existing.role, status: parsed.data.status, authVersion: { increment: 1 } } });
      await tx.auditEvent.create({ data: { entityType: "USER", entityId: existing.id, actorId, eventType: "UPDATED", details: { role: updated.role, status: updated.status, action: "PROVISIONED" } } });
      return updated;
    });
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ user: safeUser(user) });
  });
  app.get("/api/overview", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (_req, res) => {
    const now = new Date();
    const end = new Date(now);
    end.setUTCHours(0, 0, 0, 0);
    end.setUTCDate(end.getUTCDate() + 1);
    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - 7);
    const [alerts, alertSummaryRows, openCases, metrics, volumeRows] = await Promise.all([
      prisma.alert.findMany({
        orderBy: [{ riskScore: "desc" }, { createdAt: "desc" }],
        take: 5,
        select: {
          id: true, customerId: true, riskScore: true, status: true, explanation: true, createdAt: true,
          riskRule: { select: { name: true } },
        },
      }),
      prisma.$queryRaw<Array<{ openAlerts: bigint; critical: bigint }>>`
        SELECT count(*) FILTER (WHERE "status" <> 'CLOSED') AS "openAlerts",
               count(*) FILTER (WHERE "priority" = 'CRITICAL') AS "critical"
        FROM "public"."alerts"
      `,
      prisma.case.count({ where: { status: { not: "CLOSED" } } }),
      evaluationMetrics(),
      prisma.$queryRaw<Array<{ day: string; count: bigint }>>`
        SELECT to_char(date_trunc('day', "createdAt" AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
               count(*) AS count
        FROM "public"."alerts"
        WHERE "createdAt" >= ${start} AND "createdAt" < ${end}
        GROUP BY 1
      `,
    ]);
    const alertSummary = alertSummaryRows[0] ?? { openAlerts: 0n, critical: 0n };
    const groupedVolume = new Map(volumeRows.map(row => [row.day, Number(row.count)]));
    const volume = Array.from({ length: 7 }, (_, index) => {
      const day = new Date(start);
      day.setUTCDate(day.getUTCDate() + index);
      return groupedVolume.get(day.toISOString().slice(0, 10)) ?? 0;
    });
    res.json({ metrics: { alerts: Number(alertSummary.openAlerts), critical: Number(alertSummary.critical), openCases, precision: metrics.precision, recall: metrics.recall }, evaluation: metrics, volume, recentAlerts: alerts.map(alert => ({ id: alert.id, customer_id: alert.customerId, rule_name: alert.riskRule.name, priority: scoreBand(alert.riskScore), score: alert.riskScore, explanation: alert.explanation, status: alert.status })) });
  });
  app.post("/api/risk/batch", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const parsed = z.object({ batchSize: z.coerce.number().int().min(1).max(250).default(100), maxTransactions: z.coerce.number().int().min(1).optional() }).safeParse(req.body ?? {});
    if (!parsed.success) return res.status(400).json({ error: "Invalid batch options" });
    try {
      const result = await runBatchRiskAssessment((res.locals.user as AuthUser).id, parsed.data.batchSize, parsed.data.maxTransactions);
      return res.status(202).json(result);
    } catch {
      return res.status(500).json({ error: "Batch risk assessment failed" });
    }
  });
  app.post("/api/risk/batch/:runId/evaluate", auth, requireRole("ADMIN", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const run = await prisma.generationRun.findUnique({ where: { id: String(req.params.runId) } });
    if (!run) return res.status(404).json({ error: "Processing run not found" });
    const metrics = await evaluationMetrics();
    const metadata = run.metadata && typeof run.metadata === "object" && !Array.isArray(run.metadata) ? run.metadata as Record<string, unknown> : {};
    const updated = await prisma.generationRun.update({ where: { id: run.id }, data: { metadata: { ...metadata, evaluation: metrics } } });
    return res.json({ runId: updated.id, evaluation: metrics });
  });
  app.get("/api/alerts", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const where = { ...(typeof req.query.status === "string" ? { status: req.query.status as never } : {}), ...(params.search ? { OR: [{ id: { contains: params.search, mode: "insensitive" as const } }, { explanation: { contains: params.search, mode: "insensitive" as const } }, { customerId: { contains: params.search, mode: "insensitive" as const } }] } : {}) };
    const [total, alerts] = await Promise.all([prisma.alert.count({ where }), prisma.alert.findMany({ where, orderBy: [{ riskScore: "desc" }, { createdAt: "desc" }], skip: (params.page - 1) * params.pageSize, take: params.pageSize, include: { riskRule: true } })]);
    res.json({ data: alerts.map(alert => ({ ...alert, riskScore: Number(alert.riskScore), priority: scoreBand(alert.riskScore), rule_name: alert.riskRule.name, customer_id: alert.customerId })), total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/alerts/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const alert = await prisma.alert.findUnique({ where: { id: String(req.params.id) }, include: { riskRule: true, evidence: true, events: true, caseAlerts: { include: { case: true } } } });
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    return res.json({ alert, evidence: alert.evidence, events: alert.events, cases: alert.caseAlerts.map(item => item.case) });
  });
  app.get("/api/cases", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const [total, cases] = await Promise.all([prisma.case.count(), prisma.case.findMany({
      orderBy: { updatedAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize,
      select: {
        id: true, status: true, disposition: true, updatedAt: true,
        caseAlerts: { select: { caseId: true, alertId: true, alert: { select: { id: true, priority: true, riskScore: true, status: true } } } },
        assignedTo: { select: { id: true, name: true, email: true } },
      },
    })]);
    res.json({ data: cases, total, page: params.page, pageSize: params.pageSize });
  });
  app.post("/api/cases", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const parsed = z.object({ alertIds: z.array(z.string()).min(1), assignedToId: z.string().uuid().optional() }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid case details" });
    const [alerts, assignee] = await Promise.all([
      prisma.alert.findMany({ where: { id: { in: parsed.data.alertIds } }, select: { id: true } }),
      parsed.data.assignedToId ? prisma.user.findUnique({ where: { id: parsed.data.assignedToId }, select: { id: true, status: true } }) : Promise.resolve(null),
    ]);
    if (alerts.length !== new Set(parsed.data.alertIds).size) return res.status(400).json({ error: "One or more alerts do not exist" });
    if (parsed.data.assignedToId && (!assignee || assignee.status !== "ACTIVE")) return res.status(400).json({ error: "Assignee must be an active user" });
    const created = await prisma.$transaction(async tx => {
      const caseRow = await tx.case.create({ data: { id: randomUUID(), status: "NEW", assignedToId: parsed.data.assignedToId } });
      await tx.caseAlert.createMany({ data: parsed.data.alertIds.map(alertId => ({ caseId: caseRow.id, alertId })) });
      await tx.caseEvent.create({ data: { caseId: caseRow.id, eventType: "CREATED", actorId: (res.locals.user as AuthUser).id, details: { alertIds: parsed.data.alertIds } } });
      return caseRow;
    });
    res.status(201).json({ case: created });
  });
  app.post("/api/cases/:id/disposition", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const parsed = z.object({ disposition: z.enum(["CONFIRMED_SUSPICIOUS", "LEGITIMATE", "FALSE_POSITIVE", "FURTHER_INVESTIGATION", "ESCALATED"]), comment: z.string().max(2000).optional() }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid disposition" });
    const result = await prisma.$transaction(async tx => {
      const existing = await tx.case.findUnique({ where: { id: String(req.params.id) }, include: { caseAlerts: true } });
      if (!existing) return null;
      const updated = await tx.case.update({ where: { id: existing.id }, data: { disposition: parsed.data.disposition, status: "CLOSED" } });
      await tx.alert.updateMany({ where: { id: { in: existing.caseAlerts.map(item => item.alertId) } }, data: { status: "CLOSED", closedAt: new Date() } });
      for (const caseAlert of existing.caseAlerts) {
        await tx.alertEvent.create({ data: { alertId: caseAlert.alertId, actorId: (res.locals.user as AuthUser).id, eventType: "STATUS_CHANGED", details: { to: "CLOSED", reason: "CASE_DISPOSITION" } } });
        await tx.auditEvent.create({ data: { entityType: "ALERT", entityId: caseAlert.alertId, actorId: (res.locals.user as AuthUser).id, eventType: "STATUS_CHANGED", details: { to: "CLOSED", reason: "CASE_DISPOSITION" } } });
      }
      await tx.analystAction.create({ data: { caseId: existing.id, actorId: (res.locals.user as AuthUser).id, actionType: "DISPOSITION_RECORDED", toStatus: "CLOSED", disposition: parsed.data.disposition, comment: parsed.data.comment } });
      await tx.caseEvent.create({ data: { caseId: existing.id, actorId: (res.locals.user as AuthUser).id, eventType: "DISPOSITION_RECORDED", details: parsed.data } });
      await tx.auditEvent.create({ data: { entityType: "CASE", entityId: existing.id, eventType: "DISPOSITION_RECORDED", actorId: (res.locals.user as AuthUser).id, details: parsed.data } });
      return updated;
    });
    if (!result) return res.status(404).json({ error: "Case not found" });
    return res.json({ status: "ok", case: result });
  });
  app.patch("/api/cases/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const parsed = z.object({
      status: z.enum(["NEW", "IN_PROGRESS", "PENDING_REVIEW", "ESCALATED", "CLOSED"]).optional(),
      assignedToId: z.string().uuid().nullable().optional(),
      comment: z.string().trim().min(1).max(2000).optional(),
    }).safeParse(req.body);
    if (!parsed.success || (!parsed.data.status && parsed.data.assignedToId === undefined && !parsed.data.comment)) return res.status(400).json({ error: "No case changes supplied" });
    const actorId = (res.locals.user as AuthUser).id;
    if (parsed.data.assignedToId) {
      const assignee = await prisma.user.findUnique({ where: { id: parsed.data.assignedToId }, select: { id: true, status: true } });
      if (!assignee || assignee.status !== "ACTIVE") return res.status(400).json({ error: "Assignee must be an active user" });
    }
    const result = await prisma.$transaction(async tx => {
      const existing = await tx.case.findUnique({ where: { id: String(req.params.id) } });
      if (!existing) return null;
      if (parsed.data.assignedToId) {
        const assignee = await tx.user.findUnique({ where: { id: parsed.data.assignedToId }, select: { id: true, status: true } });
        if (!assignee || assignee.status !== "ACTIVE") throw new Error("Assignee must be an active user");
      }
      const nextStatus = parsed.data.status ?? existing.status;
      const updated = await tx.case.update({ where: { id: existing.id }, data: { status: nextStatus, assignedToId: parsed.data.assignedToId === undefined ? existing.assignedToId : parsed.data.assignedToId, closedAt: nextStatus === "CLOSED" ? new Date() : existing.closedAt } });
      if (parsed.data.assignedToId !== undefined) {
        await tx.analystAction.create({ data: { caseId: existing.id, actorId, actionType: parsed.data.assignedToId ? "ASSIGNED" : "UNASSIGNED", toStatus: nextStatus } });
        await tx.caseEvent.create({ data: { caseId: existing.id, actorId, eventType: parsed.data.assignedToId ? "OWNERSHIP_STARTED" : "OWNERSHIP_ENDED", details: { assignedToId: parsed.data.assignedToId } } });
        await tx.auditEvent.create({ data: { entityType: "CASE", entityId: existing.id, actorId, eventType: "UPDATED", details: { assignedToId: parsed.data.assignedToId } } });
      }
      if (parsed.data.status && parsed.data.status !== existing.status) {
        await tx.analystAction.create({ data: { caseId: existing.id, actorId, actionType: "STATUS_CHANGED", fromStatus: existing.status, toStatus: parsed.data.status } });
        await tx.caseEvent.create({ data: { caseId: existing.id, actorId, eventType: "STATUS_CHANGED", details: { from: existing.status, to: parsed.data.status } } });
        await tx.auditEvent.create({ data: { entityType: "CASE", entityId: existing.id, actorId, eventType: "STATUS_CHANGED", details: { from: existing.status, to: parsed.data.status } } });
      }
      if (parsed.data.comment) {
        await tx.analystAction.create({ data: { caseId: existing.id, actorId, actionType: "COMMENTED", comment: parsed.data.comment, toStatus: nextStatus } });
        await tx.caseEvent.create({ data: { caseId: existing.id, actorId, eventType: "UPDATED", details: { comment: parsed.data.comment } } });
        await tx.auditEvent.create({ data: { entityType: "CASE", entityId: existing.id, actorId, eventType: "UPDATED", details: { comment: parsed.data.comment } } });
      }
      return updated;
    });
    return res.json({ status: "ok", case: result });
  });
  app.post("/api/alerts/:id/status", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const parsed = z.object({ status: z.enum(["OPEN", "INVESTIGATING", "ESCALATED", "CLOSED", "FALSE_POSITIVE"]) }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid alert status" });
    const actorId = (res.locals.user as AuthUser).id;
    const updated = await prisma.$transaction(async tx => {
      const existing = await tx.alert.findUnique({ where: { id: String(req.params.id) } });
      if (!existing) return null;
      const alert = await tx.alert.update({ where: { id: existing.id }, data: { status: parsed.data.status, closedAt: ["CLOSED", "FALSE_POSITIVE"].includes(parsed.data.status) ? new Date() : null } });
      await tx.alertEvent.create({ data: { alertId: existing.id, actorId, eventType: "STATUS_CHANGED", details: { from: existing.status, to: parsed.data.status } } });
      await tx.auditEvent.create({ data: { entityType: "ALERT", entityId: existing.id, actorId, eventType: "STATUS_CHANGED", details: { from: existing.status, to: parsed.data.status } } });
      return alert;
    });
    if (!updated) return res.status(404).json({ error: "Alert not found" });
    return res.json({ status: "ok", alert: updated });
  });
  app.get("/api/customers", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    if (!canAccessCustomerRecord(user.role, ownCustomerId, ownCustomerId ?? "")) return res.status(403).json({ error: "Customer profile is not linked" });
    const where = ownCustomerId ? { id: ownCustomerId } : (params.search ? { OR: [{ id: { contains: params.search, mode: "insensitive" as const } }, { fullName: { contains: params.search, mode: "insensitive" as const } }, { email: { contains: params.search, mode: "insensitive" as const } }] } : {});
    const [total, data] = await Promise.all([prisma.customer.count({ where }), prisma.customer.findMany({ where, orderBy: { fullName: "asc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize, select: { id: true, fullName: true, email: true, countryCode: true, kycProfile: { select: { status: true, riskRating: true } } } })]);
    res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/accounts", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    if (!canAccessCustomerRecord(user.role, ownCustomerId, ownCustomerId ?? "")) return res.status(403).json({ error: "Customer profile is not linked" });
    const where = ownCustomerId ? { owners: { some: { customerId: ownCustomerId } } } : (params.search ? { OR: [{ id: { contains: params.search, mode: "insensitive" as const } }, { currency: { contains: params.search, mode: "insensitive" as const } }] } : {});
    const [total, data] = await Promise.all([prisma.account.count({ where }), prisma.account.findMany({ where, orderBy: { openedAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize, select: { id: true, accountType: true, status: true, currency: true, currentBalance: true, openedAt: true } })]);
    res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/customers/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    if (!canAccessCustomerRecord(user.role, ownCustomerId, String(req.params.id))) return res.status(403).json({ error: "Forbidden" });
    const customer = await prisma.customer.findUnique({ where: { id: String(req.params.id) }, include: { kycProfile: true, accountOwners: { include: { account: true } }, customerDevices: { include: { device: true } } } });
    if (!customer) return res.status(404).json({ error: "Customer not found" });
    return res.json({ customer });
  });
  app.get("/api/accounts/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    const account = await prisma.account.findFirst({ where: { id: String(req.params.id), ...(ownCustomerId ? { owners: { some: { customerId: ownCustomerId } } } : {}) }, include: { owners: { include: { customer: true } }, transactions: { orderBy: { occurredAt: "desc" }, take: 25 }, events: { orderBy: { occurredAt: "desc" }, take: 25 } } });
    if (!account) return res.status(404).json({ error: "Account not found" });
    return res.json({ account });
  });
  app.get("/api/transactions", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    if (user.role === "CUSTOMER" && !ownCustomerId) return res.status(403).json({ error: "Customer profile is not linked" });
    const where = ownCustomerId ? { customerId: ownCustomerId } : (params.search ? { OR: [{ id: { contains: params.search, mode: "insensitive" as const } }, { customerId: { contains: params.search, mode: "insensitive" as const } }, { accountId: { contains: params.search, mode: "insensitive" as const } }, { reference: { contains: params.search, mode: "insensitive" as const } }] } : {});
    const [total, data] = await Promise.all([prisma.transaction.count({ where }), prisma.transaction.findMany({ where, orderBy: { occurredAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize })]);
    res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/transactions/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER", "CUSTOMER"), async (req, res) => {
    const user = res.locals.user as AuthUser;
    const ownCustomerId = user.role === "CUSTOMER" ? await customerIdForUser(user) : null;
    const transaction = await prisma.transaction.findFirst({ where: { id: String(req.params.id), ...(ownCustomerId ? { customerId: ownCustomerId } : {}) }, include: { customer: true, account: true, merchant: true, device: true, transferLinks: true, alerts: { include: { riskRule: true, evidence: true } } } });
    if (!transaction) return res.status(404).json({ error: "Transaction not found" });
    return res.json({ transaction });
  });
  app.post("/api/risk/assess/:id", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const options = z.object({ caseId: z.string().optional(), createCase: z.boolean().default(false), assignedToId: z.string().uuid().optional() }).safeParse(req.body ?? {});
    if (!options.success) return res.status(400).json({ error: "Invalid risk workflow options" });
    const transaction = await prisma.transaction.findUnique({ where: { id: String(req.params.id) }, include: { account: true, merchant: true, device: true, transferLinks: true } });
    if (!transaction) return res.status(404).json({ error: "Transaction not found" });
    const recentTransactions = await prisma.transaction.findMany({
      where: { accountId: transaction.accountId, id: { not: transaction.id }, occurredAt: { gte: new Date(transaction.occurredAt.getTime() - 30 * 60_000), lte: transaction.occurredAt } },
      select: { amount: true, merchantId: true, occurredAt: true, status: true },
    });
    const rules = await prisma.riskRule.findMany({ where: { enabled: true }, orderBy: [{ ruleCode: "asc" }, { version: "desc" }] });
    const assessment = assessTransaction({
      transaction: { id: transaction.id, amount: Number(transaction.amount), balanceAfter: Number(transaction.balanceAfter), transactionType: transaction.transactionType, status: transaction.status, currency: transaction.currency, occurredAt: transaction.occurredAt },
      account: { status: transaction.account.status, currentBalance: Number(transaction.account.currentBalance), overdraftLimit: Number(transaction.account.overdraftLimit) },
      merchant: transaction.merchant ? { riskRating: transaction.merchant.riskRating } : null,
      device: transaction.device ? { firstSeenAt: transaction.device.firstSeenAt } : null,
      recentTransactions: recentTransactions.map(item => ({ amount: Number(item.amount), merchantId: item.merchantId, occurredAt: item.occurredAt, status: item.status })),
      transferLinks: transaction.transferLinks.map(link => ({ sourceAccountId: link.sourceAccountId, targetAccountId: link.targetAccountId, amount: Number(link.amount), currency: link.currency })),
    }, rules.map(rule => ({ ruleCode: rule.ruleCode, weight: rule.weight, threshold: rule.threshold ? Number(rule.threshold) : null, enabled: rule.enabled })));
    const actorId = (res.locals.user as AuthUser).id;
    if (options.data.assignedToId) {
      const assignee = await prisma.user.findUnique({ where: { id: options.data.assignedToId }, select: { id: true, status: true } });
      if (!assignee || assignee.status !== "ACTIVE") return res.status(400).json({ error: "Assignee must be an active user" });
    }
    if (options.data.caseId) {
      const existingCase = await prisma.case.findUnique({ where: { id: options.data.caseId }, select: { id: true } });
      if (!existingCase) return res.status(404).json({ error: "Case not found" });
    }
    const persisted = await prisma.$transaction(async tx => {
      const alertIds: string[] = [];
      for (const finding of assessment.findings) {
        const rule = rules.find(candidate => candidate.ruleCode === finding.ruleCode);
        if (!rule) continue;
        const evaluationVersion = `${rule.ruleCode}:v${rule.version}`;
        const existing = await tx.alert.findUnique({ where: { riskRuleId_transactionId_evaluationVersion: { riskRuleId: rule.id, transactionId: transaction.id, evaluationVersion } } });
        if (existing) {
          alertIds.push(existing.id);
          continue;
        }
        const alert = await tx.alert.create({
          data: {
            id: randomUUID(),
            customerId: transaction.customerId,
            accountId: transaction.accountId,
            transactionId: transaction.id,
            riskRuleId: rule.id,
            evaluationVersion,
            riskScore: assessment.score,
            priority: assessment.priority,
            status: "OPEN",
            explanation: finding.evidence,
            detectedAt: transaction.occurredAt,
          },
        });
        await tx.alertEvidence.create({ data: { alertId: alert.id, evidenceType: "RULE_MATCH", sourceId: transaction.id, description: finding.evidence, value: { ruleCode: finding.ruleCode, score: finding.score } } });
        await tx.alertEvent.create({ data: { alertId: alert.id, actorId, eventType: "CREATED", details: { ruleCode: finding.ruleCode, evaluationVersion } } });
        await tx.auditEvent.create({ data: { entityType: "ALERT", entityId: alert.id, actorId, eventType: "CREATED", details: { transactionId: transaction.id, ruleCode: finding.ruleCode } } });
        alertIds.push(alert.id);
      }
      let caseId = options.data.caseId;
      if (options.data.createCase && !caseId && alertIds.length) {
        const caseRow = await tx.case.create({ data: { id: randomUUID(), status: "NEW", assignedToId: options.data.assignedToId } });
        caseId = caseRow.id;
        await tx.caseEvent.create({ data: { caseId, actorId, eventType: "CREATED", details: { alertIds } } });
        await tx.auditEvent.create({ data: { entityType: "CASE", entityId: caseId, actorId, eventType: "CREATED", details: { alertIds } } });
      }
      if (caseId && alertIds.length) {
        const targetCase = await tx.case.findUnique({ where: { id: caseId } });
        if (!targetCase) throw new Error("Case not found");
        await tx.caseAlert.createMany({ data: alertIds.map(alertId => ({ caseId, alertId })), skipDuplicates: true });
      }
      return { alertIds, caseId: caseId ?? null };
    });
    return res.json({ transactionId: transaction.id, assessment, persisted });
  });
  app.get("/api/rules", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const where = { enabled: true };
    const [total, data] = await Promise.all([
      prisma.riskRule.count({ where }),
      prisma.riskRule.findMany({
        where,
        orderBy: [{ ruleCode: "asc" }, { version: "desc" }],
        skip: (params.page - 1) * params.pageSize,
        take: params.pageSize,
        select: { ruleCode: true, version: true, name: true, severity: true, weight: true, enabled: true },
      }),
    ]);
    return res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/audit", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const [total, data] = await Promise.all([prisma.auditEvent.count(), prisma.auditEvent.findMany({
      orderBy: { occurredAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize,
      select: { id: true, entityType: true, entityId: true, eventType: true, actorId: true, occurredAt: true },
    })]);
    res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/validation", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const [total, data] = await Promise.all([
      prisma.validationResult.count(),
      prisma.validationResult.findMany({
        orderBy: { checkedAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize,
        select: { id: true, checkName: true, status: true, message: true, checkedAt: true },
      }),
    ]);
    return res.json({ data, total, page: params.page, pageSize: params.pageSize });
  });
  app.get("/api/generation-runs", auth, requireRole("ADMIN", "ANALYST", "COMPLIANCE_REVIEWER"), async (req, res) => {
    const params = pageParams.parse(req.query);
    const [total, data] = await Promise.all([
      prisma.generationRun.count(),
      prisma.generationRun.findMany({
        orderBy: { startedAt: "desc" }, skip: (params.page - 1) * params.pageSize, take: params.pageSize,
        select: { id: true, seed: true, scale: true, status: true, startedAt: true, completedAt: true },
      }),
    ]);
    return res.json({ data: data.map(run => ({ ...run, seed: run.seed.toString() })), total, page: params.page, pageSize: params.pageSize });
  });
  app.get("*", (_req, res) => res.status(404).json({ error: "Not found" }));
  return app;
}
