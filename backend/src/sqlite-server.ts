import express from "express";
import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { getJwtSecret, signAuthToken, verifyAuthToken, type AuthUser } from "./auth.js";
import { createUser, db, findUserByEmail, findUserById, listUsers, now, query, run, seedDatabase, type Alert } from "./db.js";

export function createSqliteApp() {
  const app = express();
  const jwtSecret = getJwtSecret();
  app.use(cors({ origin: process.env.FRONTEND_ORIGIN ?? "http://localhost:5173" }));
  app.use(express.json({ limit: "100kb" }));
  app.use(rateLimit({ windowMs: 60_000, limit: 120 }));
  const authRateLimit = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });
  seedDatabase();

  app.get("/health", (_req, res) => res.json({ status: "ok", service: "risklens-api", database: "sqlite", timestamp: now() }));
  app.post("/api/auth/login", authRateLimit, async (req, res) => {
    const parsed = z.object({ email: z.string().email(), password: z.string().min(1) }).safeParse(req.body);
    if (!parsed.success) return res.status(401).json({ error: "Invalid credentials" });
    const user = findUserByEmail(parsed.data.email);
    const passwordHash = user?.password;
    const validHash = passwordHash?.startsWith("$2a$") || passwordHash?.startsWith("$2b$") || passwordHash?.startsWith("$2y$");
    const passwordValid = passwordHash && validHash ? bcrypt.compareSync(parsed.data.password, passwordHash) : false;
    if (!user || !passwordValid || user.status !== "ACTIVE") return res.status(401).json({ error: "Invalid credentials" });
    const safeUser: AuthUser = { id: user.id, email: user.email, name: user.name, role: user.role, authVersion: user.authVersion };
    return res.json({ token: signAuthToken(safeUser, jwtSecret), user: safeUser });
  });
  app.get("/api/auth/me", auth, (_req, res) => {
    const user = findUserById((res.locals.user as AuthUser).id);
    if (!user || user.status !== "ACTIVE") return res.status(401).json({ error: "Invalid or expired token" });
    return res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  });
  app.post("/api/auth/register", authRateLimit, (req, res) => {
    const parsed = z.object({ email: z.string().email(), name: z.string().trim().min(1).max(120), password: z.string().min(12) }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid registration details" });
    if (Buffer.byteLength(parsed.data.password, "utf8") > 72) return res.status(400).json({ error: "Password must be 72 UTF-8 bytes or fewer" });
    try { createUser(parsed.data); } catch (error) {
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) return res.status(409).json({ error: "Account already exists" });
      throw error;
    }
    return res.status(202).json({ status: "pending_activation" });
  });
  function auth(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : undefined;
    if (!token) { res.status(401).json({ error: "Authentication required" }); return; }
    try {
      const tokenUser = verifyAuthToken(token, jwtSecret);
      const currentUser = findUserById(tokenUser.id);
      if (!currentUser || currentUser.status !== "ACTIVE" || currentUser.role !== tokenUser.role || currentUser.authVersion !== tokenUser.authVersion) {
        res.status(401).json({ error: "Invalid or expired token" }); return;
      }
      res.locals.user = tokenUser; next();
    } catch { res.status(401).json({ error: "Invalid or expired token" }); }
  }
  function requireRole(...roles: string[]) {
    return (_req: express.Request, res: express.Response, next: express.NextFunction): void => {
      const user = res.locals.user as AuthUser | undefined;
      if (!user || !roles.includes(user.role)) { res.status(403).json({ error: "Forbidden" }); return; }
      next();
    };
  }
  app.get("/api/users", auth, requireRole("ADMIN"), (_req, res) => res.json({ data: listUsers() }));
  app.get("/api/overview", auth, (_req, res) => {
    const counts = query<{ alerts: number; critical: number; openCases: number }>(`SELECT
      (SELECT COUNT(*) FROM alerts WHERE status != 'CLOSED') AS alerts,
      (SELECT COUNT(*) FROM alerts WHERE priority = 'CRITICAL') AS critical,
      (SELECT COUNT(*) FROM cases WHERE status != 'CLOSED') AS "openCases"`)[0];
    const volumeRows = query<{ day: string; count: number }>(`SELECT date(created_at) AS day, COUNT(*) AS count
      FROM alerts WHERE created_at >= date('now', '-6 days')
      GROUP BY date(created_at) ORDER BY day`);
    const volumeMap = new Map(volumeRows.map((row) => [row.day, row.count]));
    const volume = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setUTCHours(0, 0, 0, 0);
      date.setUTCDate(date.getUTCDate() - (6 - index));
      return volumeMap.get(date.toISOString().slice(0, 10)) ?? 0;
    });
    const alerts = query<Alert>("SELECT * FROM alerts ORDER BY score DESC, created_at DESC LIMIT 5");
    return res.json({ metrics: { ...counts, precision: null, recall: null }, evaluation: null, volume, recentAlerts: alerts });
  });
  app.get("/api/alerts", auth, (req, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    const alerts = status ? query<Alert>("SELECT * FROM alerts WHERE status = ? ORDER BY score DESC", [status]) : query<Alert>("SELECT * FROM alerts ORDER BY score DESC");
    res.json({ data: alerts, total: alerts.length });
  });
  app.get("/api/alerts/:id", auth, (req, res) => {
    const alert = query<Alert>("SELECT * FROM alerts WHERE id = ?", [req.params.id])[0];
    if (!alert) return res.status(404).json({ error: "Alert not found" });
    return res.json({ alert, events: query("SELECT * FROM audit_events WHERE entity_id = ? ORDER BY created_at DESC", [alert.id]) });
  });
  app.get("/api/cases", auth, (_req, res) => res.json({ data: query("SELECT c.*, a.rule_name, a.priority, a.customer_id FROM cases c JOIN alerts a ON a.id = c.alert_id ORDER BY c.updated_at DESC") }));
  app.post("/api/cases/:id/disposition", auth, (req, res) => {
    const parsed = z.object({ disposition: z.enum(["CONFIRMED_SUSPICIOUS", "LEGITIMATE", "FALSE_POSITIVE", "FURTHER_INVESTIGATION", "ESCALATED"]) }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid disposition" });
    const caseRow = query<{ alert_id: string }>("SELECT alert_id FROM cases WHERE id = ?", [req.params.id])[0];
    if (!caseRow) return res.status(404).json({ error: "Case not found" });
    const timestamp = now();
    db.transaction(() => {
      run("UPDATE cases SET disposition = ?, status = 'CLOSED', updated_at = ? WHERE id = ?", [parsed.data.disposition, timestamp, req.params.id]);
      run("UPDATE alerts SET status = 'CLOSED' WHERE id = ?", [caseRow.alert_id]);
      run("INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?)", [randomUUID(), "CASE", req.params.id, "DISPOSITION_RECORDED", String((res.locals.user as AuthUser).email), JSON.stringify(parsed.data), timestamp]);
    })();
    return res.json({ status: "ok", disposition: parsed.data.disposition });
  });
  app.get("/api/audit", auth, (_req, res) => res.json({ data: query("SELECT * FROM audit_events ORDER BY created_at DESC") }));
  return app;
}
