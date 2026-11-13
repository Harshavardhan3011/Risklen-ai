import React, { lazy, Suspense, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import axios from "axios";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ClipboardList,
  Database,
  FileCheck2,
  FileClock,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Network,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  WalletCards,
} from "lucide-react";
import {
  BrowserRouter,
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import "./style.css";

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:4000" });
const AlertVolumeChart = lazy(() => import("./AlertVolumeChart"));

type AlertRecord = {
  id: string;
  customer_id?: string;
  customerId?: string;
  rule_name?: string;
  ruleName?: string;
  priority: string;
  score?: number;
  risk_score?: number;
  explanation: string;
  status: string;
};
type Overview = {
  metrics: { alerts: number; critical: number; openCases: number; precision: number; recall: number };
  volume: number[];
  recentAlerts: AlertRecord[];
};
type User = { id?: string; name: string; role: string; email: string; status?: string };
type AuthStatus = "restoring" | "authenticated" | "anonymous" | "error";
type CaseRecord = { id: string; status: string; disposition?: string | null; assignedTo?: { name: string } | null; caseAlerts?: Array<{ alert: AlertRecord }> };

const sessionRestorationRequests = new Map<string, Promise<User>>();
const overviewRequests = new Map<string, Promise<Overview>>();

function restoreAuthenticatedUser(token: string): Promise<User> {
  const existing = sessionRestorationRequests.get(token);
  if (existing) return existing;
  const pending = api.get<{ user: User }>("/api/auth/me", { headers: { Authorization: `Bearer ${token}` } })
    .then((response) => response.data.user);
  sessionRestorationRequests.set(token, pending);
  void pending.then(
    () => { if (sessionRestorationRequests.get(token) === pending) sessionRestorationRequests.delete(token); },
    () => { if (sessionRestorationRequests.get(token) === pending) sessionRestorationRequests.delete(token); },
  );
  return pending;
}

function loadOverview(token: string): Promise<Overview> {
  const existing = overviewRequests.get(token);
  if (existing) return existing;
  const pending = api.get<Overview>("/api/overview", { headers: { Authorization: `Bearer ${token}` } }).then((response) => response.data);
  overviewRequests.set(token, pending);
  void pending.then(
    () => { if (overviewRequests.get(token) === pending) overviewRequests.delete(token); },
    () => { if (overviewRequests.get(token) === pending) overviewRequests.delete(token); },
  );
  return pending;
}

const navigation = [
  { label: "Dashboard", to: "/dashboard", icon: LayoutDashboard },
  { label: "Transactions", to: "/transactions", icon: WalletCards },
  { label: "Alerts", to: "/alerts", icon: AlertTriangle },
  { label: "Cases / Investigations", to: "/cases", icon: ClipboardList },
  { label: "Customers", to: "/customers", icon: Users },
  { label: "Accounts", to: "/accounts", icon: Network },
  { label: "Analytics / Reports", to: "/analytics", icon: BarChart3 },
  { label: "Risk Rules", to: "/rules", icon: SlidersHorizontal },
  { label: "Data Generation", to: "/data-generation", icon: Database },
  { label: "Data Validation", to: "/validation", icon: FileCheck2 },
  { label: "Audit History", to: "/audit", icon: FileClock },
  { label: "User Management", to: "/users", icon: Users },
  { label: "Settings", to: "/settings", icon: Settings },
];

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("risklens-token"));
  const [user, setUser] = useState<User | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus>(() => localStorage.getItem("risklens-token") ? "restoring" : "anonymous");
  const [restoreAttempt, setRestoreAttempt] = useState(0);
  const trustedToken = useRef<string | null>(null);

  if (token) api.defaults.headers.common.Authorization = `Bearer ${token}`;
  else delete api.defaults.headers.common.Authorization;

  useEffect(() => {
    const interceptorId = api.interceptors.response.use(
      (response) => response,
      (error: unknown) => {
        if (axios.isAxiosError(error) && error.response?.status === 401) {
          localStorage.removeItem("risklens-token");
          trustedToken.current = null;
          setToken(null);
          setUser(null);
          setAuthStatus("anonymous");
        }
        return Promise.reject(error);
      },
    );
    return () => api.interceptors.response.eject(interceptorId);
  }, []);

  useEffect(() => {
    if (!token) {
      trustedToken.current = null;
      setUser(null);
      setAuthStatus("anonymous");
      return;
    }
    if (trustedToken.current === token) return;

    let active = true;
    setUser(null);
    setAuthStatus("restoring");
    restoreAuthenticatedUser(token)
      .then((restoredUser) => {
        if (!active) return;
        trustedToken.current = token;
        setUser(restoredUser);
        setAuthStatus("authenticated");
      })
      .catch((error: unknown) => {
        if (!active || (axios.isAxiosError(error) && error.response?.status === 401)) return;
        setAuthStatus("error");
      });
    return () => { active = false; };
  }, [token, restoreAttempt]);

  const login = (value: string, loggedInUser: User) => {
    localStorage.setItem("risklens-token", value);
    trustedToken.current = value;
    setToken(value);
    setUser(loggedInUser);
    setAuthStatus("authenticated");
  };
  const logout = () => {
    localStorage.removeItem("risklens-token");
    trustedToken.current = null;
    setToken(null);
    setUser(null);
    setAuthStatus("anonymous");
  };
  const retryRestoration = () => setRestoreAttempt((attempt) => attempt + 1);

  const loginPage = !token
    ? <Login onLogin={login} />
    : authStatus === "authenticated"
      ? <Navigate to="/dashboard" replace />
      : authStatus === "error"
        ? <SessionRestoreFailure onRetry={retryRestoration} onSignIn={logout} />
        : <SessionRestoring />;

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={loginPage} />
        <Route element={<ProtectedRoute token={token} user={user} status={authStatus} onRetry={retryRestoration} onSignIn={logout} />}>
          <Route element={<DashboardLayout user={user as User} onLogout={logout} />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage token={token as string} />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/transactions" element={<TransactionsPage />} />
            <Route path="/customers" element={<ResourcePage title="Customers" endpoint="/api/customers" columns={["id", "fullName", "email", "countryCode"]} searchable />} />
            <Route path="/accounts" element={<ResourcePage title="Accounts" endpoint="/api/accounts" columns={["id", "accountType", "status", "currency", "currentBalance"]} searchable />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/rules" element={<ResourcePage title="Risk Rules" endpoint="/api/rules" columns={["ruleCode", "version", "name", "severity", "weight", "enabled"]} />} />
            <Route path="/data-generation" element={<ResourcePage title="Generation Runs" endpoint="/api/generation-runs" columns={["id", "seed", "scale", "status", "startedAt", "completedAt"]} />} />
            <Route path="/validation" element={<ResourcePage title="Validation Results" endpoint="/api/validation" columns={["checkName", "status", "message", "checkedAt"]} />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/users" element={<ResourcePage title="User Management" endpoint="/api/users" columns={["email", "name", "role", "status"]} />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

function ProtectedRoute({ token, user, status, onRetry, onSignIn }: { token: string | null; user: User | null; status: AuthStatus; onRetry: () => void; onSignIn: () => void }) {
  const location = useLocation();
  if (status === "restoring") return <SessionRestoring />;
  if (status === "error") return <SessionRestoreFailure onRetry={onRetry} onSignIn={onSignIn} />;
  return token && status === "authenticated" && user
    ? <Outlet />
    : <Navigate to="/login" replace state={{ from: location.pathname }} />;
}

function SessionRestoring() {
  return <div className="login"><section className="login-card" role="status" aria-live="polite"><div className="brand"><ShieldCheck /> RiskLens<span>AI</span></div><p className="muted">Restoring your authenticated session…</p></section></div>;
}

function SessionRestoreFailure({ onRetry, onSignIn }: { onRetry: () => void; onSignIn: () => void }) {
  return <div className="login"><section className="login-card" role="alert"><div className="brand"><ShieldCheck /> RiskLens<span>AI</span></div><h1>Session could not be verified</h1><p className="muted">The service did not confirm your identity. Retry the request or sign in again.</p><div className="session-actions"><button className="primary" onClick={onRetry} type="button">Retry verification</button><button className="secondary" onClick={onSignIn} type="button">Sign in</button></div></section></div>;
}

function initialsFor(name: string, email: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length > 1) return `${words[0][0]}${words[words.length - 1][0]}`.toUpperCase();
  return (words[0]?.slice(0, 2) || email.slice(0, 1) || "?").toUpperCase();
}

function DashboardLayout({ user, onLogout }: { user: User; onLogout: () => void }) {
  const location = useLocation();
  return (
    <div className="app">
      <aside className="sidebar">
        <Link className="brand" to="/dashboard" aria-label="RiskLens AI dashboard">
          <ShieldCheck /> RiskLens<span>AI</span>
        </Link>
        <nav aria-label="Primary navigation">
          {navigation.map(({ label, to, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
              end={to === "/dashboard"}
            >
              <Icon size={17} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <button className="sign-out" onClick={onLogout} type="button">
          <LogOut size={17} aria-hidden="true" /> Sign out
        </button>
      </aside>
      <main>
        <header>
          <div>
            <h1>{pageTitle(location.pathname)}</h1>
          </div>
          <div className="user" aria-label={`Signed in as ${user.name}, ${user.role}`}>
            <strong className="user-initials" aria-hidden="true">{initialsFor(user.name, user.email)}</strong>
            <span><strong>{user.name}</strong><br /><small>{user.email}</small><br /><small>{user.role}</small></span>
          </div>
        </header>
        <Outlet />
      </main>
    </div>
  );
}

function pageTitle(pathname: string) {
  return navigation.find((item) => item.to === pathname)?.label ?? (pathname === "/" ? "Dashboard" : "Page not found");
}

function DashboardPage({ token }: { token: string }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [retryCount, setRetryCount] = useState(0);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    loadOverview(token)
      .then((data) => { if (active) { setOverview(data); setError(""); } })
      .catch((requestError: unknown) => {
        if (active && !axios.isCancel(requestError)) setError("Could not load dashboard data. Retry when the service is available.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [retryCount, token]);
  if (loading && !overview) return <section className="panel dashboard-loading" aria-busy="true" aria-live="polite">Loading dashboard data…</section>;
  if (error && !overview) return <section className="panel" role="alert"><div className="error">{error}</div><button className="primary" onClick={() => setRetryCount((count) => count + 1)} type="button">Retry</button></section>;
  if (!overview) return null;
  const chart = overview.volume.map((value, index) => ({ day: `D${index + 1}`, value }));
  const metricCards: Array<[string, string | number, typeof AlertTriangle]> = [
    ["Open alerts", overview.metrics.alerts, AlertTriangle],
    ["Critical priority", overview.metrics.critical, ShieldCheck],
    ["Open cases", overview.metrics.openCases, ClipboardList],
    ["Precision", `${Math.round(overview.metrics.precision * 100)}%`, CheckCircle2],
  ];
  return (
    <>
      {error && <div className="error" role="alert">{error}</div>}
      <section className="metrics">{metricCards.map(([label, value, Icon]) => <div className="metric" key={label}><Icon /><small>{label}</small><strong>{String(value)}</strong></div>)}</section>
      <section className="grid">
        <div className="panel"><div className="panel-head"><h2>Alert volume</h2><span className="badge green">Last 7 days</span></div><Suspense fallback={<div className="dashboard-loading" role="status">Loading chart…</div>}><AlertVolumeChart data={chart} /></Suspense></div>
        <div className="panel"><div className="panel-head"><h2>Detection quality</h2><span className="badge blue">Evaluation</span></div><div className="quality"><strong>{Math.round(overview.metrics.recall * 100)}%</strong><span>Recall</span><strong>{Math.round(overview.metrics.precision * 100)}%</strong><span>Precision</span></div><p className="muted">Metrics are calculated against isolated ground-truth labels.</p></div>
      </section>
      <div className="panel"><div className="panel-head"><h2>Priority alert queue</h2><Link className="text-link" to="/alerts">View all alerts</Link></div>{overview.recentAlerts.length ? <AlertTable alerts={overview.recentAlerts} /> : <p className="muted">No alerts require review.</p>}</div>
    </>
  );
}

function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [error, setError] = useState("");
  useEffect(() => { api.get<{ data: AlertRecord[] }>("/api/alerts").then((response) => setAlerts(response.data.data)).catch(() => setError("Could not load alerts.")); }, []);
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">INVESTIGATION QUEUE</p><h2>Alerts</h2></div><span className="muted">{alerts.length} alerts</span></div>{error ? <div className="error">{error}</div> : <AlertTable alerts={alerts} />}</section>;
}

function CasesPage() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const load = () => { setLoading(true); api.get<{ data: CaseRecord[] }>("/api/cases").then((response) => { setCases(response.data.data); setError(""); }).catch(() => setError("Could not load cases.")).finally(() => setLoading(false)); };
  useEffect(load, []);
  const updateCase = async (id: string, status: string) => { try { await api.patch(`/api/cases/${id}`, { status }); load(); } catch { setError("Could not update the case."); } };
  const closeAsLegitimate = async (id: string) => { try { await api.post(`/api/cases/${id}/disposition`, { disposition: "LEGITIMATE", comment: "Reviewed by analyst." }); load(); } catch { setError("Could not record the disposition."); } };
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>Cases / Investigations</h2></div></div>{loading ? <p className="muted">Loading cases...</p> : error ? <div className="error">{error}</div> : cases.length === 0 ? <p className="muted">No investigations have been created.</p> : <table><thead><tr><th>Case</th><th>Alerts</th><th>Assignee</th><th>Status</th><th>Action</th></tr></thead><tbody>{cases.map((item) => <tr key={item.id}><td><strong>{item.id}</strong></td><td>{item.caseAlerts?.length ?? 0}</td><td>{item.assignedTo?.name ?? "Unassigned"}</td><td>{item.status}</td><td>{item.status !== "CLOSED" && <><button className="text-link" type="button" onClick={() => updateCase(item.id, "IN_PROGRESS")}>Start review</button>{" "}<button className="text-link" type="button" onClick={() => closeAsLegitimate(item.id)}>Close legitimate</button></>}</td></tr>)}</tbody></table>}</section>;
}

function AuditPage() {
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState("");
  useEffect(() => { api.get<{ data: Array<Record<string, unknown>> }>("/api/audit").then((response) => setEvents(response.data.data)).catch(() => setError("Could not load audit history.")); }, []);
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">IMMUTABLE HISTORY</p><h2>Audit History</h2></div></div>{error ? <div className="error">{error}</div> : events.length === 0 ? <p className="muted">No audit events recorded.</p> : <table><thead><tr><th>Time</th><th>Entity</th><th>Action</th><th>Actor</th></tr></thead><tbody>{events.map((event) => <tr key={String(event.id)}><td>{new Date(String(event.occurredAt ?? event.createdAt)).toLocaleString()}</td><td>{String(event.entityType)} / {String(event.entityId)}</td><td>{String(event.eventType)}</td><td>{String(event.actorId ?? "System")}</td></tr>)}</tbody></table>}</section>;
}

function AlertTable({ alerts }: { alerts: AlertRecord[] }) {
  const [selected, setSelected] = useState<AlertRecord | null>(null);
  const [detail, setDetail] = useState<{ evidence: Array<{ description: string }>; events: Array<{ eventType: string }> } | null>(null);
  useEffect(() => { if (selected) api.get(`/api/alerts/${selected.id}`).then((response) => setDetail(response.data)).catch(() => setDetail(null)); }, [selected]);
  const closeAlert = async (status: string) => { if (!selected) return; await api.post(`/api/alerts/${selected.id}/status`, { status }); setSelected({ ...selected, status }); };
  return <><table><thead><tr><th>Alert</th><th>Rule</th><th>Customer</th><th>Priority</th><th>Status</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id} onClick={() => setSelected(alert)} className="clickable"><td><strong>{alert.id}</strong><br /><small>{alert.explanation}</small></td><td>{alert.rule_name ?? alert.ruleName}</td><td>{alert.customer_id ?? alert.customerId}</td><td><span className={`priority ${alert.priority.toLowerCase()}`}>{alert.priority}</span></td><td>{alert.status}</td></tr>)}</tbody></table>{selected && <div className="drawer"><button className="close" onClick={() => setSelected(null)} type="button">×</button><p className="eyebrow">ALERT INVESTIGATION</p><h2>{selected.id}</h2><span className={`priority ${selected.priority.toLowerCase()}`}>{selected.priority}</span><h3>Why was this flagged?</h3><p>{selected.explanation}</p><dl><dt>Rule</dt><dd>{selected.rule_name ?? selected.ruleName}</dd><dt>Customer</dt><dd>{selected.customer_id ?? selected.customerId}</dd><dt>Status</dt><dd>{selected.status}</dd></dl>{detail?.evidence.map((item, index) => <p className="muted" key={index}>Evidence: {item.description}</p>)}{selected.status !== "CLOSED" && <button className="primary" type="button" onClick={() => closeAlert("INVESTIGATING")}>Start investigation</button>}</div>}</>;
}

function TransactionsPage() {
  const [rows, setRows] = useState<Array<Record<string, unknown>>>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [assessment, setAssessment] = useState<Record<string, unknown> | null>(null);
  useEffect(() => { api.get<{ data: Array<Record<string, unknown>> }>("/api/transactions", { params: search ? { search } : undefined }).then((response) => setRows(response.data.data)).catch(() => setError("Could not load transactions.")); }, [search]);
  const assess = async (id: string) => { try { const response = await api.post(`/api/risk/assess/${id}`, {}); setAssessment(response.data.assessment); } catch { setError("Risk assessment failed."); } };
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">TRANSACTION MONITORING</p><h2>Transactions</h2></div><input aria-label="Search transactions" placeholder="Search ID, customer, account..." value={search} onChange={(event) => setSearch(event.target.value)} /></div>{error && <div className="error">{error}</div>}{rows.length === 0 ? <p className="muted">No transactions found.</p> : <table><thead><tr><th>Transaction</th><th>Type</th><th>Status</th><th>Amount</th><th>Action</th></tr></thead><tbody>{rows.map((row) => <tr key={String(row.id)}><td>{String(row.id)}</td><td>{String(row.transactionType)}</td><td>{String(row.status)}</td><td>{String(row.amount)} {String(row.currency)}</td><td><button className="text-link" type="button" onClick={() => assess(String(row.id))}>Assess risk</button></td></tr>)}</tbody></table>}{assessment && <div className="panel"><h3>Latest risk assessment</h3><p>Score: {String(assessment.score)} / Priority: {String(assessment.priority)}</p><ul>{(assessment.findings as Array<{ ruleCode: string; evidence: string }>).map((finding) => <li key={finding.ruleCode}>{finding.ruleCode}: {finding.evidence}</li>)}</ul></div>}</section>;
}

function ResourcePage({ title, endpoint, columns, searchable = false }: { title: string; endpoint: string; columns: string[]; searchable?: boolean }) {
  const [rows, setRows] = useState<Array<Record<string, unknown>>>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    setLoading(true);
    api.get<{ data: Array<Record<string, unknown>> }>(endpoint, { params: search ? { search } : undefined })
      .then((response) => { setRows(response.data.data); setError(""); })
      .catch(() => setError(`Could not load ${title.toLowerCase()}.`))
      .finally(() => setLoading(false));
  }, [endpoint, search, title]);
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">OPERATIONAL DATA</p><h2>{title}</h2></div>{searchable && <input aria-label={`Search ${title}`} placeholder="Search..." value={search} onChange={(event) => setSearch(event.target.value)} />}</div>
    {loading ? <p className="muted">Loading {title.toLowerCase()}...</p> : error ? <div className="error">{error}</div> : rows.length === 0 ? <p className="muted">No records found.</p> : <table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={String(row.id ?? index)}>{columns.map((column) => <td key={column}>{formatCell(row[column])}</td>)}</tr>)}</tbody></table>}
  </section>;
}

function AnalyticsPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.get<Overview & { evaluation?: Record<string, unknown> }>("/api/overview").then((response) => setOverview(response.data)).catch(() => setError("Could not load analytics.")); }, []);
  const evaluation = (overview as (Overview & { evaluation?: Record<string, unknown> }) | null)?.evaluation;
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">MODEL EVALUATION</p><h2>Analytics / Reports</h2></div></div>{error ? <div className="error">{error}</div> : !overview ? <p className="muted">Loading analytics...</p> : <div className="metrics">{Object.entries(evaluation ?? overview.metrics).filter(([, value]) => typeof value === "number").slice(0, 8).map(([label, value]) => <div className="metric" key={label}><small>{label}</small><strong>{typeof value === "number" && value < 1 ? `${(value * 100).toFixed(1)}%` : String(value)}</strong></div>)}</div>}</section>;
}

function SettingsPage() {
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">WORKSPACE</p><h2>Settings</h2></div></div><p className="muted">Runtime configuration is managed through the backend deployment environment. This workspace uses role-based access, short-lived JWTs, and protected evaluation storage.</p></section>;
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function NotFoundPage() {
  return <section className="panel placeholder-page"><ListChecks size={40} /><p className="eyebrow">404 / NOT FOUND</p><h2>That page does not exist</h2><p className="muted">Use the sidebar to return to a supported RiskLens section.</p><Link className="primary inline-button" to="/dashboard">Go to dashboard</Link></section>;
}

function Login({ onLogin }: { onLogin: (token: string, user: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();
  return <div className="login"><div className="login-card"><div className="brand"><ShieldCheck /> RiskLens<span>AI</span></div><h1>Sign in to your workspace</h1><p className="muted">Review explainable alerts and manage investigations.</p><form onSubmit={async (event) => { event.preventDefault(); try { const response = await api.post("/api/auth/login", { email, password }); onLogin(response.data.token, response.data.user); navigate("/dashboard", { replace: true }); } catch { setError("Invalid credentials or inactive account"); } }}><label>Email<input value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="email" required /></label><label>Password<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" required /></label>{error && <div className="error">{error}</div>}<button className="primary" type="submit">Continue to RiskLens</button></form><small>Use an account provisioned and activated by an administrator.</small></div></div>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
