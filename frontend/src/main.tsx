import React, { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import axios, { type AxiosRequestConfig, type AxiosResponse } from "axios";
import {
  Activity, AlertTriangle, BarChart3, CheckCircle2, ChevronLeft, ChevronRight,
  ClipboardList, Database, FileCheck2, FileClock, LayoutDashboard, ListChecks,
  LogOut, Network, RefreshCw, Settings, ShieldCheck, SlidersHorizontal, Users,
  WalletCards, X,
} from "lucide-react";
import {
  BrowserRouter, Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate,
} from "react-router-dom";
import "./style.css";

const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:4000" });
api.interceptors.response.use((response) => response, (error: unknown) => {
  if (axios.isAxiosError(error) && error.response?.status === 401 && !/\/api\/auth\/(login|register)$/.test(error.config?.url ?? "")) {
    window.dispatchEvent(new Event("risklens:unauthorized"));
  }
  return Promise.reject(error);
});
const TOKEN_KEY = "risklens-token";
const PAGE_SIZE = 25;
const AlertVolumeChart = lazy(() => import("./components/AlertVolumeChart.js"));
type SharedGet = { controller: AbortController; consumers: number; promise: Promise<AxiosResponse<unknown>> };
const inFlightGets = new Map<string, SharedGet>();

function getShared<T>(url: string, config: AxiosRequestConfig = {}) {
  const authorization = String(api.defaults.headers.common.Authorization ?? "");
  const key = `${api.getUri({ ...config, url })}|${authorization}`;
  let request = inFlightGets.get(key);
  if (!request || request.controller.signal.aborted) {
    const controller = new AbortController();
    const created: SharedGet = { controller, consumers: 0, promise: Promise.resolve({} as AxiosResponse<unknown>) };
    created.promise = api.get<T>(url, { ...config, signal: controller.signal }) as Promise<AxiosResponse<unknown>>;
    request = created;
    inFlightGets.set(key, request);
    void request.promise.finally(() => { if (inFlightGets.get(key) === request) inFlightGets.delete(key); }).catch(() => undefined);
  }
  const shared = request;
  const signal = config.signal;
  return new Promise<AxiosResponse<T>>((resolve, reject) => {
    if (signal?.aborted) { reject(new axios.CanceledError()); return; }
    shared.consumers += 1;
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      signal?.removeEventListener?.("abort", onAbort);
      shared.consumers -= 1;
      if (shared.consumers === 0) queueMicrotask(() => {
        if (shared.consumers === 0 && inFlightGets.get(key) === shared) shared.controller.abort();
      });
    };
    const onAbort = () => { release(); reject(new axios.CanceledError()); };
    signal?.addEventListener?.("abort", onAbort, { once: true });
    shared.promise.then(
      (response) => { if (!signal?.aborted) { release(); resolve(response as AxiosResponse<T>); } },
      (error: unknown) => { release(); reject(error); },
    );
  });
}

type User = { id: string; name: string; email: string; role: string };
type AlertRecord = {
  id: string; customer_id?: string; customerId?: string; rule_name?: string; ruleName?: string;
  priority: string; score?: number; riskScore?: number; explanation: string; status: string;
};
type Overview = {
  metrics: { alerts: number; critical: number; openCases: number; precision: number | null; recall: number | null };
  evaluation?: { precision: number; recall: number; f1: number; accuracy: number; truePositives: number; falsePositives: number; falseNegatives: number; trueNegatives: number; evidenceCompleteness: number; validationPassRate: number; ruleMetrics: Array<{ ruleCode: string; precision: number; recall: number }>; scenarioCoverage: Record<string, number> };
  volume: number[];
  recentAlerts: AlertRecord[];
};
type CaseRecord = { id: string; status: string; disposition?: string | null; assignedTo?: { name: string } | null; caseAlerts?: Array<{ alert: AlertRecord }> };
type PageResponse<T> = { data: T[]; total?: number; page?: number; pageSize?: number };

const navigation = [
  { label: "Dashboard", to: "/dashboard", icon: LayoutDashboard },
  { label: "Transaction Monitoring", to: "/transactions", icon: WalletCards },
  { label: "Risk Alerts", to: "/alerts", icon: AlertTriangle },
  { label: "Case Management", to: "/cases", icon: ClipboardList },
  { label: "Customer Records", to: "/customers", icon: Users },
  { label: "Account Monitoring", to: "/accounts", icon: Network },
  { label: "Risk Analytics", to: "/analytics", icon: BarChart3 },
  { label: "Risk Rules", to: "/rules", icon: SlidersHorizontal },
  { label: "Data Processing", to: "/data-generation", icon: Database },
  { label: "Validation Results", to: "/validation", icon: FileCheck2 },
  { label: "Audit History", to: "/audit", icon: FileClock },
  { label: "User Management", to: "/users", icon: Users, adminOnly: true },
  { label: "System Settings", to: "/settings", icon: Settings },
];

function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<"anonymous" | "restoring" | "authenticated" | "error">(() => token ? "restoring" : "anonymous");
  const [restoreAttempt, setRestoreAttempt] = useState(0);

  useEffect(() => {
    if (!token) {
      delete api.defaults.headers.common.Authorization;
      setUser(null);
      setAuthState("anonymous");
      return;
    }
    if (user) {
      setAuthState("authenticated");
      return;
    }

    const controller = new AbortController();
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
    setAuthState("restoring");
    getShared<{ user: User }>("/api/auth/me", { signal: controller.signal })
      .then(({ data }) => { setUser(data.user); setAuthState("authenticated"); })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (axios.isAxiosError(error) && error.response?.status === 401) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
          setAuthState("anonymous");
          return;
        }
        setAuthState("error");
      });
    return () => controller.abort();
  }, [token, restoreAttempt, user]);

  const login = (value: string, profile: User) => {
    localStorage.setItem(TOKEN_KEY, value);
    api.defaults.headers.common.Authorization = `Bearer ${value}`;
    setUser(profile);
    setAuthState("authenticated");
    setToken(value);
  };
  const logout = () => {
    localStorage.removeItem(TOKEN_KEY);
    delete api.defaults.headers.common.Authorization;
    setToken(null);
    setUser(null);
  };

  useEffect(() => {
    const invalidateSession = () => {
      localStorage.removeItem(TOKEN_KEY);
      delete api.defaults.headers.common.Authorization;
      setToken(null);
      setUser(null);
      setAuthState("anonymous");
    };
    window.addEventListener("risklens:unauthorized", invalidateSession);
    return () => window.removeEventListener("risklens:unauthorized", invalidateSession);
  }, []);

  if (authState === "restoring") return <AuthMessage title="Restoring your session" detail="Verifying your account with RiskLens." />;
  if (authState === "error") return <AuthMessage title="Session could not be restored" detail="Check your connection, then try again." onRetry={() => setRestoreAttempt((attempt) => attempt + 1)} />;

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={authState === "authenticated" ? <Navigate to="/dashboard" replace /> : <Login onLogin={login} />} />
        <Route element={<ProtectedRoute token={token} user={user} />}>
          <Route element={<DashboardLayout user={user!} onLogout={logout} />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/transactions" element={<TransactionsPage />} />
            <Route path="/customers" element={<ResourcePage title="Customer Records" endpoint="/api/customers" columns={["id", "fullName", "email", "countryCode"]} searchable paginated />} />
            <Route path="/accounts" element={<ResourcePage title="Account Monitoring" endpoint="/api/accounts" columns={["id", "accountType", "status", "currency", "currentBalance"]} searchable paginated />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/rules" element={<ResourcePage title="Risk Rules" endpoint="/api/rules" columns={["ruleCode", "version", "name", "severity", "weight", "enabled"]} paginated />} />
            <Route path="/data-generation" element={<ResourcePage title="Data Processing" endpoint="/api/generation-runs" columns={["id", "seed", "scale", "status", "startedAt", "completedAt"]} paginated />} />
            <Route path="/validation" element={<ResourcePage title="Validation Results" endpoint="/api/validation" columns={["checkName", "status", "message", "checkedAt"]} paginated />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/users" element={user?.role === "ADMIN" ? <ResourcePage title="User Management" endpoint="/api/users" columns={["email", "name", "role", "status"]} paginated /> : <Navigate to="/dashboard" replace />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

function AuthMessage({ title, detail, onRetry }: { title: string; detail: string; onRetry?: () => void }) {
  return <main className="auth-state"><ShieldCheck size={28} /><h1>{title}</h1><p>{detail}</p>{onRetry && <button className="primary" type="button" onClick={onRetry}><RefreshCw size={16} /> Retry</button>}</main>;
}

function ProtectedRoute({ token, user }: { token: string | null; user: User | null }) {
  const location = useLocation();
  return token && user ? <Outlet /> : <Navigate to="/login" replace state={{ from: location.pathname }} />;
}

function DashboardLayout({ user, onLogout }: { user: User; onLogout: () => void }) {
  const location = useLocation();
  const items = navigation.filter((item) => !item.adminOnly || user.role === "ADMIN");
  const initials = user.name.trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  return <div className="app-shell">
    <aside className="sidebar">
      <Link className="brand" to="/dashboard" aria-label="RiskLens AI dashboard"><span className="brand-mark"><ShieldCheck size={20} /></span><span>RiskLens<strong>AI</strong></span></Link>
      <nav aria-label="Primary navigation">{items.map(({ label, to, icon: Icon }) => <NavLink key={to} to={to} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} end={to === "/dashboard"} title={label} aria-label={label}><Icon size={17} aria-hidden="true" /><span>{label}</span></NavLink>)}</nav>
      <button className="sign-out" onClick={onLogout} type="button"><LogOut size={17} aria-hidden="true" /><span>Sign out</span></button>
    </aside>
    <main className="main-content">
      <header className="page-header">
        <div><h1>{pageTitle(location.pathname)}</h1></div>
        <div className="user-profile" aria-label={`Signed in as ${user.name}, ${user.email}, ${formatRole(user.role)}`}><span className="avatar" aria-hidden="true">{initials || <Users size={16} />}</span><span className="user-copy"><strong>{user.name}</strong><small>{user.email}</small><small>{formatRole(user.role)}</small></span></div>
      </header>
      <Outlet />
    </main>
  </div>;
}

function pageTitle(pathname: string) { return navigation.find((item) => item.to === pathname)?.label ?? (pathname === "/" ? "Dashboard" : "Page not found"); }
function formatRole(role: string) { return role.toLowerCase().split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join(" "); }

function useOverview() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    getShared<Overview>("/api/overview", { signal: controller.signal })
      .then(({ data: result }) => { setData(result); setError(""); })
      .catch(() => { if (!controller.signal.aborted) setError("Dashboard data could not be loaded."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [reload]);
  return { data, error, loading, retry: () => setReload((value) => value + 1) };
}

function DashboardPage() {
  const { data: overview, error, retry } = useOverview();
  const chart = useMemo(() => overview?.volume.map((value, index) => ({ day: dayLabel(index), value })) ?? [], [overview?.volume]);
  const cards = [
    ["Open alerts", overview?.metrics.alerts, AlertTriangle],
    ["Critical alerts", overview?.metrics.critical, ShieldCheck],
    ["Open cases", overview?.metrics.openCases, ClipboardList],
    ["Detection precision", !overview ? (error ? null : undefined) : overview.metrics.precision == null ? null : `${Math.round(overview.metrics.precision * 100)}%`, CheckCircle2],
  ] as const;
  return <>
    {error && <ErrorState message={error} onRetry={retry} />}
    <section className="metrics-grid" aria-label="Operational summary">
      {cards.map(([label, value, Icon]) => <div className="metric-card" key={label}><span className="metric-icon"><Icon size={18} /></span><span className="metric-label">{label}</span>{value === undefined ? error ? <strong className="metric-unavailable">Unavailable</strong> : <Skeleton className="metric-skeleton" /> : value === null ? <strong className="metric-unavailable">Not available</strong> : <strong className="metric-value">{value}</strong>}</div>)}
    </section>
    <section className="dashboard-grid">
      <div className="panel chart-panel"><div className="panel-heading"><div><p className="eyebrow">RECENT ACTIVITY</p><h2>Alert volume</h2></div><span className="badge neutral">Last 7 days</span></div>{overview ? <Suspense fallback={<Skeleton className="chart-skeleton" />}><AlertVolumeChart data={chart} /></Suspense> : error ? <EmptyState title="Activity unavailable" detail="Retry to load the recent alert volume." /> : <Skeleton className="chart-skeleton" />}</div>
      <div className="panel detection-panel"><div className="panel-heading"><div><p className="eyebrow">EVALUATION</p><h2>Detection performance</h2></div><Activity size={18} className="heading-icon" /></div>{overview?.evaluation ? <div className="quality-grid"><MetricValue label="Precision" value={overview.evaluation.precision} /><MetricValue label="Recall" value={overview.evaluation.recall} /><MetricValue label="F1 score" value={overview.evaluation.f1} /><MetricValue label="Accuracy" value={overview.evaluation.accuracy} /></div> : overview ? <p className="empty-state">Evaluation metrics are unavailable for this data source.</p> : error ? <p className="empty-state">Evaluation metrics are currently unavailable.</p> : <div className="quality-skeleton"><Skeleton /><Skeleton /><Skeleton /><Skeleton /></div>}<p className="footnote">Evaluation labels are isolated from operational records.</p></div>
    </section>
    <section className="panel"><div className="panel-heading"><div><p className="eyebrow">HIGH PRIORITY</p><h2>Recent risk alerts</h2></div><Link className="text-link" to="/alerts">View alert queue <ChevronRight size={15} /></Link></div>{overview ? <AlertTable alerts={overview.recentAlerts} compact /> : error ? <EmptyState title="Alerts unavailable" detail="Retry to load the recent alert queue." /> : <TableSkeleton rows={4} columns={6} />}</section>
  </>;
}

function dayLabel(index: number) { const date = new Date(); date.setDate(date.getDate() - (6 - index)); return date.toLocaleDateString(undefined, { weekday: "short" }); }
function MetricValue({ label, value }: { label: string; value: number }) { return <div className="quality-item"><strong>{(value * 100).toFixed(1)}%</strong><span>{label}</span></div>; }

function usePagedResource<T>(endpoint: string, options: { searchable?: boolean; paginated?: boolean } = {}) {
  const [rows, setRows] = useState<T[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    const timer = window.setTimeout(() => { setDebouncedSearch(search.trim()); setPage(1); }, options.searchable ? 300 : 0);
    return () => window.clearTimeout(timer);
  }, [search, options.searchable]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    if (options.searchable && search.trim() !== debouncedSearch) return () => controller.abort();
    const params: Record<string, string | number> = {};
    if (options.paginated) { params.page = page; params.pageSize = PAGE_SIZE; }
    if (options.searchable && debouncedSearch) params.search = debouncedSearch;
    getShared<PageResponse<T>>(endpoint, { params, signal: controller.signal })
      .then(({ data }) => { setRows(data.data); setTotal(typeof data.total === "number" ? data.total : null); setError(""); })
      .catch((reason: unknown) => { if (!controller.signal.aborted) setError(`Could not load ${resourceName(endpoint)}.`); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [endpoint, options.paginated, options.searchable, page, search, debouncedSearch, reload]);
  return { rows, total, search, setSearch, page, setPage, loading, error, retry: () => setReload((value) => value + 1), refresh: () => setReload((value) => value + 1) };
}

function resourceName(endpoint: string) { const parts = endpoint.split("/").filter(Boolean); return parts[parts.length - 1]?.replace(/-/g, " ") ?? "records"; }

function AlertsPage() {
  const list = usePagedResource<AlertRecord>("/api/alerts", { searchable: true, paginated: true });
  return <section className="panel page-panel" aria-busy={list.loading}><div className="panel-heading list-heading"><div><p className="eyebrow">INVESTIGATION QUEUE</p><h2>Risk Alerts</h2></div><div className="list-controls"><SearchInput label="Search alerts" value={list.search} onChange={list.setSearch} placeholder="Alert, customer, or reason" /><span className="muted" role={list.loading ? "status" : undefined}>{list.loading && list.rows.length > 0 ? "Updating results" : `${list.total ?? (list.loading ? "Loading" : list.rows.length)} records`}</span></div></div>{list.error && <ErrorState message={list.error} onRetry={list.retry} />}{list.loading && !list.rows.length ? <TableSkeleton rows={8} columns={5} /> : list.rows.length ? <AlertTable alerts={list.rows} /> : !list.error ? <EmptyState title="No alerts found" detail="Try a different search or review the current filters." /> : null}{list.total !== null && <Pagination page={list.page} pageSize={PAGE_SIZE} total={list.total} onPage={list.setPage} />}</section>;
}

function CasesPage() {
  const list = usePagedResource<CaseRecord>("/api/cases", { paginated: true });
  const [acting, setActing] = useState("");
  const [actionError, setActionError] = useState("");
  const perform = async (caseId: string, action: "start" | "close") => {
    setActing(caseId); setActionError("");
    try {
      if (action === "start") await api.patch(`/api/cases/${caseId}`, { status: "IN_PROGRESS" });
      else await api.post(`/api/cases/${caseId}/disposition`, { disposition: "LEGITIMATE" });
      list.refresh();
    } catch { setActionError("The case could not be updated. Retry the action."); }
    finally { setActing(""); }
  };
  return <section className="panel page-panel" aria-busy={list.loading}><div className="panel-heading list-heading"><div><p className="eyebrow">INVESTIGATION WORKFLOW</p><h2>Case Management</h2></div>{list.loading && list.rows.length > 0 && <span className="muted" role="status">Updating…</span>}</div>{actionError && <ErrorState message={actionError} />}{list.error && <ErrorState message={list.error} onRetry={list.retry} />}{list.loading && !list.rows.length ? <TableSkeleton rows={6} columns={5} /> : list.rows.length ? <div className="table-scroll"><table><thead><tr><th>Case</th><th>Alerts</th><th>Assignee</th><th>Status</th><th>Actions</th></tr></thead><tbody>{list.rows.map((item) => <tr key={item.id}><td><strong>{item.id}</strong></td><td>{item.caseAlerts?.length ?? 0}</td><td>{item.assignedTo?.name ?? "Unassigned"}</td><td><StatusBadge value={item.status} /></td><td>{item.status !== "CLOSED" && <div className="row-actions"><button className="text-link" type="button" disabled={acting === item.id} onClick={() => perform(item.id, "start")}>Start review</button><button className="text-link" type="button" disabled={acting === item.id} onClick={() => perform(item.id, "close")}>Close as legitimate</button></div>}</td></tr>)}</tbody></table></div> : !list.error ? <EmptyState title="No cases to review" detail="Cases will appear here when alerts are grouped for investigation." /> : null}{list.total !== null && <Pagination page={list.page} pageSize={PAGE_SIZE} total={list.total} onPage={list.setPage} />}</section>;
}

function AlertTable({ alerts, compact = false }: { alerts: AlertRecord[]; compact?: boolean }) {
  const [selected, setSelected] = useState<AlertRecord | null>(null);
  const [detail, setDetail] = useState<{ evidence: Array<{ description: string }>; events: Array<{ eventType: string }> } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionError, setActionError] = useState("");
  const [acting, setActing] = useState(false);
  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    const controller = new AbortController();
    setDetail(null);
    setDetailLoading(true);
    getShared<{ alert: AlertRecord; evidence: Array<{ description: string }>; events: Array<{ eventType: string }>; cases: unknown[] }>(`/api/alerts/${selected.id}`, { signal: controller.signal })
      .then(({ data }) => setDetail(data))
      .catch(() => { if (!controller.signal.aborted) setActionError("Alert details could not be loaded."); })
      .finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => controller.abort();
  }, [selected?.id]);
  const changeStatus = async (status: string) => {
    if (!selected) return;
    setActing(true); setActionError("");
    try { await api.post(`/api/alerts/${selected.id}/status`, { status }); setSelected({ ...selected, status }); }
    catch { setActionError("Alert status could not be updated. Retry the action."); }
    finally { setActing(false); }
  };
  return <>
    {alerts.length === 0 ? <EmptyState title="No recent alerts" detail="No risk alerts match this view." /> : <div className="table-scroll"><table><thead><tr><th>Alert</th><th>Rule</th><th>Customer</th><th>Priority</th><th>Status</th><th>Action</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id}><td><strong>{alert.id}</strong>{!compact && <small className="cell-detail">{alert.explanation}</small>}</td><td>{alert.rule_name ?? alert.ruleName ?? "—"}</td><td>{alert.customer_id ?? alert.customerId ?? "—"}</td><td><PriorityBadge value={alert.priority} /></td><td><StatusBadge value={alert.status} /></td><td><button className="text-link" type="button" onClick={() => { setActionError(""); setSelected(alert); }}>Review</button></td></tr>)}</tbody></table></div>}
    {selected && <div className="drawer-backdrop" role="presentation" onClick={(event) => { if (event.target === event.currentTarget) setSelected(null); }}><aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="alert-title"><button className="icon-button drawer-close" type="button" aria-label="Close alert details" onClick={() => setSelected(null)}><X size={18} /></button><p className="eyebrow">ALERT REVIEW</p><h2 id="alert-title">{selected.id}</h2><PriorityBadge value={selected.priority} /><h3>Detection details</h3><p>{selected.explanation}</p><dl><dt>Rule</dt><dd>{selected.rule_name ?? selected.ruleName ?? "—"}</dd><dt>Customer</dt><dd>{selected.customer_id ?? selected.customerId ?? "—"}</dd><dt>Status</dt><dd><StatusBadge value={selected.status} /></dd></dl>{detailLoading ? <Skeleton className="detail-skeleton" /> : detail?.evidence.map((item, index) => <p className="evidence-item" key={`${item.description}-${index}`}><strong>Evidence</strong>{item.description}</p>)}{actionError && <ErrorState message={actionError} />}{selected.status !== "CLOSED" && selected.status !== "FALSE_POSITIVE" && <div className="drawer-actions"><button className="secondary" type="button" disabled={acting || selected.status === "INVESTIGATING"} onClick={() => changeStatus("INVESTIGATING")}>{acting ? "Updating…" : selected.status === "INVESTIGATING" ? "Under investigation" : "Start investigation"}</button><button className="primary" type="button" disabled={acting} onClick={() => changeStatus("CLOSED")}>Close alert</button></div>}</aside></div>}
  </>;
}

function TransactionsPage() {
  const list = usePagedResource<Record<string, unknown>>("/api/transactions", { searchable: true, paginated: true });
  const [assessment, setAssessment] = useState<Record<string, unknown> | null>(null);
  const [assessmentError, setAssessmentError] = useState("");
  const [assessing, setAssessing] = useState("");
  const assess = async (id: string) => {
    setAssessing(id); setAssessment(null); setAssessmentError("");
    try { const { data } = await api.post(`/api/risk/assess/${id}`, {}); setAssessment(data.assessment); }
    catch { setAssessmentError("Risk assessment could not be completed. Retry the action."); }
    finally { setAssessing(""); }
  };
  return <section className="panel page-panel" aria-busy={list.loading}><div className="panel-heading list-heading"><div><p className="eyebrow">TRANSACTION MONITORING</p><h2>Transactions</h2></div><SearchInput label="Search transactions" value={list.search} onChange={list.setSearch} placeholder="Transaction, customer, or account" />{list.loading && list.rows.length > 0 && <span className="muted" role="status">Updating…</span>}</div>{assessmentError && <ErrorState message={assessmentError} />} {list.error && <ErrorState message={list.error} onRetry={list.retry} />}{list.loading && !list.rows.length ? <TableSkeleton rows={8} columns={5} /> : list.rows.length ? <div className="table-scroll"><table><thead><tr><th>Transaction</th><th>Type</th><th>Status</th><th>Amount</th><th>Action</th></tr></thead><tbody>{list.rows.map((row) => <tr key={String(row.id)}><td><strong>{String(row.id)}</strong></td><td>{formatCell(row.transactionType)}</td><td><StatusBadge value={String(row.status)} /></td><td>{formatCell(row.amount)} {formatCell(row.currency)}</td><td><button className="text-link" type="button" disabled={assessing === String(row.id)} onClick={() => assess(String(row.id))}>{assessing === String(row.id) ? "Assessing…" : "Assess risk"}</button></td></tr>)}</tbody></table></div> : !list.error ? <EmptyState title="No transactions found" detail="Try another transaction, customer, or account search." /> : null}{list.total !== null && <Pagination page={list.page} pageSize={PAGE_SIZE} total={list.total} onPage={list.setPage} />}{assessment && <div className="assessment-result"><h3>Risk assessment</h3><p>Score: {formatCell(assessment.score)} · Priority: <PriorityBadge value={String(assessment.priority)} /></p><ul>{(assessment.findings as Array<{ ruleCode: string; evidence: string }>).map((finding) => <li key={finding.ruleCode}><strong>{finding.ruleCode}</strong> {finding.evidence}</li>)}</ul></div>}</section>;
}

function ResourcePage({ title, endpoint, columns, searchable = false, paginated = false }: { title: string; endpoint: string; columns: string[]; searchable?: boolean; paginated?: boolean }) {
  const list = usePagedResource<Record<string, unknown>>(endpoint, { searchable, paginated });
  return <section className="panel page-panel" aria-busy={list.loading}><div className="panel-heading list-heading"><div><h2>{title}</h2></div>{searchable && <SearchInput label={`Search ${title}`} value={list.search} onChange={list.setSearch} placeholder={`Search ${title.toLowerCase()}`} />}{list.loading && list.rows.length > 0 && <span className="muted" role="status">Updating…</span>}</div>{list.error && <ErrorState message={list.error} onRetry={list.retry} />}{list.loading && !list.rows.length ? <TableSkeleton rows={7} columns={columns.length} /> : list.rows.length ? <div className="table-scroll"><table><thead><tr>{columns.map((column) => <th key={column}>{columnLabel(column)}</th>)}</tr></thead><tbody>{list.rows.map((row, index) => <tr key={String(row.id ?? row.email ?? index)}>{columns.map((column) => <td key={column}>{formatCell(row[column])}</td>)}</tr>)}</tbody></table></div> : !list.error ? <EmptyState title={`No ${title.toLowerCase()} found`} detail={searchable ? "Try a different search." : "Records will appear here when available."} /> : null}{paginated && list.total !== null && <Pagination page={list.page} pageSize={PAGE_SIZE} total={list.total} onPage={list.setPage} />}</section>;
}

function AuditPage() {
  const list = usePagedResource<Record<string, unknown>>("/api/audit", { paginated: true });
  return <section className="panel page-panel" aria-busy={list.loading}><div className="panel-heading"><div><h2>Audit History</h2></div>{list.loading && list.rows.length > 0 && <span className="muted" role="status">Updating…</span>}</div>{list.error && <ErrorState message={list.error} onRetry={list.retry} />}{list.loading && !list.rows.length ? <TableSkeleton rows={8} columns={4} /> : list.rows.length ? <div className="table-scroll"><table><thead><tr><th>Time</th><th>Entity</th><th>Action</th><th>Actor</th></tr></thead><tbody>{list.rows.map((event) => <tr key={String(event.id)}><td>{formatDate(event.occurredAt ?? event.createdAt)}</td><td>{formatCell(event.entityType)} / {formatCell(event.entityId)}</td><td>{formatCell(event.eventType)}</td><td>{formatCell(event.actorId ?? "System")}</td></tr>)}</tbody></table></div> : !list.error ? <EmptyState title="No audit events" detail="Recorded operational actions will appear here." /> : null}{list.total !== null && <Pagination page={list.page} pageSize={PAGE_SIZE} total={list.total} onPage={list.setPage} />}</section>;
}

function AnalyticsPage() {
  const { data: overview, error, retry } = useOverview();
  const evaluation = overview?.evaluation;
  const items = evaluation ? [
    ["Precision", evaluation.precision, true], ["Recall", evaluation.recall, true], ["F1 score", evaluation.f1, true], ["Accuracy", evaluation.accuracy, true],
    ["True positives", evaluation.truePositives, false], ["False positives", evaluation.falsePositives, false], ["False negatives", evaluation.falseNegatives, false], ["True negatives", evaluation.trueNegatives, false],
    ["Evidence coverage", evaluation.evidenceCompleteness, true], ["Validation pass rate", evaluation.validationPassRate, true],
  ] as const : [];
  return <section className="panel page-panel"><div className="panel-heading"><div><p className="eyebrow">DETECTION PERFORMANCE</p><h2>Risk Analytics</h2></div></div>{error ? <ErrorState message={error} onRetry={retry} /> : !overview ? <TableSkeleton rows={3} columns={4} /> : !evaluation ? <EmptyState title="Evaluation metrics unavailable" detail="The current data source does not provide an isolated evaluation dataset." /> : <><div className="analytics-grid">{items.map(([label, value, percent]) => <div className="analytics-metric" key={label}><span>{label}</span><strong>{percent ? `${(Number(value) * 100).toFixed(1)}%` : Number(value).toLocaleString()}</strong></div>)}</div><div className="analytics-detail-grid"><section><h3>Performance by rule</h3><div className="table-scroll"><table><thead><tr><th>Rule</th><th>Precision</th><th>Recall</th></tr></thead><tbody>{evaluation.ruleMetrics.map((item) => <tr key={item.ruleCode}><td>{item.ruleCode}</td><td>{(item.precision * 100).toFixed(1)}%</td><td>{(item.recall * 100).toFixed(1)}%</td></tr>)}</tbody></table></div></section><section><h3>Scenario coverage</h3><div className="table-scroll"><table><thead><tr><th>Scenario</th><th>Coverage</th></tr></thead><tbody>{Object.entries(evaluation.scenarioCoverage).map(([name, value]) => <tr key={name}><td>{formatLabel(name)}</td><td>{(value * 100).toFixed(1)}%</td></tr>)}</tbody></table></div></section></div><p className="footnote">Evaluation ground truth is used only for aggregate metrics and is not exposed through operational records.</p></>}</section>;
}

function SettingsPage() { return <section className="panel page-panel"><div className="panel-heading"><div><p className="eyebrow">WORKSPACE</p><h2>System Settings</h2></div></div><p className="muted">Runtime configuration is managed through the backend deployment environment. Account access and evaluation storage remain server-controlled.</p></section>; }
function NotFoundPage() { return <section className="panel empty-page"><ListChecks size={36} /><p className="eyebrow">404 / NOT FOUND</p><h2>Page not found</h2><p className="muted">Choose a section from the navigation to continue.</p><Link className="primary inline-button" to="/dashboard">Return to dashboard</Link></section>; }

function Login({ onLogin }: { onLogin: (token: string, user: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const destination = (location.state as { from?: string } | null)?.from ?? "/dashboard";
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError(""); setLoading(true);
    try { const { data } = await api.post<{ token: string; user: User }>("/api/auth/login", { email, password }); onLogin(data.token, data.user); navigate(destination, { replace: true }); }
    catch { setError("Sign-in failed. Check your credentials or contact an administrator."); }
    finally { setLoading(false); }
  };
  return <div className="login-page"><div className="login-card"><div className="brand login-brand"><span className="brand-mark"><ShieldCheck size={20} /></span><span>RiskLens<strong>AI</strong></span></div><h1>Sign in</h1><p className="muted">Use your provisioned account.</p><form onSubmit={submit}><label>Email address<input value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="username" required /></label><label>Password<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" required /></label>{error && <div className="error-state" role="alert">{error}</div>}<button className="primary login-submit" type="submit" disabled={loading}>{loading ? "Signing in…" : "Sign in"}</button></form><p className="login-footnote">Accounts are activated by an administrator.</p></div></div>;
}

function SearchInput({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder: string }) { return <div className="search-control"><input aria-label={label} placeholder={placeholder} value={value} onChange={(event) => onChange(event.target.value)} /><span>Search</span></div>; }
function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (page: number) => void }) { const pages = Math.max(1, Math.ceil(total / pageSize)); return <div className="pagination"><span>{total ? `${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}` : "0 records"}</span><div><button className="icon-button" type="button" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft size={17} /></button><span>Page {page} of {pages}</span><button className="icon-button" type="button" aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)}><ChevronRight size={17} /></button></div></div>; }
function StatusBadge({ value }: { value: string }) { const tone = value.toLowerCase().replace(/_/g, "-"); return <span className={`status-badge status-${tone}`}>{formatLabel(value)}</span>; }
function PriorityBadge({ value }: { value: string }) { const tone = value.toLowerCase(); return <span className={`priority-badge priority-${tone}`}>{formatLabel(value)}</span>; }
function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) { return <div className="error-state" role="alert"><span>{message}</span>{onRetry && <button className="text-link" type="button" onClick={onRetry}>Retry</button>}</div>; }
function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="empty-state"><h3>{title}</h3><p>{detail}</p></div>; }
function Skeleton({ className = "" }: { className?: string }) { return <span className={`skeleton ${className}`} aria-hidden="true" />; }
function TableSkeleton({ rows, columns }: { rows: number; columns: number }) { return <div className="table-skeleton" aria-label="Loading records">{Array.from({ length: rows }, (_, row) => <div className="skeleton-row" key={row} style={{ gridTemplateColumns: `repeat(${columns}, minmax(50px, 1fr))` }}>{Array.from({ length: columns }, (_, column) => <Skeleton key={column} />)}</div>)}</div>; }
function formatCell(value: unknown): string { if (value === null || value === undefined || value === "") return "—"; if (typeof value === "object") return JSON.stringify(value); if (typeof value === "boolean") return value ? "Yes" : "No"; return String(value); }
function columnLabel(value: string) { return value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/_/g, " ").replace(/^./, (letter: string) => letter.toUpperCase()); }
function formatLabel(value: string) { return value.toLowerCase().split(/[_-]/).map((part) => part[0]?.toUpperCase() + part.slice(1)).join(" "); }
function formatDate(value: unknown) { const date = new Date(String(value)); return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(); }

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
