# Local PostgreSQL and route verification

Run date: 2026-11-13. Environment: isolated PostgreSQL 16 cluster bound to `127.0.0.1:55432`; database `risklens_perf_test`; migrations 0001–0005 applied only to this disposable local database. It contains the synthetic dataset (5,000 customers, 7,000 accounts, 100,000 transactions, 1,000 alerts, 200 baseline cases, and 100,000 ground-truth labels). Integration fixtures are retained because append-only event triggers prohibit deleting their history. No production database or deployment was accessed.

## Verification results

- PostgreSQL integration test: **PASS**. It exercised login, `/api/auth/me`, invalid-token handling, analyst/admin/reviewer/customer authorization, customer isolation, transaction risk assessment, alert evidence, case creation and disposition, case/alert/audit history, query filters, pagination boundaries, and evaluation-cache invalidation after an alert insert.
- Backend test suite with PostgreSQL integration enabled: **26 passed, 0 failed, 0 skipped**.
- Backend TypeScript build: **PASS**.
- Frontend production build: **PASS**.
- Python suite: **14 passed**.
- Browser route automation: **BLOCKED**. The available computer-use browser host reported unavailable, and no Playwright/Puppeteer dependency is installed. Consequently, visual rendering, browser-only loading/error/retry states, nested-route refresh, and mobile interactions were not verified in this sprint.

## Route checklist

This checklist follows `frontend/src/main.tsx`. “API checked” means the backend route/query contract was exercised by the PostgreSQL integration test; it does not claim the React page was rendered in a browser.

| Frontend route | API checked | Browser page and interaction check |
|---|---|---|
| `/login` | `/api/auth/login`, invalid credentials/token paths | Not run; browser host unavailable |
| `/dashboard` | `/api/overview`, aggregates and evaluation cache invalidation | Not run; browser host unavailable |
| `/alerts` | `/api/alerts`, search, pagination boundary, detail/evidence, role denial | Not run; browser host unavailable |
| `/cases` | `/api/cases`, pagination, disposition and subsequent state | Not run; browser host unavailable |
| `/transactions` | `/api/transactions`, search, pagination boundary, customer isolation | Not run; browser host unavailable |
| `/customers` | `/api/customers`, search, KYC relation, customer isolation | Not run; browser host unavailable |
| `/accounts` | `/api/accounts`, search, ownership and customer isolation | Not run; browser host unavailable |
| `/analytics` | `/api/overview` aggregate contract | Not run; browser host unavailable |
| `/rules` | `/api/rules`, paginated query | Not run; browser host unavailable |
| `/data-generation` | `/api/generation-runs`, paginated query | Not run; browser host unavailable |
| `/validation` | `/api/validation`, paginated query | Not run; browser host unavailable |
| `/audit` | `/api/audit`, reviewer access and paginated query | Not run; browser host unavailable |
| `/users` | Admin-only user-list access and analyst denial | Not run; browser host unavailable |
| `/settings` | No page-specific API request identified in route declaration | Not run; browser host unavailable |
| `*` | No API request | Not run; browser host unavailable |

Authentication restoration and persisted actual identity are covered by `/api/auth/me` tests; a real browser refresh/navigation check remains unverified.

## Current-state local API measurements

Measurements below came from six sequential requests per endpoint (first request reported as cold; five subsequent requests summarized as warm median and p95). These are API handler times through Supertest against the local PostgreSQL test cluster, not production latency and not browser page-render times. Payload size is serialized response JSON. Dataset volume is given above. Timing values vary between runs; the table records the final full-suite run.

| Endpoint | Status | Cold ms | Warm median ms | Warm p95 ms | Payload bytes |
|---|---:|---:|---:|---:|---:|
| Login | 200 | 11.78 | 12.09 | 17.01 | 587 |
| `/api/auth/me` | 200 | 13.21 | 12.82 | 17.21 | 181 |
| `/api/overview` | 200 | 12.14 | 16.07 | 19.33 | 4,379 |
| `/api/alerts` (25 rows) | 200 | 17.06 | 17.07 | 17.83 | 23,956 |
| `/api/transactions` (25 rows) | 200 | 104.15 | 96.40 | 104.67 | 12,887 |
| `/api/cases` (25 rows) | 200 | 17.14 | 18.16 | 23.48 | 20,880 |
| `/api/customers` (25 rows) | 200 | 17.21 | 12.93 | 18.14 | 4,056 |
| `/api/accounts` (25 rows) | 200 | 15.35 | 9.99 | 11.11 | 4,101 |
| `/api/rules` (25 rows) | 200 | 9.80 | 9.87 | 17.02 | 3,292 |
| `/api/validation` (25 rows) | 200 | 16.08 | 10.73 | 12.73 | 1,572 |
| `/api/generation-runs` (25 rows) | 200 | 20.35 | 10.70 | 11.33 | 1,532 |
| `/api/audit` (25 rows) | 200 | 13.60 | 10.52 | 13.05 | 5,392 |

No reliable browser page-load or before/after runtime baseline was available. Transaction listing is the slowest measured API here; investigate query plans and representative production infrastructure separately before changing indexes or claiming a production bottleneck.

## Reproduction

Start the isolated local PostgreSQL test cluster and populate the dedicated `risklens_perf_test` database using the existing local test setup. Then run from `backend`:

```powershell
$env:DATABASE_URL='postgresql://postgres@127.0.0.1:55432/risklens_perf_test?schema=public'
$env:DIRECT_URL=$env:DATABASE_URL
$env:RUN_POSTGRES_INTEGRATION_TESTS='true'
npm.cmd test
```

The integration test refuses any URL other than the dedicated loopback database on port 55432. Do not substitute production credentials.
