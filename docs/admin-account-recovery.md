# Administrator account recovery

## Findings and root cause

PostgreSQL login (`POST /api/auth/login`) requires an exact email match, `ACTIVE` status, a bcrypt password hash, and a matching password. Missing users, inactive users, malformed hashes, and wrong passwords all receive the same `401 Invalid credentials` response. Login is rate-limited to 10 attempts per 15 minutes per client IP. The generated synthetic users are `PENDING` analysts and are not administrator accounts.

A read-only count query against the Supabase project configured by the backend found one `ADMIN` with `ACTIVE` status. The live Render backend and Supabase use that project, as confirmed by the operator. The exact email and any credential material were not retrieved. The previous bootstrap route intentionally returns `409` whenever an active administrator exists, so it cannot recover this account. The immediate cause of login failure is forgotten account credentials; the service does not distinguish the wrong email from the wrong password in its response.

Inspection confirmed:

- `passwordHash` is verified with `bcryptjs`; production provisioning uses cost 12.
- `authVersion` is included in JWT claims. Token validation checks it against the persisted user record. Recovery increments it, invalidating every existing session.
- `audit_events` has a unique UUID primary key, allows `actorId = NULL`, and is append-only. Inserts are allowed.
- The schema therefore supports a one-time atomic recovery marker without a migration. No migration was added.
- `/api/users/:id/provision` already updates a user's password and `authVersion`, then writes an audit event transactionally, but requires an authenticated administrator.
- The existing bootstrap implementation and route were left unchanged.

## Recovery endpoint implemented

`POST /api/admin/recover` is available only in the PostgreSQL backend. It:

1. Requires `ADMIN_RECOVERY_SECRET` (exactly 64 hexadecimal characters representing 32 random bytes) and a future UTC `ADMIN_RECOVERY_EXPIRES_AT`. The endpoint returns `503` if either setting is absent, invalid, or expired.
2. Compares the submitted recovery secret with the configured value using the existing constant-time comparison helper.
3. Requires the exact email and a new password of at least 12 characters and at most 72 UTF-8 bytes.
4. Only updates an existing `ADMIN` whose status is already `ACTIVE`. It cannot create an account, change role or status, or recover any other user.
5. Hashes the new password with bcrypt cost 12 and increments `authVersion`.
6. Inserts an audit record in the same transaction as the password update. Its primary key is a deterministic UUID derived from the configured recovery secret; the database's unique constraint makes concurrent or later uses of that authorization conflict atomically. The audit details contain the action and authorization type, never the secret or password. The transaction rolls back the marker if the target is missing, not an active administrator, or the update fails.
7. Returns the same `401 Recovery request rejected` response for an incorrect secret, unknown email, non-admin/inactive user, or replay. Successful recovery returns only the normal safe user fields.
8. Allows at most five attempts per 15 minutes per client IP through an endpoint-specific in-process limiter. One-time consumption remains database-atomic across backend processes. The limiter itself is process-local; if the Render service is scaled to multiple instances, shared throttling should be added before enabling the endpoint there.

The SQLite backend and all existing auth routes are unchanged. The endpoint does not reveal the account status to callers who submit an invalid authorization. Use it only with a separately protected secret and only for the verified administrator.

## Find the exact administrator email

Because the login identity is forgotten, an authorized operator can run this read-only query in the SQL Editor for the live project. It returns only the active admin's identity fields, not a password hash or token:

```sql
SELECT email, name, role, status
FROM public.users
WHERE role = 'ADMIN' AND status = 'ACTIVE';
```

The investigation verified one result but did not display or copy the email. Do not use SQL `UPDATE` to change the account.

## Recovery configuration

No recovery secret is committed to the repository. Configure these variables only in the Render service's protected environment settings, during an explicitly approved recovery window:

- `ADMIN_RECOVERY_SECRET`: a newly generated 256-bit random secret, represented as exactly 64 hexadecimal characters. Generate locally with `openssl rand -hex 32` or an equivalent cryptographically secure generator. Store it temporarily in an approved password manager; do not put it in source control, `.env`, shell command arguments, logs, or chat.
- `ADMIN_RECOVERY_EXPIRES_AT`: a short-lived UTC timestamp in ISO format, for example `2026-11-14T12:30:00.000Z`. Set it only a short time ahead and before the approved recovery attempt.

The production `JWT_SECRET` remains unchanged. Updating Render environment settings restarts the service; do not make that production change until the code has been reviewed, deployed, and the operator has approved the recovery window. If the endpoint returns `503`, stop: do not repeatedly alter configuration or issue repeated requests.

## PowerShell request

Use this only after the production sequence below is explicitly approved and the endpoint code has been deployed. Confirm `$apiBase` is the intended HTTPS service and enter the exact email from the read-only query. The command prompts for the recovery secret and new password; it does not place either in command history or print the request body.

```powershell
$apiBase = 'https://risklens-ai.onrender.com'
if (([uri]$apiBase).Scheme -ne 'https') { throw 'Recovery requires HTTPS.' }
$email = Read-Host 'Exact active administrator email from the read-only query'
$recoverySecure = Read-Host 'ADMIN_RECOVERY_SECRET' -AsSecureString
$passwordSecure = Read-Host 'New administrator password (12+ characters)' -AsSecureString
$recoveryPtr = [IntPtr]::Zero
$passwordPtr = [IntPtr]::Zero
$recoverySecret = $null
$password = $null
$body = $null
try {
    $recoveryPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($recoverySecure)
    $passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
    $recoverySecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($recoveryPtr)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr)
    if ([Text.Encoding]::UTF8.GetByteCount($password) -gt 72) {
        throw 'Password exceeds the endpoint limit of 72 UTF-8 bytes.'
    }
    $body = @{ recoverySecret = $recoverySecret; email = $email; password = $password } | ConvertTo-Json -Compress
    $result = Invoke-RestMethod -Method Post -Uri "$apiBase/api/admin/recover" `
        -ContentType 'application/json' -Body $body -TimeoutSec 30
    $result.user | Select-Object email, name, role, status | Format-List
} catch {
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
        Write-Error "Recovery failed with HTTP $statusCode. Stop and diagnose; do not retry repeatedly."
    } else {
        Write-Error 'Recovery failed before a successful response. Stop and diagnose without sharing request values.'
    }
} finally {
    if ($recoveryPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($recoveryPtr) }
    if ($passwordPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr) }
    $recoverySecret = $null; $password = $null; $body = $null; $result = $null
    if ($recoverySecure) { $recoverySecure.Dispose() }
    if ($passwordSecure) { $passwordSecure.Dispose() }
    Remove-Variable recoverySecure, passwordSecure, recoveryPtr, passwordPtr -ErrorAction SilentlyContinue
}
```

Expected results: `200` means the existing active administrator password was changed; `401` means the authorization was rejected without indicating whether the email exists; `429` means the endpoint rate limit was reached; `503` means recovery is not enabled or has expired. A request is consumed only when the transaction succeeds. Do not send the same request again after a `200`.

## Production execution sequence

No production request or configuration change has been performed. Once the code has been reviewed and production action is explicitly approved:

1. Deploy the reviewed application change through the normal approved release process. Do not apply a database migration; none is required.
2. Verify the endpoint is present, then configure a fresh recovery secret and a brief UTC expiry in Render's protected settings.
3. Run the read-only SQL above and confirm there is exactly one active `ADMIN`. Record the exact email privately.
4. Make one PowerShell request. Confirm the response is `200` and shows the expected account identity. Do not repeat on `401`, `429`, `503`, or a network error; diagnose first.
5. Log in once with the new password and confirm the actual identity. Existing access tokens should now fail because `authVersion` changed.
6. Immediately remove `ADMIN_RECOVERY_SECRET` and `ADMIN_RECOVERY_EXPIRES_AT` from Render's protected settings, allowing the service restart to complete. Confirm the route returns `503` without these settings. Revoke/delete the temporary secret from its password manager entry after verification.

## Rollback and secret rotation

- Before successful recovery, removing both recovery variables disables the endpoint. No user row or audit row is changed by rejected requests.
- On successful recovery, the prior password is irrecoverable and all previous JWTs are invalid. If the new password was mistyped or otherwise unusable, do not try to restore or inspect the old hash. After investigation and renewed explicit authorization, configure a different fresh secret and short expiry for a new one-time recovery.
- The audit event is append-only and must remain as evidence. Do not delete it or revert the account by direct SQL.
- Rotate/remove the temporary recovery secret and expiry immediately after the approved attempt. Do not change `JWT_SECRET` as part of recovery.

## Local test evidence

The recovery test uses random local test accounts and 256-bit random authorization secrets. It covers valid recovery, wrong secret, unknown email, non-admin account, replay, concurrent requests, post-recovery login, old-token invalidation, audit persistence, missing/expired configuration, rate limiting, and the unchanged bootstrap behavior. It is guarded to use only `127.0.0.1:55432/risklens_perf_test`.

On this main-based review branch:

- Backend build passed.
- Backend suite: **22 passed, 0 failed, 2 skipped**. The existing Prisma PostgreSQL integration test and the recovery PostgreSQL integration test were skipped because the guarded local PostgreSQL server was unavailable.
- Tests used a temporary copy of the local SQLite seed database outside the worktree. The original database SHA-256 remained unchanged.

When the disposable PostgreSQL service is available, run this from `backend` to execute the guarded PostgreSQL integration tests:

```powershell
$env:DATABASE_URL = 'postgresql://postgres@127.0.0.1:55432/risklens_perf_test?schema=public'
$env:RUN_POSTGRES_INTEGRATION_TESTS = 'true'
npm.cmd test
```