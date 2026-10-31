# Auth backend (customer console session auth)

Status: **complete** — `go build ./...`, `go vet ./...`, `go test ./...` all pass.
No commit was made (worktree already contains unrelated in-flight changes).

## Files

New:
- `internal/authstore/store.go` — thin pgx adapter over the `003_auth.sql` SECURITY DEFINER functions; tenant registration transaction.
- `internal/authstore/store_test.go` — policy-body contract test + DB-gated integration test.
- `internal/auth/permissions.go` — server-side permission matrix (mirror of `web/console/src/lib/roles.ts`).
- `internal/auth/permissions_test.go` — every matrix cell (5 roles × 9 permissions = 45) plus unknown role/permission denial.
- `cmd/controlplane/auth_server.go` — `/auth/*` HTTP handler.
- `cmd/controlplane/auth_server_test.go` — handler tests with an in-memory fake store.
- `build/reports/auth-backend.md` — this report.

Edited:
- `internal/config/config.go` — six new settings, `durationEnv` helper, `Config.Validate()`.
- `cmd/controlplane/main.go` — calls `cfg.Validate()` at startup; mounts `/auth/` (real store when a pool exists, 503 handler otherwise). `/grant`, demo routes and the static file server are untouched.

## Function signatures

`internal/authstore`:
```go
type Member struct { MemberID, TenantID, Role string }
type Session struct { MemberID, TenantID, Email, Role string }
func New(pool *pgxpool.Pool) *Store
func (s *Store) RequestCode(ctx context.Context, email string, codeHash []byte, expires time.Time) (bool, error)
func (s *Store) VerifyCode(ctx context.Context, email string, codeHash []byte) (Member, bool, error)
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, memberID string, expires time.Time) error
func (s *Store) GetSession(ctx context.Context, tokenHash []byte, idle time.Duration) (Session, bool, error)
func (s *Store) EndSession(ctx context.Context, tokenHash []byte) error
func (s *Store) CreateTenantWithAdmin(ctx context.Context, tenantName, email, role string) (string, error)
```

SQL mapping:
- `SELECT auth_request_login($1,$2,$3)`
- `SELECT member_id, tenant_id, role FROM auth_verify_login($1,$2)`
- `SELECT auth_create_session($1,$2,$3)`
- `SELECT member_id, tenant_id, email, role FROM auth_get_session($1, make_interval(secs => $2))`
- `SELECT auth_end_session($1)`

`CreateTenantWithAdmin` runs one transaction: `SELECT create_tenant(gen_random_uuid(), $1)` → `SELECT set_config('app.tenant_id', $1, true)` → insert `members` (`status='active'`, lowercased/trimmed email) → insert `policies` (`gen_random_uuid()`, version 1, status `published`, body exactly the spec text). No direct reads of `sessions`/`login_codes`; no hashing in Go beyond the caller-supplied sha256 digests.

`internal/auth`:
```go
type Permission string
const (PermissionAgentsRead … PermissionMembersManage)
func Can(role, permission string) bool
```

`cmd/controlplane`:
```go
type authStore interface { … } // the six store methods above
type authPrincipal struct { TenantID, MemberID, Email, Role string } // json tenant_id/member_id/email/role
func newAuthHandler(store authStore, cfg config.Config, logger *slog.Logger) http.Handler
func newAuthLogger() *slog.Logger
func authUnavailableHandler() http.Handler
```

## Endpoints / contract

| Method + path | Behaviour |
| --- | --- |
| `POST /auth/request` `{email}` | Always `202 {"status":"ok"}` for a parseable body. Trim+lower email; 6 digits via `crypto/rand`; stores `sha256(code)` with 10 min expiry. `response` adds `dev_code` only when `DevMode`; `log` logs the code only when `AuthCodeLogPlaintext`; `none` no-op. Store errors/throttle/unknown email are swallowed (202). |
| `POST /auth/verify` `{email,code}` | `200 Principal` + `Set-Cookie: lanyard_session`; token is 32 random bytes base64url, stored as `sha256(token)` with `now+SessionTTL`. Wrong/expired/malformed code → `401 {"error":"invalid or expired code"}`. |
| `GET /auth/me` | `200 Principal` from `auth_get_session(token_hash, SessionIdle)`; else `401 {"error":"not signed in"}`. |
| `POST /auth/logout` | Ends the session (errors logged), clears the cookie (`Max-Age=0`), `204`. |
| `POST /auth/register` `{email,tenant_name}` | `403 {"error":"signup disabled"}` unless `AllowSignup`. Email must be ≤254 chars with exactly one `@`; tenant name 1–100 runes after trim (400 otherwise). Creates tenant+admin member+published policy, then issues a login code exactly like `/auth/request`. Always `202 {"status":"ok"}`; unique-violation is logged at info, other errors at error. |

Cross-cutting:
- `Cache-Control: no-store` on every `/auth/*` response (including 405 and the no-database 503).
- Origin check on `POST/PATCH/DELETE`: if `Origin` is present it must equal `scheme://host` of `PUBLIC_BASE_URL`, else `403 {"error":"origin not allowed"}`. Safe methods are not checked. Fail-closed when `PUBLIC_BASE_URL` is unparseable.
- Method mismatch → `405` (Go 1.22+ method patterns).
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` iff `PUBLIC_BASE_URL` scheme is https, `MaxAge=int(SessionTTL.Seconds())`.
- No-database mount: any `/auth/*` → `503 {"error":"authentication requires a database"}`.

## Config

| Field | Env | Default |
| --- | --- | --- |
| `PublicBaseURL` | `PUBLIC_BASE_URL` | `http://localhost:8080` |
| `AuthCodeDelivery` | `AUTH_CODE_DELIVERY` | `none` (`none|log|response`) |
| `AuthCodeLogPlaintext` | `AUTH_CODE_LOG_PLAINTEXT` | `false` (`=="true"`) |
| `AllowSignup` | `ALLOW_SIGNUP` | `false` (`=="true"`) |
| `SessionTTL` | `SESSION_TTL` | `12h` |
| `SessionIdle` | `SESSION_IDLE` | `2h` |

Fail-fast: new `Config.Validate()` (called from `main` before `ValidateProduction`) returns an error for an invalid delivery mode, for `AUTH_CODE_DELIVERY=response` when `!DevMode`, for a non-absolute `PUBLIC_BASE_URL`, and for non-positive session durations. Invalid `SESSION_TTL`/`SESSION_IDLE` strings panic in `Load` via `durationEnv`, matching the existing panic-on-bad-config style (empty still means unset/default).

## Idempotency / retry notes

- `/auth/request` and `/auth/register` are intentionally non-idempotent but safe to retry from the client: they always 202, and the SQL layer allows one code per email per 30 s (a retry is throttled, not an error).
- `/auth/verify` consumes the code inside `auth_verify_login` (`DELETE … RETURNING` semantics under `FOR UPDATE`), so a retry with the same code is rejected — no duplicate sessions.
- `/auth/logout` is idempotent (unknown token is a no-op, cookie always cleared).
- Registration is atomic: tenant, member and policy are committed together, so a unique-email conflict leaves no partial tenant.

## Verification

```
$ go build ./...
(no output)

$ go vet ./...
(no output)

$ go test ./...
ok  	github.com/example/lanyard/cmd/controlplane	0.169s
ok  	github.com/example/lanyard/cmd/proxy	1.450s
ok  	github.com/example/lanyard/internal/auth	0.595s
ok  	github.com/example/lanyard/internal/authstore	0.131s
ok  	github.com/example/lanyard/internal/config	0.475s
… (all other packages ok / no test files)
```

Focused run:
```
--- PASS: TestDefaultPolicyBodyMatchesSpec
--- SKIP: TestAuthStoreIntegration (TEST_DATABASE_URL not set)
--- PASS: TestCanMatchesEveryMatrixCell
--- PASS: TestCanDeniesUnknownRoleAndPermission
--- PASS: TestAuthRequestUnknownEmailStillAccepted
--- PASS: TestAuthRequestNormalizesEmailAndStoresHash
--- PASS: TestAuthVerifyHappyPathSetsCookieAndPrincipal
--- PASS: TestAuthVerifyWrongCodeIsUnauthorized
--- PASS: TestAuthMeAndLogout
--- PASS: TestAuthOriginCheck
--- PASS: TestAuthSignupDisabled
--- PASS: TestAuthRegisterCreatesTenantAndIssuesCode
--- PASS: TestAuthRegisterConflictStillAccepted
--- PASS: TestAuthRegisterValidation
--- PASS: TestAuthCookieSecureFollowsBaseURL
--- PASS: TestAuthMethodMismatchIs405
--- PASS: TestAuthUnavailableHandler
```

## Not verified / risks

- **No database was available** (`TEST_DATABASE_URL` and `DATABASE_URL` unset), so `TestAuthStoreIntegration` skipped. Unverified against a live schema: the exact SQL parameter inference for `auth_get_session($1, make_interval(secs => $2))`, `set_config` + RLS on the `members`/`policies` inserts inside the registration transaction, and `create_tenant(gen_random_uuid(), …)` returning a UUID that scans into `string`. These follow the same patterns already used by `internal/db.WithTenant` and the 002/003 functions, but they have not been executed.
- `CreateTenantWithAdmin` assumes the migration role owns `tenants` so the SECURITY DEFINER `create_tenant` insert bypasses the SELECT-only `tenant_self` policy. True for the repo's migration flow; would need re-checking if the app ever connects as the owner.
- `/auth/verify` returns `500 {"error":"internal error"}` (logged) for store/DB failures and `401` only for a bad code; the spec's "on failure 401" is read as covering invalid/expired codes.
- Malformed JSON bodies return `400` from the shared `decodeJSON` helper (which also rejects unknown fields); `/auth/request` still returns 202 for any parseable `{email}`.
- `main.go` calls `cfg.Validate()` in addition to route wiring so the `response`-outside-dev rejection actually fails startup.
- The no-database 503 mount is only exercised in unit tests; `newDBPool` still exits at startup when no database is configured, so production always mounts the real handler.

## Suggested follow-ups for Sentinel / Probe

- Sentinel: confirm origin comparison semantics (`Origin: null`, mixed case, `PUBLIC_BASE_URL` with a path), cookie `Secure` behind TLS termination (the handler only reads `PUBLIC_BASE_URL`, not `r.TLS`), and that no code/token is ever logged unless `AUTH_CODE_LOG_PLAINTEXT=true`.
- Probe: end-to-end registration → verify → `/auth/me` → logout against a migrated DB as `lanyard_app`; confirm the published policy makes `/grant` possible for a new tenant; confirm verify after 5 wrong attempts is locked.

## Review fixes

Small, surgical changes only; no other packages touched.

| # | Finding | Change |
|---|---|---|
| 1 | CRITICAL — `TestAuthRegisterCreatesTenantAndIssuesCode` registered one email but verified another | `cmd/controlplane/auth_server_test.go`: both calls now use the **registered** email (the register literal, which normalizes to the same member). The old "other" email is now used deliberately as the negative case: `POST /auth/verify` with a different email and the same code must return `401` and set no cookie. Added an assertion that the returned principal's email is the registered email. (Note: the two original literals differed only in case, so the old test passed by normalization and never proved the intent.) |
| 2 | IMPORTANT — conflict path logged the raw email (PII) | `cmd/controlplane/auth_server.go`: the unique-violation branch now logs `"registration skipped: already registered"` plus `tenant_name_len` only; no email, no tenant name. `202 {"status":"ok"}` behaviour unchanged, and the code is still issued (the store decides whether it exists). |
| 3a | HARDENING — pgx inference for `auth_create_session` | `internal/authstore/store.go`: `SELECT auth_create_session($1, $2::uuid, $3)` — member id cast explicitly. |
| 3b | HARDENING — non-integer `make_interval` argument | `internal/authstore/store.go`: `int64(idle.Seconds())` instead of a float. |
| 4 | New tests for malformed JSON | `TestAuthMalformedJSONIsBadRequest` covers `/auth/verify` and `/auth/register`: truncated bodies return `400 {"error":"invalid JSON"}` and leave the fake store untouched (no codes, sessions, or tenants created). `/auth/register` runs with `AllowSignup` enabled so the body is actually parsed. |

Verification: `go build ./... && go vet ./... && go test ./...` — all pass. `gofmt -l` clean on the three changed files.

Focused test tail:

```
--- PASS: TestAuthRequestUnknownEmailStillAccepted (0.00s)
--- PASS: TestAuthRequestNormalizesEmailAndStoresHash (0.00s)
--- PASS: TestAuthVerifyHappyPathSetsCookieAndPrincipal (0.00s)
--- PASS: TestAuthVerifyWrongCodeIsUnauthorized (0.00s)
--- PASS: TestAuthMeAndLogout (0.00s)
--- PASS: TestAuthOriginCheck (0.00s)
--- PASS: TestAuthSignupDisabled (0.00s)
--- PASS: TestAuthRegisterCreatesTenantAndIssuesCode (0.00s)
--- PASS: TestAuthMalformedJSONIsBadRequest (0.00s)
--- PASS: TestAuthRegisterConflictStillAccepted (0.00s)
--- PASS: TestAuthRegisterValidation (0.00s)
--- PASS: TestAuthCookieSecureFollowsBaseURL (0.00s)
--- PASS: TestAuthMethodMismatchIs405 (0.00s)
--- PASS: TestAuthUnavailableHandler (0.00s)
PASS
ok  	github.com/example/lanyard/cmd/controlplane	0.333s
```

Full suite: all packages `ok` (or `no test files`); `internal/authstore` still passes with `TestAuthStoreIntegration` skipped (no `TEST_DATABASE_URL`), so the `::uuid` cast and integer `secs` remain unverified against a live database.
