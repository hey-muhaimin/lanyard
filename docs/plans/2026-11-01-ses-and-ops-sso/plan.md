# Implementation Plan — SES login-code delivery + Cognito staff SSO for `/ops`

Date: 2026-11-01
Status: ready for execution
Repo: `V:\lanyard` (Go 1.27, `github.com/example/lanyard`)

Two greenfield features on top of the existing code:

1. **SES email delivery** for customer console login codes (`AUTH_CODE_DELIVERY=email`).
2. **Real staff SSO** for the ops console via Amazon Cognito authorization-code + PKCE,
   which finally satisfies `AGENTS.md`'s condition for mounting `/ops/*`.

Nothing here is implemented yet. Execute the task briefs in order; each brief is
self-contained and lists its own verification commands.

---

## Global Constraints (binding on every task)

- **Toolchain.** Go 1.27. From the repo root: `go build ./...`, `go vet ./...`,
  `go test ./...` must pass before a task is declared done.
- **Never log, return, or echo:** login codes, OAuth authorization codes, ID/access/refresh
  tokens, client secrets, `Authorization` headers, or request bodies. Errors returned to a
  client are generic; the detail goes to `slog` only.
- **Migrations are immutable.** Do not edit `migrations/001`–`005`. This plan adds exactly
  `migrations/006_ops_sso.sql` and `migrations/007_ops_tenants.sql`.
- **Do not use demo mode or demo credentials.** `AUTH_CODE_DELIVERY=response` stays dev-only.
- **Tenant auth is frozen** except for the new `email` delivery branch in
  `issueLoginCode`. Cookie name, origin rule, session store and status codes for
  `/auth/*` do not change.
- **Reuse existing helpers in `cmd/controlplane`** (package `main`): `writeJSON` /
  `decodeJSON` (`api.go`), `originOf` / `schemeOf` / `hashValue` / `newSessionToken`
  (`auth_server.go`). Do not add duplicates.
- **No CORS anywhere.** Browser traffic is same-origin via Amplify rewrites.
- **Cookies.**
  - tenant: `lanyard_session` (unchanged)
  - ops: `lanyard_ops_session` (new)
  - attributes for both: `Path=/`, `HttpOnly`, `SameSite=Strict`,
    `Secure` iff the corresponding public base URL scheme is `https`,
    `MaxAge=int(SessionTTL.Seconds())`.
- **Origin rule for ops writes.** `POST/PUT/PATCH/DELETE` with a non-empty `Origin`
  must equal `scheme://host` of `OPS_PUBLIC_BASE_URL`, else
  `403 {"error":"origin not allowed"}`. `GET` is not origin-checked.
- **Fail closed.** Any failed state check, token check, group check, member check or
  session write yields **no** session cookie.
- **Fixed protocol values.** callback path `/ops/auth/callback/` (trailing slash matches
  the registered Cognito callback); scope `openid email profile`; PKCE `S256`; `state`
  and `code_verifier` are 32 random bytes base64url (43 chars); state TTL 10 minutes,
  single use.

## Environment variables

| Variable | New/Changed | Default | Meaning |
|---|---|---|---|
| `AUTH_CODE_DELIVERY` | changed (adds `email`) | `none` | `none\|log\|response\|email` |
| `AUTH_EMAIL_FROM` | **new** | `no-reply@linkedqueue.cloud` | SES `FromEmailAddress` |
| `AWS_REGION` | existing | — | SES + Secrets Manager region; required when delivery is `email` |
| `OPS_SSO_ENABLED` | **new** | `false` | mounts `/ops/*` behind Cognito SSO |
| `COGNITO_SECRET_ARN` | **new** | — | ARN of `production/lanyard/cognito`; required when enabled |
| `OPS_PUBLIC_BASE_URL` | **new** | — | e.g. `https://ops.linkedqueue.cloud`; origin + redirect base |
| `PUBLIC_BASE_URL` | existing, now set in Compose | — | console origin used by the tenant origin check |

No new env var duplicates the `staffGroup` value: it comes from the Cognito secret.

## Decisions already made (do not re-open)

1. **OAuth state is in-memory**, guarded by a mutex, single-use, 10-minute TTL. The
   deployment is one `controlplane` container (`deploy/production.compose.yml`); a restart
   only invalidates in-flight sign-ins. Adding a table would need new SQL for no benefit.
2. **Ops members are linked by `cognito_sub`.** New members are created with the
   least-privileged role `ops_support`. Existing roles are never overwritten; promotion is
   a manual DB update. A suspended member is never reactivated by signing in.
3. **`hardware_key` comes from the ID token `amr` claim** (`"hwk"` present → true, absent →
   false). It is stored per ops session so `/ops/auth/me` can report it. It is a
   best-effort signal; the real control is WebAuthn/MFA enforcement on the Cognito pool.
4. **`/ops/tenants` needs a SECURITY DEFINER function.** `tenants`/`agents`/`grants` are
   RLS-scoped to `current_tenant()`, and ops staff are not a tenant, so a plain query
   returns zero rows. `ops_list_tenants()` (migration 007) is the fix.
5. **`ops_create_session` and `ops_get_session` are replaced** (dropped and recreated) in
   migration 006 to carry `hardware_key`; the 3-argument form is dropped so no caller can
   create a session without stating it.
6. **The ops UI needs no code change.** `web/ops/src/app/login/page.tsx` already links to
   `/ops/auth/login` when `NEXT_PUBLIC_OPS_MOCK !== "1"`, and `web/ops/src/lib/api.ts`
   already calls `/ops/auth/me`, `/ops/auth/logout`, `/ops/health`, `/ops/tenants`,
   `/ops/actions`. The backend must therefore serve `/ops/auth/me` (today it does not).
7. **Write actions require a hardware key and a non-read-only role.** `ops_support` is
   read-only (the default for SSO-provisioned members); `ops_admin` and `ops_oncall` may
   queue and decide, and only when the ID token's `amr` contains `hwk`.
8. **`PUBLIC_BASE_URL` is added to Compose.** It is currently unset in
   `deploy/production.compose.yml`, so every mutating console request would be rejected by
   the origin check. Setting it is part of making email-code login actually usable.

## Tasks

| # | Task | Files | Depends on |
|---|---|---|---|
| 01 | Config: `AUTH_CODE_DELIVERY=email` | `internal/config/config.go`, `internal/config/config_test.go` | — |
| 02 | `internal/mailer` SES sender | `internal/mailer/{mailer,ses,ses_test}.go`, `go.mod`, `go.sum` | — |
| 03 | Wire email delivery into the tenant auth handler | `cmd/controlplane/auth_server.go`, `cmd/controlplane/auth_server_test.go`, `cmd/controlplane/main.go`, `cmd/controlplane/main_test.go` | 01, 02 |
| 04 | IAM: `ses:SendEmail` on role + boundary | `infra/iam/lanyard-ec2-ssm-runtime-boundary.json`, `infra/iam/lanyard-ses-send-policy.json`, `infra/iam/README.md` | — |
| 05 | Config: ops SSO settings | `internal/config/config.go`, `internal/config/config_test.go` | — |
| 06 | Migration 006: Cognito subject + `hardware_key` sessions | `migrations/006_ops_sso.sql` | — |
| 07 | `internal/staffsso`: secret parsing + authorize URL | `internal/staffsso/{config,config_test}.go` | — |
| 08 | `internal/staffsso`: code exchange + ID-token/JWKS verification | `internal/staffsso/{token,verify,token_test,verify_test}.go`, `go.mod`, `go.sum` | 07 |
| 09 | `internal/opsstore`: member/session adapter | `internal/opsstore/{store,store_test}.go` | 06 |
| 10 | Migration 007: `ops_list_tenants()` | `migrations/007_ops_tenants.sql` | — |
| 11 | Ops login: PKCE + state store + `/ops/auth/login` | `cmd/controlplane/ops_auth.go`, `cmd/controlplane/ops_auth_test.go` | 07 |
| 12 | Ops callback + `/ops/auth/me` + `/ops/auth/logout` | `cmd/controlplane/ops_auth.go`, `cmd/controlplane/ops_auth_test.go` | 08, 09, 11 |
| 13 | Ops session middleware + real `/ops` API | `cmd/controlplane/ops_handler.go`, `cmd/controlplane/ops_handler_test.go`, `internal/opsstore/store.go` | 09, 10, 11 |
| 14 | Startup wiring: load Cognito secret, mount `/ops/` | `cmd/controlplane/ops_wire.go`, `cmd/controlplane/main.go`, `cmd/controlplane/main_test.go` | 05, 12, 13 |
| 15 | Compose, deployment docs, Amplify rewrite runbook | `deploy/production.compose.yml`, `deploy/production.md`, `README.md`, `AGENTS.md`, `web/ops/README.md` | 03, 04, 14 |

### Dependency chain

```
01, 02 ──> 03 ──────────────┐
05 ─────────────────────────┤
06 ──> 09 ──> 12 ───────────┼─> 14 ──> 15
07 ──> 08 ──┘               │
07 ──> 11 ──> 13 <── 10     │
04 ─────────────────────────┘
```

Parallel waves (file-disjoint):

- **Wave 1:** 01, 02, 04, 05, 06, 07, 10
- **Wave 2:** 03, 08, 09, 11
- **Wave 3:** 12, 13
- **Wave 4:** 14
- **Wave 5:** 15

> 11 and 12 both edit `cmd/controlplane/ops_auth.go`; 12 must run after 11.
> 03 and 14 both edit the `newControlPlaneHandler` signature; 03 first (adds `mail`),
> 14 second (adds `ops`).

## Test strategy summary

| Layer | How it is tested |
|---|---|
| `internal/config` | table tests on `Validate()` / `Load()` (no env leaks; `t.Setenv`) |
| `internal/mailer` | fake `sesAPI` capturing `SendEmailInput`; asserts exact subject/body/charset and that errors never contain the code |
| `cmd/controlplane` tenant auth | existing `fakeAuthStore` + a new `fakeSender`; asserts 202 with no `dev_code`, 503 on send failure, and that the code never appears in logs |
| `internal/staffsso` | `httptest` JWKS + token endpoints with a generated RSA key; signed tokens via `golang-jwt/jwt/v5`; covers iss/aud/exp/alg/token_use/kid-rotation/cache |
| `internal/opsstore` | unit tests for input validation; integration test gated on `TEST_DATABASE_URL` (CI provides it) |
| `cmd/controlplane` ops auth | `fakeOpsStore` + `httptest` token/JWKS server; asserts 302 shape, single-use state, cookie attributes, and every rejection path sets no cookie |
| migrations | CI applies them on a fresh Postgres 16; each migration task also gives a `psql` check |
| IAM / Compose / docs | JSON + YAML parse checks and `aws iam` read-back commands (no live send in CI) |

## Out of scope (deliberately)

- `/ops/health` still returns the prototype's static numbers.
- Console (`web/console`) Amplify API rewrite rules remain the pre-existing release
  blocker; only the ops rewrite rule is documented here.
- Revoking Cognito tokens at logout (we delete the local session only).
- Role mapping beyond "member of `staff` ⇒ authenticated"; no per-group role sync.
