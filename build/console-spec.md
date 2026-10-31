# Console + ops delivery spec (v1)

## Goal
Ship the customer console (`web/console`) and staff ops console (`web/ops`) with a real Go backend, then deploy both to the production host.

## Runtime topology
- **Customer console**: static export (`out/`) copied to `/app/web`; served by the control plane on `:8080` at `/`. Same origin as `/auth/*` and `/admin/*` so the `SameSite=Strict` cookie works.
- **Ops console**: static export copied to `/app/web-ops`; served by the control plane on a **second listener** `OPS_ADDR` (default disabled; production `127.0.0.1:8082`), which also serves `/ops/*`. Never exposed by the security group; reachable over SSM port forwarding.
- Old `web/app.js`, `web/index.html`, `web/styles.css` are already deleted; do not restore them.

## Customer auth (frozen client contract)
| Call | Body | Response |
| --- | --- | --- |
| `POST /auth/request` | `{email}` | `202 {"status":"ok"}` always (no enumeration) |
| `POST /auth/verify` | `{email,code}` | `200 Principal` + `Set-Cookie` |
| `GET /auth/me` | – | `200 Principal` / `401` |
| `POST /auth/logout` | `{}` | `204` + cleared cookie |
| `POST /auth/register` | `{email,tenant_name}` | `202 {"status":"ok"}` (gated by `ALLOW_SIGNUP`) |

`Principal = {tenant_id, member_id, email, role}` with `role ∈ admin|security|agent_owner|approver|auditor`.

- Storage: reuse `migrations/003_auth.sql` functions (`auth_request_login`, `auth_verify_login`, `auth_create_session`, `auth_get_session`, `auth_end_session`). Never store raw codes or tokens: `sha256(code)` and `sha256(token)` as `bytea`.
- Token: 32 random bytes, base64url. Cookie `lanyard_session`: HttpOnly, SameSite=Strict, Path=/, `Secure` when `PUBLIC_BASE_URL` is https, Max-Age 8h. Idle timeout 2h, absolute 12h.
- Code: 6 digits from `crypto/rand`. Delivery via `AUTH_CODE_DELIVERY`:
  - `response` — dev only (`DevMode`), returns `dev_code` in the 202 body.
  - `log` — logs the code only when `AUTH_CODE_LOG_PLAINTEXT=true`. **Production alpha uses this; flagged as a risk.**
  - `none` — default; nothing delivered.
- Origin/CSRF: for `POST/PATCH/DELETE`, if an `Origin` header is present it must equal the origin of `PUBLIC_BASE_URL`, else `403`.
- Registration creates: tenant (`create_tenant`), first member with role `admin`, and a **published Cedar policy** for the tenant (otherwise `/grant` denies everything). Then it issues a login code like `/auth/request`.

## Admin API (session-authenticated, tenant from session — replaces dev-only in-memory stores in production)
| Call | Purpose |
| --- | --- |
| `GET /admin/agents` | list: `[{id(slug), tenant_id, owner_subject, public_key(base64url), status}]` |
| `POST /admin/agents` | `{id(slug), owner_subject, public_key}` → created agent |
| `GET /admin/tenant` | `{id,name,contact_email,status,plan,created_at}` |
| `PATCH /admin/tenant` | `{name?,contact_email?}` |
| `GET /approve` | `ApprovalRequest[]` |
| `POST /approve` | `{id,status,parameters}` → decided request |
| `POST /revoke` | `{agent_id|task_id|chain_id|token_id: value}` → `{"status":"ok"}` |
| `GET /events/replay` | `StoredEvent[]` |

- Server-side permission matrix must mirror `web/console/src/lib/roles.ts` exactly.
- `agents.write` = admin, agent_owner. `approvals.decide` = admin, approver. `revoke` = admin, security. `events.read` = admin, security, agent_owner, auditor.
- Self-approval must be rejected **before** any mutation.
- Revoking an agent also sets `agents.status='suspended'`.
- Agent `public_key`: accept base64url 32 bytes, store **raw bytes** in `agents.public_key`, return base64url.

## Known backend defects to fix in this work
1. `grantstore.GetAgent` scans `bytea` into `string`; pgx v5 binary format makes it fail silently → `/grant` returns 401 for every agent. Fix with `encode(public_key,'base64')` **and** make `token.PublicKeyThumbprintFromBase64` accept std/raw/padded base64.
2. `/approve` currently mutates before validating self-approval.
3. Demo seed (`agent:demo` into UUID column) — leave demo-only code untouched, but production must not depend on it.

## Ops API (`/ops/*`, second listener)
| Call | Purpose |
| --- | --- |
| `GET /ops/auth/login` | `302` to `/login/` (SSO placeholder; code login for alpha) |
| `POST /ops/auth/request` | `{email}` → 202 |
| `POST /ops/auth/verify` | `{email,code}` → `{email,role,hardware_key}` + ops cookie |
| `GET /ops/auth/me` / `POST /ops/auth/logout` | session |
| `GET /ops/health` | `{proxy_p99_ms,revocation_lag_s,event_backlog,uptime_30d_pct,updated_at}` |
| `GET /ops/tenants` | `[{id,name,plan,agents,grants,state}]` |
| `GET/POST /ops/actions` | queue; `reason` ≥ 20 chars |
| `POST /ops/actions/{id}/decide` | `{status: approved|denied}` |

- Roles `ops_admin|ops_oncall|ops_support`; support is read-only.
- Two-person rule: decider ≠ requester, decided once, expires after 1h. Enforce in SQL check **and** Go.
- `hardware_key` is `false` for alpha; write actions gated by `OPS_REQUIRE_HARDWARE_KEY` (default false, flagged).
- Cookie `lanyard_ops_session`, same attributes as the customer cookie.
- Bootstrap: if no `ops_members` row exists, create one from `OPS_BOOTSTRAP_EMAIL` (role `ops_admin`) at startup.

## Migration 005 (next number; 004 is taken and must not be edited)
- `tenants`: `contact_email TEXT`, `status TEXT NOT NULL DEFAULT 'active'` CHECK(active|suspended), `settings JSONB NOT NULL DEFAULT '{}'`.
- `approval_requests`: `parameters JSONB NOT NULL DEFAULT '{}'`, `requested_by TEXT`.
- New: `ops_members`, `ops_sessions`, `ops_login_codes`, `ops_actions` (with `CHECK (decided_by IS NULL OR decided_by <> requested_by)`).
- Grants to `lanyard_app`; **no RLS** on `ops_*` (platform-scoped by design). Use `pg_temp.ensure_constraint` for idempotent constraints.

## Frontend changes
- Console: add `/register` page (email + tenant name), replace `settings` ComingSoon with a tenant profile form, add `api.register`, `api.tenant.get/update`, keep loading/empty/error/no-access states, no raw HTML.
- Ops: replace the SSO-only button flow with an email + code form calling `/ops/auth/request|verify`; keep the "Continue with SSO" URL as `/ops/auth/login`.

## Headers (static responses)
`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`.

## Build/deploy
- Dockerfile: node:22-alpine stages build `web/console` and `web/ops` static exports; final distroless copies `out/` → `/app/web`, ops `out/` → `/app/web-ops`. Remove `COPY web /app/web`.
- `.dockerignore`: node_modules, .next, out. `.gitignore`: build/, *.exe, proxy.bin, web/*/node_modules, web/*/.next, web/*/out. Untrack committed `.exe` files.
- Compose: `OPS_ADDR=127.0.0.1:8082`, `OPS_WEB_DIR=./web-ops`, `PUBLIC_BASE_URL`, `AUTH_CODE_DELIVERY=log`, `AUTH_CODE_LOG_PLAINTEXT=true`, `ALLOW_SIGNUP=true`, `OPS_BOOTSTRAP_EMAIL`.
