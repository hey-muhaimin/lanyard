# Internal Ops Console Prototype

Prototype interface for platform staff: platform health, tenants, and incident actions that need two people. It is a
separate app from `web/console`, but the current CDK prototype places both under one CloudFront distribution; it does
not provide a separate staff domain or a production security boundary. The app uses Next.js, Tailwind v4, shadcn/ui,
monochrome styling, and glyph + word statuses.

## First run

```bash
cd web/ops
npm install
npm run ui:add            # pulls the shadcn components into src/components/ui; commit them
cp .env.example .env.local   # NEXT_PUBLIC_OPS_MOCK=1 gives fixture data and a signed-in on-call engineer
npm run typecheck && npm test
npm run dev               # http://localhost:3001
```

In mock mode the app behaves like the rules below: filing a request never runs it, and you cannot decide your own request.
A fixture request from another engineer is pending, so you can try Approve and Deny.

## Backend Status

This UI uses mock fixtures for local development. Do not connect it to production or rely on it for staff operations. The existing Go handler is a placeholder and is intentionally not mounted: it does not establish a trustworthy staff identity. `/ops/*` returns 404 until a separately reviewed authentication and authorization implementation is available.

The following is a proposed API contract only, not a supported backend:

| Call | Purpose |
| --- | --- |
| `GET /ops/auth/login` | Start staff SSO (OIDC) with a hardware-key requirement |
| `GET /ops/auth/me` → `{email, role, hardware_key}` | Session |
| `POST /ops/auth/logout` | |
| `GET /ops/health` → `{proxy_p99_ms, revocation_lag_s, event_backlog, uptime_30d_pct, updated_at}` | Health tiles |
| `GET /ops/tenants` → `[{id, name, plan, agents, grants, state}]` | Tenants |
| `GET /ops/actions`, `POST /ops/actions {type, tenant_id, reason}` | Request queue; `tenant_id` is `"*"` for platform-wide |
| `POST /ops/actions/{id}/decide {status: approved\|denied}` | Second person decides |

Roles: `ops_admin`, `ops_oncall` (request and decide), `ops_support` (read only).

## What the server must enforce (the UI only reflects it)

- The decider is never the requester, and a request is decided once and expires (the mock uses 1 hour).
- Write actions require a hardware-key sign-in, taken from the identity provider's assertion, not from the browser.
- Approving runs the action in the same transaction that records it. Requests, decisions and results go to the audit log.
- "View as customer" requires a consent record from the customer, is read-only and time-limited.
- Reasons are required (the form asks for 20+ characters).
- Serve this app and `/ops/*` only on an internal network or behind an allowlist, never on the public customer listener.

## Build and Deployment

`npm run build:static` writes `out/`. The repository's CDK bucket deployment is a prototype, not an approved production hosting path. Do not publish this UI until staff authentication, authorization, network access, and response security headers have been reviewed. Do not use the former `unsafe-inline` CSP suggestion as production policy.

## Notes

- Health thresholds in `src/app/(ops)/health/page.tsx` are placeholders. Tune them against real traffic.
- Fonts come from `next/font/google` at build time; switch to `next/font/local` for offline builds.
- Not built: tenant detail pages, incident timelines, audit search, dark mode.
