# Task 15 — Compose, deployment docs, and the ops hosting runbook

**Where this fits:** the last task. Makes the new features deployable: the Compose template
gains the required environment, and the deployment docs stop claiming that email delivery and
`/ops/*` are unimplemented.

**Depends on:** 03 (`AUTH_CODE_DELIVERY=email`), 04 (`infra/iam/README.md`), 14 (`/ops/`
mounting).
**Blocks:** nothing.

## Files

- `deploy/production.compose.yml` (edit)
- `deploy/production.md` (edit)
- `README.md` (edit — two lines)
- `AGENTS.md` (edit — one rule)
- `web/ops/README.md` (edit — "Backend Status" section)

## 1. `deploy/production.compose.yml`

In the **controlplane** service's `environment:` block only (leave the proxy block alone),
insert after `TENANT_ID` and before `AWS_REGION`:

```yaml
      PUBLIC_BASE_URL: ${PUBLIC_BASE_URL:?set PUBLIC_BASE_URL to the customer console origin}
      AUTH_CODE_DELIVERY: ${AUTH_CODE_DELIVERY:-email}
      AUTH_EMAIL_FROM: ${AUTH_EMAIL_FROM:-no-reply@linkedqueue.cloud}
```

and append after `TOKEN_AUDIENCE`:

```yaml
      OPS_SSO_ENABLED: ${OPS_SSO_ENABLED:-false}
      COGNITO_SECRET_ARN: ${COGNITO_SECRET_ARN:-}
      OPS_PUBLIC_BASE_URL: ${OPS_PUBLIC_BASE_URL:-}
```

Do not add `ALLOW_INSECURE_DEMO`, `AUTH_CODE_DELIVERY=response`, or `AUTH_CODE_LOG_PLAINTEXT`
anywhere.

## 2. `deploy/production.md`

### a. "Current Release Blockers" — replace the first bullet

```markdown
- Customer login-code delivery is implemented for SES (`AUTH_CODE_DELIVERY=email`) but is not
  provisioned by this template: it needs a verified SES identity, the `ses:SendEmail` grants in
  [../infra/iam/README.md](../infra/iam/README.md), and `AUTH_EMAIL_FROM` on a verified domain.
  Until those exist `/auth/request` returns `503` rather than claiming a code was sent. Never
  enable plaintext login-code logging as a workaround.
```

### b. Replace the ops bullet

```markdown
- The ops console is still a prototype UI, but its backend now exists: `/ops/*` is mounted only
  when `OPS_SSO_ENABLED=true` and backed by Cognito authorization-code + PKCE. It is not approved
  for production until the hosting, network allowlist, and staff-group membership below are
  reviewed. The former placeholder handler stays deleted; do not re-add it.
```

### c. "Runtime inputs" — add to the bullet list

```markdown
- `PUBLIC_BASE_URL`: the customer console origin (e.g. `https://console.linkedqueue.cloud`); used
  by the tenant cookie and origin checks
- `AUTH_CODE_DELIVERY`: `email` (default in the template), `none`, or the dev-only `log`/`response`
- `AUTH_EMAIL_FROM`: SES `FromEmailAddress` on a verified identity (default `no-reply@linkedqueue.cloud`)
- `OPS_SSO_ENABLED`: `true` to mount `/ops/*` behind Cognito; `false` keeps every `/ops/*` path at 404
- `COGNITO_SECRET_ARN`: ARN of the `production/lanyard/cognito` secret (required when SSO is on)
- `OPS_PUBLIC_BASE_URL`: the ops console origin (e.g. `https://ops.linkedqueue.cloud`); the cookie
  `Secure` flag and the write-origin check derive from it
```

### d. "Rollout" — insert two steps after step 3 (the migrate step)

```markdown
4. Confirm the new migrations applied: `ops_members.cognito_sub`, `ops_sessions.hardware_key`, and
   `ops_list_tenants()` (`psql -c '\df ops_list_tenants'`). Re-running `/app/migrate` must report
   "database migrations are up to date".
5. Only when `OPS_SSO_ENABLED=true`: apply the SES/IAM changes in `infra/iam/README.md`, then check
   that `GET /ops/auth/login` returns a `302` to the Cognito hosted UI and that `GET /ops/health`
   without a cookie returns `401`.
```

Renumber the following steps (the old 4–6 become 6–8).

### e. New section at the end of the file

````markdown
## Ops console SSO and hosting

The ops UI is a static export served from its own internal origin. It calls `/ops/*` on the same
origin, so the host must proxy those paths to the control plane.

1. Cognito app client (already provisioned as `production/lanyard/cognito`): confidential client,
   authorization-code grant, scopes `openid email profile`, callback URLs
   `https://ops.linkedqueue.cloud/ops/auth/callback/` and
   `http://localhost:8080/ops/auth/callback/` (the trailing slash is required), sign-out URL
   `https://ops.linkedqueue.cloud/`. Staff are members of the `staff` group; membership is what
   authorizes access. New members are provisioned in `ops_members` as read-only `ops_support`;
   promotion to `ops_oncall`/`ops_admin` is a manual `UPDATE ops_members SET role = ...`.
2. Host rewrite rule (Amplify console → Rewrites and redirects, JSON form). Replace the target host
   with the control plane's public origin; keep status `200` so it is a proxy rewrite, not a redirect:

   ```json
   [
     {
       "source": "/ops/<*>",
       "target": "https://console.linkedqueue.cloud/ops/<*>",
       "status": "200",
       "condition": null
     }
   ]
   ```

   The rewrite forwards the browser's `Origin` header, so `OPS_PUBLIC_BASE_URL` must be the ops
   origin (`https://ops.linkedqueue.cloud`), not the control plane host. Responses keep their
   `Set-Cookie` on the ops origin because the browser sees a same-origin response.
3. Local development: `cd web/ops && LANYARD_API_ORIGIN=http://localhost:8080 npm run dev` uses the
   Next dev rewrite (`web/ops/next.config.mjs`). `NEXT_PUBLIC_OPS_MOCK=1` is fixtures only.
4. Do not expose `/ops/*` on the public customer listener. Keep the ops host on an internal network
   or behind an allowlist.

## Rollback for this change

`006_ops_sso.sql` and `007_ops_tenants.sql` are additive except for
`ops_create_session`/`ops_get_session`, which are replaced. No previously shipped image calls those
functions (the ops handler was never mounted), so rolling back to the previous image is safe without
a database restore. Rolling back only the application leaves the new columns and function in place,
which the previous image ignores.
````

## 3. `README.md`

Replace the status sentence fragment

```markdown
Customer login has no production code-delivery provider, the CDK stack is unsafe and incomplete, the ops console is a prototype, and distributed revocation/replay requirements are unfinished.
```

with

```markdown
Customer login can deliver codes by email through SES when `AUTH_CODE_DELIVERY=email` and the IAM/SES setup in `infra/iam/README.md` is applied; the CDK stack is unsafe and incomplete, the ops console is a prototype whose backend is mounted only behind Cognito SSO (`OPS_SSO_ENABLED=true`), and distributed revocation/replay requirements are unfinished.
```

Replace

```markdown
- `web/ops`: internal operations UI prototype. Its backend routes are intentionally unavailable until staff identity and authorization are implemented.
```

with

```markdown
- `web/ops`: internal operations UI prototype. Its backend (`/ops/*`) is mounted only when `OPS_SSO_ENABLED=true` and backed by Cognito staff SSO; it stays 404 in every other configuration.
```

## 4. `AGENTS.md`

Replace

```markdown
- Keep production access fail-closed. `/ops/*` is intentionally not mounted until real staff authentication and authorization are implemented. Do not re-enable the placeholder handler.
```

with

```markdown
- Keep production access fail-closed. `/ops/*` is mounted only when `OPS_SSO_ENABLED=true` with a real Cognito user pool (`COGNITO_SECRET_ARN`) and `OPS_PUBLIC_BASE_URL`; every other configuration must leave it at 404. Never re-enable the former placeholder session handler.
```

## 5. `web/ops/README.md`

Replace the whole "Backend Status" section body (from `This UI uses mock fixtures…` through the
API table) with:

```markdown
The backend exists in `cmd/controlplane` and is mounted at `/ops/*` only when `OPS_SSO_ENABLED=true`;
otherwise every route returns 404. Staff sign in through Cognito (authorization code + PKCE, `staff`
group required), and `/ops/auth/me` reports the session. Local development can either use the Next
dev rewrite against a running control plane (`LANYARD_API_ORIGIN`) or `NEXT_PUBLIC_OPS_MOCK=1` for
fixtures. Mock mode is not an authentication implementation and must never be deployed.

| Call | Purpose |
| --- | --- |
| `GET /ops/auth/login` | Start staff SSO (OIDC) with a hardware-key requirement |
| `GET /ops/auth/callback/` | Cognito redirect target; sets the `lanyard_ops_session` cookie |
| `GET /ops/auth/me` → `{email, role, hardware_key}` | Session |
| `POST /ops/auth/logout` | Clears the session |
| `GET /ops/health` → `{proxy_p99_ms, revocation_lag_s, event_backlog, uptime_30d_pct, updated_at}` | Health tiles (still static) |
| `GET /ops/tenants` → `[{id, name, plan, agents, grants, state}]` | Tenants, platform-wide |
| `GET /ops/actions?tenant_id=`, `POST /ops/actions {type, tenant_id, reason}` | Request queue; `tenant_id` is `"*"` for platform-wide |
| `POST /ops/actions/{id}/decide {status: approved\|denied}` | Second person decides; `approved` is stored as `executed` |
```

Keep the "What the server must enforce" section as written.

## Verification

Compose interpolation (values are throwaway):

```sh
LANYARD_IMAGE=test PUBLIC_BASE_URL=https://console.linkedqueue.cloud \
TENANT_ID=00000000-0000-0000-0000-000000000000 DATABASE_SECRET_ARN=a TOKEN_PRIVATE_KEY_SECRET_ARN=b \
TOKEN_KEY_ID=c TOKEN_ISSUER=d TOKEN_AUDIENCE=e UPSTREAM_URL=https://example.com UPSTREAM_SECRET_ARN=f \
PROXY_CONNECTOR_ID=g PROXY_SECRET_ID=h TOKEN_PUBLIC_KEY_SECRET_ARN=i \
  docker compose -f deploy/production.compose.yml config >/dev/null && echo ok
```

If Docker is unavailable, at minimum confirm with a diff:

```sh
git diff -- deploy/production.compose.yml
```

Expect six added lines in the controlplane `environment:` block and nothing else. Then:

```sh
rg -n "OPS_SSO_ENABLED|PUBLIC_BASE_URL|AUTH_EMAIL_FROM|COGNITO_SECRET_ARN|OPS_PUBLIC_BASE_URL" deploy/ AGENTS.md README.md
rg -n "placeholder" AGENTS.md README.md deploy/production.md web/ops/README.md
go build ./... && go test ./...
```

The last `rg` must return no line that claims `/ops/*` is unmounted without qualification.
