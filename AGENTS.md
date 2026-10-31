## Quick Commands
- Build all Go code: `go build ./...`
- Run all Go tests (skip DB integration unless env set): `go test ./...`
- Run a single Go test (package or pattern): `go test ./path/to/pkg -run TestName`
- Lint and type‑check before tests (CI order): `go vet ./... && staticcheck ./... && go test -run=^$ ./...`
- Run migrations (requires `DATABASE_URL` or secret ARN): `DATABASE_URL=postgres://… go run ./cmd/migrate`
- Start control‑plane demo (needs DB and a UUID tenant): `ALLOW_INSECURE_DEMO=true DATABASE_URL=postgres://… TENANT_ID=$(uuidgen) go run ./cmd/controlplane`
- Start proxy demo (no DB): `ALLOW_INSECURE_DEMO=true UPSTREAM_URL=https://example.com go run ./cmd/proxy`
- Run the Next.js console UI dev server (must be in `web/console`):
  ```
  cd web/console
  npm install          # once per repo
  npm run typecheck   # lint TypeScript / ensure build works
  npm test            # vitest unit tests
  npm run dev         # proxies to control‑plane at http://localhost:8080
  ```
- Build the static console for production (outputs to `web/console/.next`): `cd web/console && npm run build`
- Docker build the control‑plane image (requires Go binary already built): `docker build -t lanyard/controlplane .`

## Admin API Details
- `POST /admin/agents` now accepts an optional `tenant_id`. If omitted, the tenant is inferred from the authenticated session. If provided and it does **not** match the session tenant, the request fails with `tenant_id mismatch`.
- In dev mode (`ALLOW_INSECURE_DEMO=true`), admin routes (`/admin/*`, `/approve`, `/revoke`, `/events/*`) are available and backed by in‑memory stores. In production they return 404 unless a database pool is configured.

## Test Flavors
- DB‑dependent tests are skipped unless `TEST_DATABASE_URL` is set. Provide a fresh Postgres instance to run integration tests.
- CI disables DB integration (`CI` env var) – locally you can enable with `go test ./...` after setting `TEST_DATABASE_URL`.
- UI tests (Vitest) run in `web/console`; they need Node ≥20.

## Environment Gotchas
- `internal/config` panics on empty `PORT`, `TENANT_ID`, or `VAULT_KEY_ID`. Ensure these are either unset or set to a non‑empty value.
- Outside demo mode the binaries require:
  - `AWS_REGION`
  - `KMS_KEY_ID`
  - Secrets Manager ARNs: `DATABASE_SECRET_ARN`, `TOKEN_PRIVATE_KEY_SECRET_ARN`, `TOKEN_PUBLIC_KEY_SECRET_ARN`, `UPSTREAM_SECRET_ARN`, `PROXY_CONNECTOR_ID`, `PROXY_SECRET_ID`
- Demo fallbacks: `TOKEN_PRIVATE_KEY` (raw seed) and in‑memory KMS.
- Tenant IDs must be UUIDs; the default `tenant-demo` is not a UUID and will cause schema mismatches on fresh DBs.

## CI / Pre‑commit
- CI workflow (`.github/workflows/ci.yml`) runs:
  1. `cedar validate`
  2. `go run ./cmd/migrate`
  3. `ALTER ROLE lanyard_app PASSWORD`
  4. `go test ./...`
  5. `go build ./...`
  6. `docker build`
- Pre‑commit hooks are not committed; configure your own (e.g., `golangci-lint`, `prettier` for UI) if needed.

## Docker Compose
- The provided `docker compose` file is outdated for the control plane – it sets `TENANT_ID=tenant-demo` without `DATABASE_URL`, causing startup failure. Use the demo command above or update the compose file with a real DB URL and UUID tenant.
- The proxy service works out‑of‑the‑box.

## Miscellaneous
- No `.gitignore` – remember to add common patterns (`build/`, `*.exe`, `proxy.bin`, `web/console/.next`, `web/console/node_modules`).
- The `web/console` directory is untracked – commit only source files, not build artifacts.
- Cedar policies are required for `/grant`; the default policy is published in `policies/default.cedar`.
- The `auth` package provides session handling; admin routes (`/admin/*`, `/approve`, `/revoke`, `/events/*`) are only mounted when a DB pool is present.
- Ops routes (`/ops/*`) are always mounted but use a stub session middleware; replace with real `authstore.Validate` for production.


Task-scoped identity and secrets for autonomous agents: the control plane issues short-lived scoped grants, the proxy enforces them and injects the real upstream credential so the agent/model never sees it.

## Stack and layout
- Go module `github.com/example/lanyard`, go 1.27. Deps: pgx v5, cedar-go, nats.go (invalidator only), AWS SDK v2 (KMS + Secrets Manager).
- Binaries: `cmd/controlplane` (:8080), `cmd/proxy` (:8081), `cmd/migrate`. Image: `golang:1.27` → distroless non-root, all three bins plus `web/` at `/app/web`.
- `web/` is a vanilla ops UI served by the control plane from the relative path `./web` (run from repo root or it 404s). `web/console/` is a Next.js 16 customer console — untracked, not built or served by anything yet.
- `migrations/*.sql` are embedded via `migrations/embed.go`; `policies/` holds the Cedar schema + example bundle; `sdk/python`, `sdk/ts`; `infra/terraform` only has variables/versions (no resources); `deploy/` has production compose + rollout doc.

## Commands
- Build `go build ./...`; test `go test ./...` (passes with no services; DB integration tests skip unless `TEST_DATABASE_URL` / `TEST_ADMIN_DATABASE_URL` are set, and **fail** when `CI` is set).
- CI order (`.github/workflows/ci.yml`): `cedar validate` → `go run ./cmd/migrate` → `ALTER ROLE lanyard_app PASSWORD` → `go test ./...` → `go build ./...` → `docker build`.
- Cedar check: `cedar validate --schema policies/schema.cedarschema.json --schema-format json --policies policies/default.cedar --policy-format cedar` (cedar-policy-cli v4.14).
- Console: `cd web/console && npm run typecheck && npm test` (vitest); `npm run dev` proxies `/auth`, `/admin`, `/approve`, `/revoke`, `/events` to `LANYARD_API_ORIGIN` (default `http://localhost:8080`).
- Migrate: `DATABASE_URL=postgres://... go run ./cmd/migrate`, or `DATABASE_SECRET_ARN` + `AWS_REGION`. Admin role needs rights to create/alter `lanyard_app`.
- Control plane demo run **needs a database**: `ALLOW_INSECURE_DEMO=true DATABASE_URL=... TENANT_ID=<uuid> go run ./cmd/controlplane`.
- Proxy demo run is self-contained (in-memory vault, secret `demo-secret`): `ALLOW_INSECURE_DEMO=true UPSTREAM_URL=https://example.com go run ./cmd/proxy`.
- `docker compose up --build` is stale for the control plane: that service sets `TENANT_ID=tenant-demo` and no `DATABASE_URL`, so it exits at startup. The proxy service works.

## Migrations
- Applied migrations are checksummed in `schema_migrations`. **Never edit a migration that has run anywhere** — add the next zero-padded, contiguous file (`005_...sql`) instead, or `migrate` aborts with "checksum differs". `004_secret_lookup.sql` already carries an uncommitted slug backfill: if 004 ran on a local DB, reset the DB rather than editing it further.
- Every tenant table needs `ENABLE ROW LEVEL SECURITY` + a `tenant_isolation` policy using `current_tenant()` **and** explicit `GRANT`s to `lanyard_app` (see 002/003). `lanyard_app` is `NOBYPASSRLS`; `sessions`/`login_codes` are reachable only through `SECURITY DEFINER` functions.

## Gotchas
- `internal/config` panics when `PORT`, `TENANT_ID`, or `VAULT_KEY_ID` are set to empty strings (empty ≠ unset). Defaults: `0.0.0.0:8080`, `tenant-demo`, `local-dev-key`.
- Tenant IDs must be UUIDs (RLS casts `current_setting('app.tenant_id')::uuid`). The `tenant-demo` default is not a UUID, and the demo seed inserts agent id `agent:demo` into `agents.id UUID` / `public_key BYTEA`, so demo startup against a migrated DB fails — use a real UUID tenant and treat the demo seed as out of sync with the schema.
- All DB access must be tenant-scoped: wrap queries in `db.WithTenant` (sets `app.tenant_id` per transaction); grantstore additionally reads the tenant from context (`grantstore.WithTenant` / `TenantKey{}`).
- Outside demo mode (`ALLOW_INSECURE_DEMO` != `"true"`) the binaries require `AWS_REGION` + `KMS_KEY_ID` and Secrets Manager ARNs: `DATABASE_SECRET_ARN`, `TOKEN_PRIVATE_KEY_SECRET_ARN`, `TOKEN_PUBLIC_KEY_SECRET_ARN` (proxy), `UPSTREAM_SECRET_ARN`, `PROXY_CONNECTOR_ID`, `PROXY_SECRET_ID`. Demo fallbacks: `TOKEN_PRIVATE_KEY` or a hardcoded well-known seed, `vault.MemoryKMS`.
- `POST /grant` is real now: DPoP proof verified against the agent's registered key, Cedar decision, Ed25519 JWT. `/admin/*`, `/approve`, `/revoke`, `/events/*` are mounted **only** in demo mode (404 otherwise) and back onto in-memory stores.
- `/auth/request|verify|me|logout` do not exist in Go yet even though `web/console` calls them; `cmd/controlplane/admin_server.go` (session/role admin handler) exists but is never wired in `main.go`.
- Proxy: `UPSTREAM_URL` must be HTTPS with no credentials/query/fragment; DNS is re-resolved and must be public unicast; redirects are not followed; responses capped at 1 MiB; secret scrubbed with `logging.Redact`. Never log bodies, headers, or secrets.
- Vault: tenant is the AES-GCM AAD, so cross-tenant/tampered ciphertext fails to decrypt; the Postgres store keys secrets by `(tenant_id, secret_id, version)` with `encryption_context_version`.
- Cedar denies when no policy is loaded for the tenant; only the approval subsystem may set `context.approval.status`.
- Not wired / placeholder: `internal/policy/nats_invalidation.go` and compose's `nats` service, `internal/registry`, `internal/mcp`, `internal/deps`, `infra/terraform`.
- No `.gitignore` exists: `build/`, `*.exe`, `proxy.bin`, `web/console/.next`, `web/console/node_modules` are untracked — never commit them.

<!-- BEGIN AWS Agent Toolkit rules -->
# AWS Guidance for the new AWS experience

This user has signed up for the new AWS experience. This experience lets you sign into AWS using a social provider and requires the following additional context.

Where this guidance conflicts with the project's own instructions, the project's instructions take precedence.

## Context

### Terminology:

- Say "project" instead of "account" — a project contains an AWS account and settings for sharing with other collaborators
- Say "team member" instead of "IAM user" — users are invited by email, not created or federated in IAM
- Say "AWS Settings" when referring to management tasks at [settings.aws.com](https://settings.aws.com/) (project management, billing, team members, spend limits). Users view their actual AWS resources in the AWS Management Console.
- Say "selected Region" when referring to the user's Region — not "home Region"
- The user has a managed IAM experience. This includes a managed service control policies (SCP) and resource control policies (RCP) that govern the use of AWS. They will still need to use IAM to create policies to let services work with each other. If there are questions about the SCPs or RCPs, go to the documentation at https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html

### Constraints:

- All projects share a single AWS Region determined by the user's contact address. Resources cannot be created in other Regions
- When developing:
  - MUST create all Regional resources in the project's assigned Region
  - You CAN create AWS WAF and Cloudwatch Logs resources in us-east-1 when there are global resources (like a global WAF instance) that require a connection to dependencies in us-east-1. You should not use these for any other reason, because resources in the selected Region will provide lower cost (due to no cross-Region traffic), increased availability (due to no cross-Region traffic), and easier manageability (due to not needing to look in another Region). When you need to do an inventory of resources, you need to look in both the selected Region and us-east-1 for Cloudwatch Logs or WAF resources.
  - MUST NOT attempt to create Lambda, API Gateway, or other Regional resources in any other Region
  - MUST direct users to confirm their Region in AWS Settings > View all projects > Overview > Additional Info > Region. If the user cannot confirm their Region, check in ~/.aws/config
  - MUST NOT use Lambda@Edge — excluded from both Lambda and CloudFront
  - MUST NOT use CloudFormation StackSets — no multi-account or multi-Region deployments
  - MUST NOT attempt cross-Region actions — no cross-Region replication for DynamoDB/S3/RDS, no multi-Region KMS keys
  - MUST NOT use Route 53 cross-Region routing — geolocation, latency-based, and failover routing policies are not available
  - CloudFront is a global service and its actions ARE allowed in `us-east-1`. A user can create a CloudFront distribution pointing to their project-region Lambda function URL or API Gateway. However, Lambda and API Gateway themselves MUST NOT be created in `us-east-1` — they must be in the project Region.
  - Reduced availability in `eu-north-1` specifically: Amazon Rekognition, Amazon Textract, Amazon Personalize, AWS App Runner are not available in that Region.
- IAM permissions for human access are managed by AWS. Don't assign roles to team members unless absolutely necessary
- The user may have a spend limit if they are on the paid plan. The limit that pauses their project if it's exceeded. If resources suddenly become inaccessible, ask if they have a spend limit configured. Only project owners can modify a spend limit.
- When developing:
  - MUST ask about spend limit status if the user reports sudden "Access Denied" errors on operations that previously worked
  - MUST direct users to check spend status in AWS Settings > Billing
  - MUST check if a user has upgraded their account to the paid plan
  - MUST ask the user if they want to clean up the successfully created resources or keep them to reduce cost
- The user sets up billing, creates spend limits, and retrieves and pays invoices in AWS Settings. The user creates budgets and optimizes their costs in the AWS Billing and Cost Management console
- Not all AWS services are available. If a service isn't working, do the following:
  1. Run the command `aws freetier get-account-plan-state`
  2. If accountPlanType": "FREE", check the [Free Tier supported services list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-free-tier) next,
  3. If accountPlanType": "PAID", check the [Paid Tier supported services list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-paid-plan).
  4. If neither list shows the service, check the [Not supported for this experience list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#unsupported-services). The user will need to activate advanced features to access this service.
- Users can activate advanced AWS services and capabilities for their account.
- For any AWS task or question — building, configuring, migrating, debugging, or operating a service, writing SDK code, authoring CDK/CloudFormation, or answering how a service works — first call `aws___search_documentation` with topic `agent_skills` and load the matching skill with `aws___retrieve_skill`. Do this even when you believe you know the answer: skills carry current service behavior that your training may not. Prefer the skill's guidance over general knowledge. Skip it only for work that does not involve AWS.

### Help level

- help_level (required): LOW, MEDIUM, or HIGH. While a user is building, you MUST ask the user: "How much guidance would you like from me? Low (I only flag security risks), medium (I ask a couple of clarifying questions if something seems off), or high (I explain what I'm doing, suggest alternatives, and flag best practices)."

You CAN update this rule file to save a user's help_level.

Constraints for each level:

**LOW:**

- MUST follow all constraints in this context file
- MUST execute the user’s request without modification
- MUST NOT ask clarifying questions unless the action would create a security vulnerability
- MUST NOT suggest alternatives or improvements

**MEDIUM:**

- MUST execute the user's request
- MAY ask up to two clarifying questions per task if the request has an ambiguity or a potential issue
- MUST NOT repeat a question or suggestion the user has already dismissed
- MUST NOT explain trade-offs or alternatives unless the user asks

**HIGH:**

- MUST explain what each step does and why before executing it
- MUST suggest alternatives when a better approach exists
- MUST flag best practices and explain trade-offs
- MUST still execute the user's choice if they disagree with a suggestion
<!-- END AWS Agent Toolkit rules -->
