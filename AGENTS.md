# Lanyard

Go control plane + egress proxy issuing task-scoped grants to autonomous agents, with Cedar policy evaluation and PostgreSQL-backed audit.

**Status: not production-ready.** [README.md](README.md) is the source of truth for status, setup, and release blockers. Sprint notes, plans in `docs/plans/`, and `12-Hour Implementation Plan.md` are historical — verify against code before trusting them.

## Commands

```bash
go test ./... && go build ./...          # Go 1.27
cedar validate --schema policies/schema.cedarschema.json --schema-format json \
  --policies policies/default.cedar --policy-format cedar

go run ./cmd/migrate                     # applies migrations/ (embedded via embed.go)
```

Database integration tests need two URLs or they **silently skip**:

```bash
TEST_DATABASE_URL=postgres://lanyard_app:lanyard_app@localhost:5432/lanyard?sslmode=disable
TEST_ADMIN_DATABASE_URL=postgres://lanyard:lanyard@localhost:5432/lanyard?sslmode=disable
```

If `CI` is set, missing URLs are fatal instead of skipped. A plain `go test ./...` without these proves nothing about SQL, RLS, or migrations. CI (`.github/workflows/ci.yml`) starts `postgres:16-alpine`, runs migrations as the `lanyard` owner, then sets the `lanyard_app` password before testing.

Web apps (both Next 16 static-export; Node >= 20.9). Run per app from its directory:

```bash
npm ci && npm run typecheck && npm test && npm run build:static
```

- `web/console` — customer console, dev on :3000.
- `web/ops` — internal ops console, dev on :3001. `NEXT_PUBLIC_OPS_MOCK=1` serves fixtures and a fake signed-in engineer; **mock mode is not authentication**.

## Repository Rules

- **Tenant IDs in PostgreSQL must be UUIDs.** The `tenant-demo` default in `internal/config` and the demo agent seed are local-only and will fail against the production UUID schema.
- Never use demo mode or demo credentials in production. `AUTH_CODE_DELIVERY=response` returns login codes in the HTTP response and is rejected unless `ALLOW_INSECURE_DEMO=true`.
- Never log request bodies, authorization headers, login codes, tokens, or upstream secrets. Secrets belong in the configured secret store (Secrets Manager / KMS), never in source or Compose files.
- **Migrations are immutable after release.** Add the next contiguous file in `migrations/`; preserve RLS, tenant scoping, and explicit grants on tenant-owned tables.
- Keep production access fail-closed. Config fails fast on empty `PORT`, `TENANT_ID`, `VAULT_KEY_ID`; production also requires `KMS_KEY_ID` and `AWS_REGION` (`ValidateProduction`). `/ops/*` is mounted only when `OPS_SSO_ENABLED=true` with a real Cognito user pool (`COGNITO_SECRET_ARN`) and `OPS_PUBLIC_BASE_URL`; every other configuration must leave it at 404. Never re-enable the former placeholder session handler.
- The root `docker-compose.yml` is **not** a supported production deployment. `deploy/production.compose.yml` is a manual single-host template that expects external ingress/TLS; it is not an endorsement of production readiness.
- `cdk/` is a prototype and is not approved for production deployment.
- Do not commit generated binaries, local env files, `node_modules/`, or static build output. `.env` is gitignored. Some historical artifacts (`controlplane.exe`, `proxy.exe`, `migrate.exe`, `proxy.bin`, `fix3.py`, `lanyard-policy.json`) are still tracked — do not delete or rewrite them without an explicit cleanup decision.

## Layout

- `cmd/controlplane`, `cmd/proxy`, `cmd/migrate` — service and migration entry points.
- `internal/` — auth, authstore, grant, policy, storage/db, vault, kms, staffsso, mailer, opsstore, proxy support, logging.
- `migrations/` — embedded PostgreSQL migrations. `policies/` — Cedar schema + example policy.
- `web/console`, `web/ops` — customer and ops consoles. `web/` also holds legacy static assets.
- `deploy/` — single-host Compose template and rollout notes. `infra/terraform`, `infra/iam`, `infra/nginx` — infra assets.
- `sdk/`, `connectors/`, `docs/`, `openapi.yaml` — client code, connector specs, design records, API description.

## Ops console and staff SSO

`/ops/*` is mounted **only** when `OPS_SSO_ENABLED=true`, backed by real Cognito SSO (`internal/staffsso`). There is no placeholder handler anymore.

- Required when enabled: `COGNITO_SECRET_ARN`, `OPS_PUBLIC_BASE_URL`, `OPS_CONSOLE_ORIGIN`. The last two must be absolute and HTTPS outside demo mode.
- Callback path is exactly `/ops/auth/callback/` (`staffsso.CallbackPath`). It must match the Cognito app client's registered callback URL character for character.
- The ops console and the API are **separate origins**. The static console is served from its own origin (`https://ops.linkedqueue.cloud`) and calls the API at `NEXT_PUBLIC_API_BASE` (`https://api.linkedqueue.cloud`). Do not point the console hostname at the API load balancer — `/ops/auth/*` will 404 there because that host serves only static files.
- CORS is applied to `/ops/*` only and allows exactly `OPS_CONSOLE_ORIGIN` with credentials; the ops frontend must send `credentials: "include"`.
- `/ops/*` endpoints: `health`, `tenants`, `actions`, `actions/{id}/decide`, plus `auth/login|callback|me|logout`.

## Email login-code delivery

- Enable with `AUTH_CODE_DELIVERY=email`; `AUTH_EMAIL_FROM` (default `no-reply@linkedqueue.cloud`) must be a non-empty valid address, validated at startup.
- Requires `AWS_REGION` for SES. If SES init fails, startup logs a warning and email delivery is disabled.
- Mailer tests: `go test ./internal/mailer`.
- The EC2 instance role needs `ses:SendEmail` on the SES identity; see `infra/iam/lanyard-ses-send-policy.json` and apply the matching statement to the `lanyard-ec2-ssm-runtime-boundary-v1` boundary.

<!-- BEGIN AWS Agent Toolkit rules -->
# AWS Guidance for the new AWS experience

This user has signed up for the new AWS experience. This experience lets you sign into AWS using a social provider and requires the following additional context.

*When this guidance conflicts with the project's own instructions, the project's instructions take precedence.*

## Context

### Terminology:

- Say "project" instead of "account" — a project contains an AWS account and settings for sharing with other collaborators
- Say "team member" instead of "IAM user" — users are invited by email, not created or federated in IAM
- Say "AWS Settings" when referring to management tasks at https://settings.aws.com/ (project management, billing, team members, spend limits). Users view their actual AWS resources in the AWS Management Console.
- Say "selected Region" when referring to the user's Region — not "home Region"
- The user has a managed IAM experience. This includes a managed service control policies (SCP) and resource control policies (RCP) that govern the use of AWS. They will still need to use IAM to create policies to let services work with each other. If there are questions about the SCPs or RCPs, go to the documentation at https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html

### Constraints:

- All projects share a single AWS Region determined by the user's contact address. Resources cannot be created in other Regions
- When developing:
  - **MUST** create all Regional resources in the project's assigned Region
  - You **CAN** create AWS WAF and CloudWatch Logs resources in us-east-1 when there are global resources (like a global WAF instance) that require a connection to dependencies in us-east-1. You should not use these for any other reason, because resources in the selected Region will provide lower cost, higher availability, and easier manageability.
  - **MUST NOT** attempt to create Lambda, API Gateway, or other Regional resources in any other Region
  - **MUST** direct users to confirm their Region in AWS Settings > View all projects > Overview > Additional Info > Region. If the user cannot confirm their Region, check `~/.aws/config`
  - **MUST NOT** use Lambda@Edge — excluded from both Lambda and CloudFront
  - **MUST NOT** use CloudFormation StackSets — no multi‑account or multi‑Region deployments
  - **MUST NOT** attempt cross‑Region actions — no cross‑Region replication for DynamoDB/S3/RDS, no multi‑Region KMS keys
  - **MUST NOT** use Route 53 cross‑Region routing — geolocation, latency‑based, and failover routing policies are not available
  - CloudFront is a global service and its actions **ARE** allowed in `us-east-1`. A user can create a CloudFront distribution pointing to their project‑region Lambda function URL or API Gateway. However, Lambda and API Gateway themselves **MUST NOT** be created in `us-east-1` — they must be in the project Region.
  - Reduced availability in `eu-north-1` specifically: Amazon Rekognition, Amazon Textract, Amazon Personalize, AWS App Runner are not available in that Region.
- IAM permissions for human access are managed by AWS. Don't assign roles to team members unless absolutely necessary
- The user may have a spend limit if they are on the paid plan. The limit that pauses their project if it's exceeded. If resources suddenly become inaccessible, ask if they have a spend limit configured. Only project owners can modify a spend limit.
- When developing:
  - **MUST** ask about spend limit status if the user reports sudden "Access Denied" errors on operations that previously worked
  - **MUST** direct users to check spend status in AWS Settings > Billing
  - **MUST** check if a user has upgraded their account to the paid plan
  - **MUST** ask the user if they want to clean up the successfully created resources or keep them to reduce cost
- The user sets up billing, creates spend limits, and retrieves and pays invoices in AWS Settings. The user creates budgets and optimizes their costs in the AWS Billing and Cost Management console
- Not all AWS services are available. If a service isn't working, do the following:
  1. Run `aws freetier get-account-plan-state`
  2. If `accountPlanType` is "FREE", check the Free‑Tier supported services list
  3. If `accountPlanType` is "PAID", check the Paid‑Tier supported services list
  4. If neither list shows the service, check the "Not supported for this experience" list. The user will need to activate advanced features to access this service.
- Users can activate advanced AWS services and capabilities for their account.
- For any AWS task or question — building, configuring, migrating, debugging, or operating a service, writing SDK code, authoring CDK/CloudFormation, or answering how a service works — first call `aws___search_documentation` with topic `agent_skills` and load the matching skill with `aws___retrieve_skill`. Do this even when you believe you know the answer: skills carry current service behavior that your training may not. Prefer the skill's guidance over general knowledge. Skip it only for work that does not involve AWS.

## Help level

- `help_level` (required): `LOW`, `MEDIUM`, or `HIGH`. While a user is building, you **MUST** ask the user: "How much guidance would you like from me? Low (I only flag security risks), medium (I ask a couple of clarifying questions if something seems off), or high (I explain what I'm doing, suggest alternatives, and flag best practices)."

You **CAN** update this rule file to save a user's `help_level`.

### Constraints for each level

**LOW** – No extra questions, just obey.
**MEDIUM** – May ask up to two clarifying questions.
**HIGH** – Explain steps, suggest alternatives, flag best practices.
<!-- END AWS Agent Toolkit rules -->
