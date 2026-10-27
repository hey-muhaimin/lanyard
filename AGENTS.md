# AGENTS.md (Lanyard)

## Stack
- Go module: `github.com/example/lanyard` (go 1.27)
- Two binaries: `cmd/controlplane` (HTTP :8080) and `cmd/proxy` (HTTP :8081)
- Deps/services (local): Postgres 16 (with RLS), NATS 2.10 (JetStream enabled) via `docker-compose.yml`
- Container build: multi-stage (`golang:1.27` -> `gcr.io/distroless/base-debian12:nonroot`), builds both binaries for the target platform with stripped symbols, runs as non-root (default CMD runs controlplane)

## Entrypoints & layout
- `cmd/controlplane/main.go`: serves `/healthz`, `/readyz`, and `POST /grant`; readiness returns `503` and grant issuance responds `501 Not Implemented` until the real service is wired, rather than returning success-shaped placeholders. Graceful shutdown and bounded HTTP server timeouts.
- `cmd/proxy/main.go`: initializes in-memory KMS (`vault.NewMemoryKMS(cfg.VaultKeyID)`) and a hardcoded demo secret only when `ALLOW_INSECURE_DEMO=true`; this explicit opt-in is for local demos and is not suitable for production. It serves `/healthz`, `/readyz`, `/jwks.json`, and an authenticated `/proxy` route. Configure `UPSTREAM_URL` to a fixed HTTPS destination; the proxy does not accept caller-selected destinations, refuses non-public DNS resolutions and redirects, strips caller credentials, limits response size, and scrubs echoed secrets. HTTP server timeouts and header limits are configured.
- `internal/config`: env-driven (HOST/PORT/LOG_LEVEL/TENANT_ID/VAULT_KEY_ID). Defaults: `0.0.0.0:8080`, `tenant-demo`, `local-dev-key`. Fails fast if required vars empty.
- `internal/logging`: JSON stdout logger; `Redact(input string, secrets ...string)` replaces secrets with `[REDACTED]` (never log bodies/headers/secrets).
- `internal/vault`: envelope encryption with AES-GCM, DEK wrapped by `KMS` (MemoryKMS is dev-only). `Seal` binds tenant as AAD; `Open` verifies AAD. `Store.Put` seals/wraps; `Store.UseOnce` enforces tenant match and unwraps (one-time retrieval pattern). 
- `internal/policy`: `Engine` interface, `SimpleEngine` denies if missing identity/action, denies admin resources for non-`agent:` actors, denies `MaxRows>1000`, treats `pending` approval as `approve` with reason.
- `internal/grant`: `Service.Issue` validates request/agent/tenant, enforces parent-grant attenuation (`validateAttenuation` checks connector/action/resource prefix and `MaxRows` <= parent), calls policy engine, and returns claims bound to the registered agent public-key thumbprint.
- `internal/registry` and `internal/events`: supporting packages (inspect as needed).
- The `token` package in `internal/token.go` signs and verifies Ed25519 JWTs, publishes JWKS, and verifies DPoP proofs with replay protection. The replay cache is process-local; multi-replica deployments need a shared replay store. Agent `PublicKey` values use unpadded base64url-encoded Ed25519 public keys.
- Proxy `/proxy` requires a valid bearer grant, DPoP proof, and the `demo:read` / `demo-secret` scope. Configure `TOKEN_KEY_ID`, `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, and `TOKEN_PUBLIC_KEY` (unpadded base64url Ed25519 public key) plus `UPSTREAM_URL` (operator-configured HTTPS URL without query or fragment). Without either configuration, `/proxy` and `/readyz` fail closed; `/jwks.json` publishes the configured public key.
- `migrations/001_init.sql` is the immutable deployed baseline (tenants/agents/grants/events). `002_tenant_isolation.sql` adds the current schema and tenant hardening; run it with `DATABASE_URL=... go run ./cmd/migrate` (the migration role needs permission to create/alter `lanyard_app`).

## Commands
- Build (module root): `go build ./...` 
- Test: `go test ./...` runs all packages; the DB isolation test requires `TEST_DATABASE_URL` and `TEST_ADMIN_DATABASE_URL` in CI.
- Migrate: `DATABASE_URL=... go run ./cmd/migrate`; the migration runner is also included as `/app/migrate` in the container image.
- Run locally (no Docker): 
  - Control plane: `PORT=8080 TENANT_ID=tenant-demo go run ./cmd/controlplane`
  - Proxy: `PORT=8081 TENANT_ID=tenant-demo VAULT_KEY_ID=local-dev-key go run ./cmd/proxy` (proxy preloads a demo secret)
- Docker: `docker compose up --build` starts postgres/nats/controlplane/proxy (controlplane uses default CMD; proxy overridden in compose with the explicitly unsafe local-demo mode).

## Gotchas / constraints
- Config panics if `PORT`, `TENANT_ID`, or `VAULT_KEY_ID` are empty strings (even if set). Use non-empty values.
- `MemoryKMS` stores key material in-memory and "wraps" by returning the DEK as-is (dev-only). Do not use in prod.
- The proxy exits unless `ALLOW_INSECURE_DEMO=true`, because the only current KMS/secret-store implementation is an in-memory demo with a hardcoded secret. Do not set this in a production environment.
- The container image runs as non-root on Distroless, but is not by itself production deployable: production KMS, persistent secret/grant storage, authenticated grant issuance, revocation, durable audit, and Kubernetes/IAM configuration remain unimplemented.
- Vault encryption binds tenant via AAD (`[]byte(tenantID)`) — tampering or wrong tenant fails decryption (see `vault_test.go`).
- Store API is `Put` + `UseOnce` (no direct plaintext fetch). Proxy demonstrates one-time use pattern.
- Logging must redact secrets via `logging.Redact` (canary test mentioned in build guide). 
- Grant attenuation is enforced in `grant.Service` when `ParentGrant` is set (resource prefix match + MaxRows <= parent).
- DB has RLS on `grants`; app must set `app.tenant_id` per transaction when querying (per build guide).
- Control plane `/grant` currently accepts any POST JSON and returns `202/201`-style accepted response (no full policy/grant issuance wired in main yet) — trust code over docs.

## Verification
- Vault roundtrip: `TestSealAndOpenRoundTrip` passes; tenant mismatch and tamper fail.
- Logging: `Redact` tested indirectly; ensure no secrets leak.
- Grant/policy: table-driven/property-style expectations in build guide; current `SimpleEngine` implements stated rules.

<!-- BEGIN AWS Agent Toolkit rules -->
# AWS Guidance for the new AWS experience

This user has signed up for the new AWS experience. This experience lets you sign into AWS using a social provider and requires the following additional context.

Where this guidance conflicts with the project's own instructions, the project's instructions take precedence.

## Context

### Terminology

- Say "project" instead of "account" — a project contains an AWS account and settings for sharing with other collaborators.
- Say "team member" instead of "IAM user" — users are invited by email, not created or federated in IAM.
- Say "AWS Settings" when referring to management tasks at https://settings.aws.com/ (project management, billing, team members, spend limits). Users view their actual AWS resources in the AWS Management Console.
- Say "selected Region" when referring to the user's Region — not "home Region".
- The user has a managed IAM experience. This includes managed service control policies (SCP) and resource control policies (RCP) that govern AWS use. IAM policies are still needed to let services work with each other. For questions about SCPs or RCPs, consult https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html.

### Constraints

- All projects share a single AWS Region determined by the user's contact address. Resources cannot be created in other Regions.
- Create all Regional resources in the project's assigned Region.
- AWS WAF and CloudWatch Logs resources may be created in `us-east-1` only when required by a global resource, such as a global WAF instance. Do not use `us-east-1` for other Regional resources. For inventory, check the selected Region and `us-east-1` for CloudWatch Logs or WAF resources.
- Do not attempt to create Lambda, API Gateway, or other Regional resources outside the selected Region.
- Direct users to confirm their Region in AWS Settings > View all projects > Overview > Additional Info > Region. If they cannot confirm, check `~/.aws/config`.
- Do not use Lambda@Edge; it is excluded from both Lambda and CloudFront.
- Do not use CloudFormation StackSets; multi-account and multi-Region deployments are unavailable.
- Do not attempt cross-Region actions, including cross-Region replication for DynamoDB, S3, or RDS, or multi-Region KMS keys.
- Do not use Route 53 cross-Region routing policies (geolocation, latency-based, or failover). CloudFront is global and its actions are allowed in `us-east-1`; its Lambda function URL or API Gateway origin must still be in the selected Region.
- Amazon Rekognition, Textract, Personalize, and App Runner are unavailable in `eu-north-1`.
- AWS manages human IAM access. Do not assign roles to team members unless absolutely necessary.
- If a previously working operation suddenly returns Access Denied, ask whether a spend limit is configured. Direct users to AWS Settings > Billing for spend status, and check whether the project is on the paid plan. Only project owners can modify spend limits.
- Ask whether the user wants successfully created resources cleaned up or kept to reduce cost.
- Billing setup, spend limits, and invoices are managed in AWS Settings. Budgets and cost optimization are handled in the AWS Billing and Cost Management console.
- If a service is unavailable, run `aws freetier get-account-plan-state`. For a `FREE` plan, check https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-free-tier; for a `PAID` plan, check https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-paid-plan. If the service is in neither list, check https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#unsupported-services; advanced features may need activation.
- Users can activate advanced AWS services and capabilities for their project.
- Before starting an AWS task, check whether a relevant AWS skill is available and use its guidance in preference to general knowledge.

### Help level

While the user is building, ask: "How much guidance would you like from me? Low (I only flag security risks), medium (I ask a couple of clarifying questions if something seems off), or high (I explain what I'm doing, suggest alternatives, and flag best practices)."

The user may select a level and save it in this file.

- **LOW:** Follow all constraints; execute requests without modification; do not ask clarifying questions unless the action would create a security vulnerability; do not suggest alternatives or improvements.
- **MEDIUM:** Execute requests; ask up to two clarifying questions per task for ambiguity or potential issues; do not repeat dismissed questions or suggestions; do not explain trade-offs unless asked.
- **HIGH:** Explain what each step does and why before execution; suggest alternatives when better; flag best practices and trade-offs; still execute the user's choice if they disagree.
<!-- END AWS Agent Toolkit rules -->
