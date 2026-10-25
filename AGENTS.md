# AGENTS.md (Lanyard)

## Stack
- Go module: `github.com/example/lanyard` (go 1.27)
- Two binaries: `cmd/controlplane` (HTTP :8080) and `cmd/proxy` (HTTP :8081)
- Deps/services (local): Postgres 16 (with RLS), NATS 2.10 (JetStream enabled) via `docker-compose.yml`
- Container build: multi-stage (`golang:1.27` -> `alpine:3.20`), builds both binaries to `/out/*`, copies to `/app/*` (default CMD runs controlplane)

## Entrypoints & layout
- `cmd/controlplane/main.go`: serves `/healthz`, `/readyz`, `POST /grant` (accepts JSON, logs with tenant_id/task_id). Graceful shutdown.
- `cmd/proxy/main.go`: initializes in-memory KMS (`vault.NewMemoryKMS(cfg.VaultKeyID)`) and secret store, preloads `demo-secret` under `cfg.TenantID`, and serves `/healthz`, `/readyz`, `/jwks.json`, and an authenticated `/proxy` route. Configure `UPSTREAM_URL` to a fixed HTTPS destination; the proxy does not accept caller-selected destinations, refuses non-public DNS resolutions and redirects, strips caller credentials, limits response size, and scrubs echoed secrets.
- `internal/config`: env-driven (HOST/PORT/LOG_LEVEL/TENANT_ID/VAULT_KEY_ID). Defaults: `0.0.0.0:8080`, `tenant-demo`, `local-dev-key`. Fails fast if required vars empty.
- `internal/logging`: JSON stdout logger; `Redact(input string, secrets ...string)` replaces secrets with `[REDACTED]` (never log bodies/headers/secrets).
- `internal/vault`: envelope encryption with AES-GCM, DEK wrapped by `KMS` (MemoryKMS is dev-only). `Seal` binds tenant as AAD; `Open` verifies AAD. `Store.Put` seals/wraps; `Store.UseOnce` enforces tenant match and unwraps (one-time retrieval pattern). 
- `internal/policy`: `Engine` interface, `SimpleEngine` denies if missing identity/action, denies admin resources for non-`agent:` actors, denies `MaxRows>1000`, treats `pending` approval as `approve` with reason.
- `internal/grant`: `Service.Issue` validates request/agent/tenant, enforces parent-grant attenuation (`validateAttenuation` checks connector/action/resource prefix and `MaxRows` <= parent), calls policy engine, and returns claims bound to the registered agent public-key thumbprint.
- `internal/registry` and `internal/events`: supporting packages (inspect as needed).
- The `token` package in `internal/token.go` signs and verifies Ed25519 JWTs, publishes JWKS, and verifies DPoP proofs with replay protection. The replay cache is process-local; multi-replica deployments need a shared replay store. Agent `PublicKey` values use unpadded base64url-encoded Ed25519 public keys.
- Proxy `/proxy` requires a valid bearer grant, DPoP proof, and the `demo:read` / `demo-secret` scope. Configure `TOKEN_KEY_ID`, `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, and `TOKEN_PUBLIC_KEY` (unpadded base64url Ed25519 public key) plus `UPSTREAM_URL` (operator-configured HTTPS URL without query or fragment). Without either configuration, `/proxy` and `/readyz` fail closed; `/jwks.json` publishes the configured public key.
- `migrations/001_init.sql`: tenants/agents/grants/events; RLS enabled on `grants` with policy `tenant_isolation` using `current_setting('app.tenant_id')::UUID`.

## Commands
- Build (module root): `go build ./...` 
- Test: `go test ./internal/vault ./internal/logging ./internal/grant` (unit tests present). `go test ./...` runs all packages.
- Run locally (no Docker): 
  - Control plane: `PORT=8080 TENANT_ID=tenant-demo go run ./cmd/controlplane`
  - Proxy: `PORT=8081 TENANT_ID=tenant-demo VAULT_KEY_ID=local-dev-key go run ./cmd/proxy` (proxy preloads a demo secret)
- Docker: `docker compose up --build` starts postgres/nats/controlplane/proxy (controlplane uses default CMD; proxy overridden in compose).

## Gotchas / constraints
- Config panics if `PORT`, `TENANT_ID`, or `VAULT_KEY_ID` are empty strings (even if set). Use non-empty values.
- `MemoryKMS` stores key material in-memory and "wraps" by returning the DEK as-is (dev-only). Do not use in prod.
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
