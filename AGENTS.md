# AGENTS.md (Lanyard)

## Stack
- Go module: `github.com/example/lanyard` (go 1.27)
- Binaries: `cmd/controlplane` (:8080), `cmd/proxy` (:8081), `cmd/migrate`
- Local deps: Postgres 16 (RLS), NATS 2.10 JetStream via `docker-compose.yml`
- Container: multi-stage `golang:1.27` → `gcr.io/distroless/base-debian12:nonroot`, both bins, non-root

## Key files
- `cmd/controlplane/main.go`: `/healthz`, `/readyz` (503 until wired), `POST /grant` (currently 501/accepted placeholder)
- `cmd/proxy/main.go`: needs `ALLOW_INSECURE_DEMO=true` + in-memory demo secret; requires `UPSTREAM_URL` (fixed HTTPS, no query/fragment), `TOKEN_KEY_ID/ISSUER/AUDIENCE/PUBLIC_KEY`; enforces DPoP + bearer grant + scopes; refuses non-public DNS/redirects, strips creds, caps response size
- `internal/config`: env-driven; **panics** if `PORT`, `TENANT_ID`, or `VAULT_KEY_ID` are empty strings (even if set). Defaults: `0.0.0.0:8080`, `tenant-demo`, `local-dev-key`
- `internal/token.go`: Ed25519 JWTs + JWKS + DPoP with process-local replay cache (needs shared store for multi-replica)
- `internal/vault`: AES-GCM envelope encryption; `Seal` binds tenant as AAD (`[]byte(tenantID)`) — tamper/wrong tenant fails; `MemoryKMS` is dev-only (wraps DEK as-is). Store: `Put` + `UseOnce` (no plaintext fetch)
- `internal/grant`: enforces parent attenuation (`validateAttenuation` resource prefix + `MaxRows <= parent`), calls policy engine, binds claims to agent key thumbprint
- `internal/policy/SimpleEngine`: denies missing identity/action, denies admin resources for non-`agent:` actors, denies `MaxRows>1000`, treats `pending` approval as `approve` with reason
- `migrations/001_init.sql` immutable baseline; `002_tenant_isolation.sql` adds hardening — run via migrator. DB has RLS on `grants`; app must set `app.tenant_id` per transaction

## Commands
- Build: `go build ./...`
- Test: `go test ./...` (DB isolation tests need `TEST_DATABASE_URL` + `TEST_ADMIN_DATABASE_URL`)
- Migrate: `DATABASE_URL=... go run ./cmd/migrate` (or `/app/migrate` in image). Migration role needs perms to create/alter `lanyard_app`
- Run locally:
  - Control plane: `PORT=8080 TENANT_ID=tenant-demo go run ./cmd/controlplane`
  - Proxy (demo): `PORT=8081 TENANT_ID=tenant-demo VAULT_KEY_ID=local-dev-key ALLOW_INSECURE_DEMO=true UPSTREAM_URL=https://example.com go run ./cmd/proxy`
- Docker: `docker compose up --build` (proxy runs in unsafe local-demo mode per compose)

## Gotchas
- **Config**: empty string env vars cause panic even if "set" — use non-empty values
- **Proxy**: exits without `ALLOW_INSECURE_DEMO=true`; hardcoded demo secret only in that mode; not for prod
- **Vault**: tenant is AAD — cross-tenant/tamper = decrypt failure
- **Secrets**: always use `logging.Redact` (never log bodies/headers/secrets)
- **RLS**: set `app.tenant_id` per transaction when querying `grants`
- **Attenuation**: enforced in `grant.Service` for parent grants
- **Prod gaps**: no real KMS/persistent grant store/authenticated issuance/revocation/durable audit/multi-replica replay store
