# Lanyard

Lanyard is a Go control plane and egress proxy for issuing short-lived, task-scoped grants to autonomous agents. The proxy validates grants and brokers upstream credentials so they do not need to be exposed to the agent runtime.

> **Status: not production-ready.** The repository has working components and deployment prototypes, but still has release blockers. Customer login has no production code-delivery provider, the CDK stack is unsafe and incomplete, the ops console is a prototype, and distributed revocation/replay requirements are unfinished. Read [production status](deploy/production.md) before deploying anything beyond a controlled development environment.

## Components

- `cmd/controlplane`: issues DPoP-bound, Ed25519-signed grants, evaluates Cedar policies, and exposes customer auth/admin routes when configured with PostgreSQL.
- `cmd/proxy`: validates grants and proxies to a configured HTTPS upstream while resolving the upstream credential from the secret store.
- `cmd/migrate`: applies the embedded PostgreSQL migrations.
- `web/console`: customer console; built as a static export and deployed separately from the Go API.
- `web/ops`: internal operations UI prototype. Its backend routes are intentionally unavailable until staff identity and authorization are implemented.

## Requirements

- Go 1.27.
- Node.js 20.9 or newer for either web app.
- PostgreSQL 16 for the database-backed control plane and integration tests.
- Cedar CLI for validating policy files.

## Development Checks

```sh
go test ./...
go build ./...
```

Validate the example Cedar policy:

```sh
cedar validate --schema policies/schema.cedarschema.json --schema-format json \
  --policies policies/default.cedar --policy-format cedar
```

Run the customer UI checks:

```sh
cd web/console
npm ci
npm run typecheck
npm test
npm run build:static
```

Run the internal UI checks similarly from `web/ops`. Set `NEXT_PUBLIC_OPS_MOCK=1` for local fixture data; mock mode is not an authentication implementation.

Database integration tests need PostgreSQL and the environment variables configured in `.github/workflows/ci.yml`. A Go test run without those URLs does not prove database integration behavior.

The root `docker-compose.yml` is a development artifact and currently does not provide a working database-backed control-plane setup. Do not use it as a production recipe.

## Production Boundary

`deploy/production.compose.yml` is a single-host template that binds service ports to loopback. It requires an external TLS/authenticated ingress, configured AWS identity, PostgreSQL, Secrets Manager entries, and KMS permissions. Production deployment is incomplete until login-code delivery, static console/API routing, operational alerting, and the remaining security/reliability gates are implemented and verified.

The `cdk/` stack is a prototype and must not be deployed as-is. It currently has a public HTTP load balancer, destructive removal policies, placeholder secrets and tenant settings, no proxy service, and incomplete customer API routing. See [deployment status and rollout notes](deploy/production.md).

## Documentation

- [Agent and contributor instructions](AGENTS.md)
- [Production status and manual deployment notes](deploy/production.md)
- [Architecture decision record](docs/adr/0001-stack.md)
- [Current implementation status](docs/implementation-plan.md)
- [Cedar policy guidance](policies/README.md)
- [Customer console notes](web/console/README.md)
- [Ops console prototype notes](web/ops/README.md)

The thesis, build guide, and sprint plans are design/history documents, not authoritative descriptions of the current implementation.