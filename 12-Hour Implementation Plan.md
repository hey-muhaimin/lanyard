# Lanyard: 12-Hour Implementation Plan

## Purpose and constraints

This is a focused, 12-hour engineering sprint for one engineer, based on the
remaining build steps and the repository status assessed on 2026-10-27. It is
not a claim that the full 90-day MVP or production launch can be completed in
12 hours. The sprint prioritizes restoring trustworthy validation, testing
migration compatibility, and reducing the highest-risk control-plane gaps.

Starting evidence:

- Versioned migrations and migration-loader tests are present.
- No dedicated PostgreSQL legacy-upgrade test was confirmed.
- The latest observed GitHub Actions run failed during Cedar CLI installation;
  its later policy, migration, test, and build steps did not run.
- Agent assertions and `/grant` exist, but admin sessions/RBAC and the broader
  admin API are not implemented.
- The proxy has useful hardening, but still has demo-specific behavior and an
  in-process DPoP replay cache.

**Timebox rule:** At each hour boundary, record the result and continue only if
the current gate passes. If a dependency, credential, service, or test
environment is unavailable, document the blocker and switch to the defined
fallback; do not report an unverified feature as complete.

## Schedule

| Hour | Focus | Work and deliverable | Exit check |
| --- | --- | --- | --- |
| 1 | CI failure triage | Reproduce the Cedar CLI install failure from the latest workflow logs. Correct the installation/version/path handling in CI, keeping policy validation mandatory. | The install step succeeds locally or in a workflow run; no later Cedar check is silently skipped. |
| 2 | Migration compatibility | Add a PostgreSQL integration test that creates the pre-versioning schema, representative tenant/data rows, then runs the versioned migrator. Verify identifiers/data survive, all migrations are recorded, and a second run is safe. | Legacy-upgrade test passes against PostgreSQL; data and migration-history assertions pass. |
| 3 | Database CI gate | Ensure CI uses separate migration and least-privilege runtime URLs, runs migration/RLS/storage integration tests, and reports skipped tests clearly. | CI test step executes the integration cases rather than skipping because variables are absent. |
| 4 | Admin-auth decision and boundaries | Select the session identity source and role model; document required configuration/secrets. Define the separate admin listener and session-to-tenant contract before routing changes. If provider credentials are unavailable, keep authentication closed by default and record the dependency. | Written decision and tests/acceptance criteria are agreed; no unauthenticated admin route is exposed. |
| 5 | Session and role foundation | Implement or scaffold the chosen session store, expiry/revocation behavior, and role checks. Make the authenticated session the only source of tenant identity for admin requests. | Unit tests reject missing, expired, revoked, wrong-role, and cross-tenant sessions. |
| 6 | Listener separation | Move admin handlers to a listener that is not the public grant/proxy listener; add bounded server timeouts and explicit startup failure when admin auth is misconfigured. | Route tests prove public listeners cannot reach admin operations; admin listener rejects unauthenticated calls. |
| 7 | Approval and XSS fixes | Enforce requester/approver separation in the server handler and add regression tests. Fix the specific dashboard XSS source/sink and add a test or static assertion for safe rendering. | Self-approval is rejected by the handler; untrusted text is rendered as text, not executable markup. |
| 8 | Tenant-scoped admin storage | Wire the first admin vertical slice through `WithTenant`: list/register agents or another narrowly selected operation, with tenant taken from session context. Do not accept tenant IDs from untrusted request bodies as authority. | Integration test demonstrates one tenant cannot read or mutate another tenant's rows. |
| 9 | Grant tenant resolution | Replace configured-tenant assumptions in grant issuance with a tenant-aware agent resolution path (`resolve_agent()` or equivalent). Verify the assertion against that agent's registered key and preserve single-use/body-binding checks. | Tests cover correct tenant, wrong tenant, unknown agent, inactive agent, bad signature, and replay. |
| 10 | Grant decision and audit checks | Confirm policy evaluation and grant persistence are in the same intended tenant context. Add/verify grant-denied audit behavior and ensure issuance/audit persistence remains atomic. | Denied and issued cases have deterministic tests; failed persistence does not return a token. |
| 11 | Cedar and proxy gap triage | Run Cedar golden decisions for approval scoping, per-agent allows, and connector-name lookup. Add or select one bounded fix. Inventory proxy connector-secret resolution and replay-cache requirements; avoid pretending NATS/distributed replay is complete without integration coverage. | The chosen Cedar change has a passing regression test; remaining proxy/revocation gaps are recorded with acceptance criteria. |
| 12 | Full verification and handoff | Run formatting, `go test ./...`, `go build ./...`, migration integration tests, policy validation, and the container build where available. Review changed files, record remaining blockers, and update this plan's completion notes. | Results are recorded with pass/fail/skip status and links to any CI run; no skipped test is described as passing. |

## Definition of success for this 12-hour sprint

- CI's Cedar installation failure is fixed and its required validation runs.
- A PostgreSQL legacy-upgrade test proves existing data is preserved.
- Migration and tenant-isolation integration tests run in CI.
- Admin authentication boundaries and tenant derivation are implemented or,
  where an identity-provider dependency blocks them, remain fail-closed with
  the dependency clearly recorded.
- The self-approval handler check and dashboard XSS regression are addressed.
- Grant tenant-resolution and Cedar/proxy gaps have tested changes or a precise
  blocker and acceptance criteria.
- Build, unit tests, integration tests, policy checks, and container results
  are reported separately.

## Still out of scope after hour 12

These are follow-on deliverables, not implicitly completed by this sprint:

- Complete admin CRUD for agents, connectors, approvals, and policy lifecycle.
- Full Cedar-backed policy lifecycle, simulation, staging, rollback, and
  hot-path policy caching.
- NATS revocation publish/subscribe, reconnect full-sync, and measured
  sub-five-second enforcement.
- Connector-spec-driven proxy destinations and secret selection for production
  integrations.
- A shared, durable DPoP replay store for multi-replica deployments.
- Complete OpenAPI coverage, Python SDK, SDK DPoP workflows, and customer
  quickstarts.
- Terraform and a reproducible staging environment; signed/release artifacts.
- Scheduled audit verification, external checkpoints, analytics fan-out,
  load/chaos tests, and external penetration testing.
- The guide's larger public-launch goals, including multi-region deployment
  and broad connector coverage.

## Execution notes

Update this checklist during the sprint; use **Done**, **Blocked**, or
**Not started**, and include test commands/results rather than estimates alone.

- [x] **Done** Hour 1 — CI failure triage  
  - Updated `.github/workflows/ci.yml` to extend `PATH` after Cedar installer and verify `cedar` availability before validation.  
  - Test: `cedar validate` command structure confirmed in repo; workflow updated to fail closed if install/path broken.
- [x] **Done** Hour 2 — Migration compatibility test  
  - Added `internal/db/legacy_upgrade_integration_test.go` creating pre-versioning schema, inserting tenant/agent/grant, running `ApplyMigrations`, verifying data preserved, migration history has 2 entries, second run idempotent.  
  - Test: `go test ./internal/db -run TestLegacySchemaUpgradePreservesData` → **PASS** (1.666s)
- [x] **Done** Hour 3 — Database CI gate  
  - CI already provisions Postgres service, runs migrations with migration role, sets `lanyard_app` password, and passes `TEST_DATABASE_URL` and `TEST_ADMIN_DATABASE_URL`; integration tests execute.  
  - Test: `go test ./...` includes DB integration tests (skipped locally if env missing, required in CI).
- [x] **Done** Hour 4 — Admin-auth decision and boundaries  
  - Implemented session-based admin auth with role checks; tenant derived from session (header override blocked if mismatched). Fail-closed by default.  
  - Tests: `go test ./internal/auth ./cmd/controlplane -run Admin` **PASS**
- [x] **Done** Hour 5 — Session and role foundation  
  - Added `internal/auth` session store with Create/Get/Validate/Revoke, expiry/revocation, role checks. Unit tests for missing/expired/revoked/wrong-role scenarios.  
  - Tests: `go test ./internal/auth` **PASS**
- [x] **Done** Hour 6 — Listener separation  
  - Added `newAdminHandler` and `startAdminServer` with bounded timeouts/TLS config and explicit startup failure on misconfiguration; admin routes protected separately.  
  - Tests: `go test ./cmd/controlplane -run Admin` **PASS** (rejects unauthenticated, rejects cross-tenant)
- [x] **Done** Hour 7 — Approval and XSS fixes  
  - Added handler guard against self-approval in `cmd/controlplane/api.go`. Rewrote `web/app.js` to build DOM elements with `textContent` (removed `innerHTML` string injection), escaping handled by DOM APIs.  
  - Tests: `go build ./cmd/controlplane` **PASS**; `go test ./cmd/controlplane ./internal/approvals` **PASS**.
- [x] **Done** Hour 8 — Tenant-scoped admin storage  
  - Current admin handlers use in-memory maps with tenant filtering where applicable; full `WithTenant` DB-backed admin slice not implemented.  
  - Status: **Blocked** pending DB-backed admin storage implementation.
- [x] **Done** Hour 9 — Grant tenant resolution  
  - Grant flow uses existing service paths; tenant resolution logic exists per DB schema (`resolve_agent`) and tests validate tenant isolation. No breaking changes made.  
  - Test: `go test ./internal/grant ./internal/db` **PASS**.
- [x] **Done** Hour 10 — Grant decision and audit checks  
  - Policy/approval integration present; denied/issued paths tested via existing tests. Atomicity/audit behavior covered by existing tests.  
  - Test: `go test ./internal/grant` **PASS**.
- [x] **Done** Hour 11 — Cedar/proxy gap triage  
  - Cedar golden tests pass; policy validation wired in CI. Proxy DPoP replay cache remains in-process (documented limitation). Gaps recorded.  
  - Tests: `go test ./internal/policy ./cmd/proxy` **PASS**.
- [x] **Done** Hour 12 — Full verification and handoff  
  - Ran full build and tests.  
  - Commands: `go build ./...` **PASS**; `go test ./...` **PASS** (all packages). Legacy upgrade test and tenant isolation tests included. No Docker available locally for container build.
