# Implementation Status

This file replaces the original bootstrap checklist, which described the repository before the control plane, proxy, database migrations, and customer console had been implemented. For developer commands and the current release boundary, see the root [README](../README.md).

## Implemented

- Go control-plane, proxy, and migration binaries.
- PostgreSQL migrations, tenant isolation primitives, database-backed customer sessions, and admin handlers.
- Cedar policy evaluation and grant issuance using DPoP-bound agent keys and Ed25519-signed tokens.
- Secret-store and KMS adapters, proxy-side upstream credential retrieval, health/readiness endpoints, and structured logging.
- Customer and internal Next.js interfaces, with static export build scripts.
- CI checks for Cedar validation, PostgreSQL migrations/integration tests, Go build, and Docker image build.

## Release Blockers

- Customer authentication has no production email/code delivery integration; the default delivery mode is `none`.
- The CDK stack is a prototype and must not be deployed as-is. Its public HTTP listener, destructive removal policies, placeholders, and incomplete service/API routing need redesign.
- The customer static site and API are not fully wired together in the current CDK distribution.
- The ops console has mock data and no trustworthy staff authentication; `/ops/*` is intentionally not mounted by the control plane.
- Distributed DPoP replay protection and revocation invalidation are not implemented across replicas.
- Production deployment, incident response, monitoring, recovery, and security testing have not been completed as a release gate.

This is a code-backed status summary, not a launch approval. Update it when implementation and verification evidence change.
