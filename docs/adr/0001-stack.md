# ADR 0001: Lanyard Stack and Security Model

- Status: Accepted
- Date: 2026-10-26

## Context

The Lanyard system must issue task-scoped identity and credentials for autonomous agents without exposing raw secrets to the model or the agent runtime.

## Decision

- Language: Go for the control plane, grant service, and proxy.
- Database: PostgreSQL with row-level security and tenant-specific app settings.
- Policy engine: Cedar via cedar-go semantics wrapped in a Lanyard interface.
- Tokens: Ed25519-signed JWT-like claims with DPoP-style sender constraints.
- Event log: append-only, hash-chained audit events stored per tenant.
- Secrets: envelope encryption using per-secret data keys wrapped by a KMS.
- Dashboard: TypeScript/React at the admin layer.
- Infra: Docker Compose, Terraform, and GitHub Actions for build and release automation.

## Consequences

This stack keeps the core logic in one language while preserving security boundaries across tenant, policy, vault, and audit functions.
