# Lanyard: Step-by-Step Build Guide

*Companion to the Lanyard thesis paper. From empty repo to a deployable v1.*

## 0. How to Use This Guide

Yes, the next step is code. This guide walks through the build in the order that keeps something runnable at every stage. Each step has a goal, the work, a snippet where it helps, and a **done when** check. Snippets are Go and SQL and are meant as working starting points: pin dependency versions and check library APIs against their current docs before you rely on them.

**Stack decisions (change them deliberately, not by drift):**

- **Language:** Go for the control plane, grant service, and proxy. One language across the core keeps a five-person team fast. Revisit Rust for the proxy only if profiling demands it.
- **Database:** Postgres with row-level security for tenant isolation.
- **Policy:** Cedar through the cedar-go library.
- **Tokens:** Ed25519-signed JWTs, sender-constrained with DPoP.
- **Event log:** start with an append-only Postgres table, put a log (Kafka-class or NATS JetStream) behind an interface, and swap later.
- **Push channel for revocation:** NATS or Redis pub/sub.
- **SDKs:** TypeScript and Python.
- **Dashboard:** TypeScript and React.
- **Infra:** containers, Terraform, GitHub Actions.

## 1. Repository and Tooling

**Goal:** a monorepo where every commit is built, tested, scanned, and signed.

**Layout:**

```
lanyard/
  cmd/controlplane/      # admin API, registry, policy, grant service
  cmd/proxy/             # data plane: egress proxy and MCP gateway
  internal/vault/        # envelope encryption, KMS interface
  internal/grant/        # grant minting, attenuation, validation
  internal/policy/       # Cedar evaluation, policy store
  internal/events/       # event model, hash chain, emitters
  internal/registry/     # tenants, agents, connectors
  internal/revocation/   # deny-list, push channel
  internal/connectors/   # declarative connector specs
  migrations/            # SQL migrations
  sdk/ts/  sdk/python/   # client SDKs
  web/                   # dashboard
  deploy/                # Terraform, Helm or compose files
  docs/                  # public docs and ADRs
```

**Work:**

1. Create the repo, enable branch protection, require review and passing CI.
2. Add `golangci-lint`, `govulncheck`, and a pre-commit hook.
3. CI pipeline: lint, unit tests, build, container image, SBOM generation, image signing (cosign), dependency scanning.
4. Write `docs/adr/0001-stack.md` recording the decisions above.
5. Add a `docker-compose.yml` with Postgres, NATS, and a local KMS stand-in so any engineer can run everything with one command.

**Done when:** a pull request runs the full pipeline and produces a signed image.

## 2. Database Schema and Tenant Isolation

**Goal:** the control-plane data model, with isolation enforced by the database, not only by application code.

**Migration 001:**

```sql
create table tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table agents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  name text not null,
  owner_subject text not null,
  public_key bytea not null,
  attestation jsonb not null default '{}',
  status text not null default 'active',
  created_at timestamptz not null default now()
);

create table connectors (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  kind text not null,
  allowed_hosts text[] not null,
  config jsonb not null default '{}'
);

create table secrets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  connector_id uuid not null references connectors(id),
  ciphertext bytea not null,
  wrapped_dek bytea not null,
  kms_key_id text not null,
  created_at timestamptz not null default now()
);

create table policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  version int not null,
  body text not null,
  status text not null default 'draft',
  created_at timestamptz not null default now(),
  unique (tenant_id, version)
);

create table grants (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  agent_id uuid not null references agents(id),
  task_id text not null,
  parent_grant_id uuid references grants(id),
  chain_id uuid not null,
  subject text not null,
  scope jsonb not null,
  policy_version int not null,
  expires_at timestamptz not null,
  revoked_at timestamptz
);

create table events (
  seq bigserial primary key,
  tenant_id uuid not null,
  ts timestamptz not null default now(),
  type text not null,
  payload jsonb not null,
  prev_hash bytea not null,
  hash bytea not null
);
```

**Row-level security (repeat for every tenant table):**

```sql
alter table grants enable row level security;
create policy tenant_isolation on grants
  using (tenant_id = current_setting('app.tenant_id')::uuid);
```

Every request handler opens a transaction and runs `set local app.tenant_id = ...` before any query. Use a database role that does not own the tables and cannot bypass RLS.

**Done when:** an integration test proves tenant A cannot read or write tenant B rows even with a buggy query that forgets a WHERE clause.

## 3. Service Skeleton

**Goal:** two binaries that start, log structured output, expose health checks, and shut down cleanly.

**Work:**

1. Config from environment variables with validation at startup (fail fast on missing values).
2. Structured logging (JSON) with a request ID and tenant ID on every line. **Never log request bodies, headers, or secrets.** Add a log-scrubbing test that fails if a canary secret appears in output.
3. `/healthz` (liveness) and `/readyz` (dependencies reachable).
4. Graceful shutdown on SIGTERM, with connection draining.
5. OpenTelemetry tracing and Prometheus metrics wired in from the start, because Lanyard must be observable itself.

**Done when:** `docker compose up` brings both services to ready, and a kill signal drains in-flight requests.

## 4. The Vault (Envelope Encryption)

**Goal:** store upstream secrets so that the database alone is useless to an attacker.

**Design:** each secret gets a random data key (DEK). The DEK encrypts the secret with AES-256-GCM, and a KMS key wraps the DEK. Bind ciphertext to its tenant using AES-GCM additional authenticated data.

```go
type KMS interface {
    Wrap(ctx context.Context, keyID string, dek []byte) ([]byte, error)
    Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
}

func Seal(ctx context.Context, k KMS, keyID, tenantID string, plaintext []byte) (ct, wrapped []byte, err error) {
    dek := make([]byte, 32)
    if _, err = rand.Read(dek); err != nil {
        return nil, nil, err
    }
    defer zero(dek)
    block, err := aes.NewCipher(dek)
    if err != nil {
        return nil, nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = rand.Read(nonce); err != nil {
        return nil, nil, err
    }
    ct = gcm.Seal(nonce, nonce, plaintext, []byte(tenantID))
    wrapped, err = k.Wrap(ctx, keyID, dek)
    return ct, wrapped, err
}
```

`Open` is the mirror image: unwrap the DEK, split the nonce, decrypt with the same tenant ID as additional data.

**Work:**

1. Implement `KMS` twice: a local development implementation (key from an environment variable, clearly marked unsafe) and a real one for your cloud's KMS.
2. Expose the vault only as `Put` and `UseOnce`. There is **no API that returns plaintext to a caller outside the proxy.**
3. Decrypt inside the proxy only, hold plaintext in memory for the duration of one request, and zero it afterwards.
4. Support key rotation: store the KMS key ID with every row and add a background re-wrap job.

**Done when:** tests prove ciphertext from tenant A fails to decrypt under tenant B, a flipped bit fails authentication, and a rotation re-wraps without changing plaintext.

## 5. Registry and Agent Identity

**Goal:** register agents and authenticate them.

**Work:**

1. Admin API (OpenAPI first): create tenants, register agents with an owner subject, create connectors, store secrets.
2. **Agent authentication, version 1:** each agent holds an Ed25519 keypair. Registration stores the public key. To authenticate, the agent signs a short-lived challenge or presents a signed assertion (a JWT with a ten-minute lifetime and a unique ID to prevent replay).
3. Design the attestation field now even if v1 only uses the key: later methods (Kubernetes service accounts, cloud instance identity, SPIFFE SVIDs) plug into the same `Attestor` interface.
4. Admin authentication: OIDC login for humans, API keys with hashed storage for automation. Admin actions emit events.

**Done when:** a registered agent can authenticate, an unknown or revoked agent cannot, and replaying an old assertion fails.

## 6. Policy Engine (Cedar)

**Goal:** a library that answers allow, deny, or require approval, with reasons.

**Work:**

1. Wrap cedar-go behind your own interface so the engine can be swapped or extended:

```go
type Decision struct {
    Effect   string   // allow | deny | approve
    PolicyIDs []string
    Reason   string
}

type Engine interface {
    Decide(ctx context.Context, req Request) (Decision, error)
}
```

2. Map Lanyard concepts onto Cedar: the principal is the agent, with the human subject and task passed as context; the action is a string like `crm:read`; the resource is a connector resource; the context carries task purpose, requested row limits, amounts, and approval status.
3. Represent **require approval** as a convention: a policy annotation such as `@requires_approval` on a permit that matched, or a forbid that is lifted only when `context.approval.status` is granted.
4. Store policies per tenant and version; load into memory on a pushed update; **evaluate with no database call on the hot path.**
5. Write a validator that type-checks policies against your schema before they can be activated.
6. Build the **simulator** now, because it is cheap and powerful: a function that replays stored events against a candidate policy set and reports changed decisions.

**Done when:** table-driven tests cover allow, deny, approval-required, and conflicting policies, and the simulator reports a diff for a deliberately tightened policy.

## 7. Grant Service and Token Minting

**Goal:** turn an authenticated request plus a policy decision into a short-lived, bound credential.

**Request shape (from the SDK):**

- agent assertion, subject (on whose behalf), task ID, purpose, requested resources and actions, requested TTL, optional parent grant.

**Flow:**

1. Authenticate the agent; load tenant and policy set.
2. If a parent grant is present, **verify attenuation**: requested scope is a subset of the parent's, expiry is no later than the parent's, depth is below the cap, and the parent is not revoked.
3. Call `Engine.Decide`. On deny, return a structured error with the reason. On approve, create an approval request and return a pending state.
4. On allow, insert the grant row and mint the token.
5. Emit `grant.issued` or `grant.denied`.

**Token claims:**

```go
type Claims struct {
    jwt.RegisteredClaims               // sub, exp, iat, jti, aud
    TenantID  string                   `json:"tid"`
    Actor     string                   `json:"act"`  // agent ID
    ChainID   string                   `json:"chn"`
    TaskID    string                   `json:"tsk"`
    Scope     []ScopeEntry             `json:"scp"`
    PolicyVer int                      `json:"pv"`
    Cnf       map[string]string        `json:"cnf"` // {"jkt": thumbprint of agent key}
}
```

Sign with Ed25519 (algorithm EdDSA) using a key held in KMS or an HSM-backed signer, and publish the public keys at a JWKS endpoint with a `kid` so rotation is routine.

**Sender constraint (DPoP):** the proxy requires a DPoP proof with each call: a JWT signed by the agent's key, containing the HTTP method, URL, a timestamp, and a unique ID, plus a hash of the access token. The proxy checks that the proof key's thumbprint equals `cnf.jkt`, the timestamp is within a small window, and the unique ID has not been seen (short-lived cache). A stolen token without the key is then useless.

**Done when:** property tests show a child scope is never wider than its parent across thousands of random inputs, and a token replayed without a valid proof is rejected.

## 8. The Proxy (Data Plane)

**Goal:** the component that enforces everything and holds secrets only for the instant they are needed.

**Request pipeline, in order:**

1. Parse and validate the grant token (signature, expiry, audience, not in the deny-list).
2. Verify the DPoP proof.
3. Resolve the target: the agent names a connector and path; **the proxy, not the agent, decides the destination host from the connector's allow-list.** Reject any other host.
4. Evaluate fine-grained policy on the concrete request: method, path, parameter limits, body size, rate and budget counters.
5. Fetch the secret from the vault (decrypt in memory), inject it, and forward.
6. Scrub the response, emit the event, return.

```go
rp := &httputil.ReverseProxy{
    Rewrite: func(r *httputil.ProxyRequest) {
        r.SetURL(target) // chosen from the connector allow-list
        r.Out.Header.Del("Authorization")
        r.Out.Header.Del("Cookie")
        r.Out.Header.Set("Authorization", "Bearer "+string(secret))
    },
    ModifyResponse: func(resp *http.Response) error {
        return scrubResponse(resp, secretValues) // redact echoed secrets
    },
}
rp.ServeHTTP(w, req)
zero(secret)
```

**Hardening checklist:**

- Strip hop-by-hop and agent-supplied auth headers before injection.
- Block redirects to hosts outside the allow-list (or follow them inside the proxy under the same check).
- Reject requests that smuggle a different `Host` or use absolute-form tricks.
- Block private, loopback, and link-local destination addresses after DNS resolution, to prevent SSRF into your own network.
- Enforce body-size and timeout limits; use connection pooling per upstream.
- Support streaming responses, and scrub across chunk boundaries.
- Make the **fail mode** a per-scope setting: closed by default.

**Done when:** a canary-secret test proves the secret never appears in any response, log line, or trace; SSRF and redirect tests pass; and a benchmark shows added latency under 5 ms at p50 locally.

## 9. Event Pipeline and Tamper-Evident Audit

**Goal:** every decision and call becomes a structured, ordered, verifiable event.

**Event types:** `grant.issued`, `grant.denied`, `approval.requested`, `approval.decided`, `call.proxied`, `call.blocked`, `grant.revoked`, `admin.changed`, `anomaly.flagged`.

**Hash chain:** per tenant, each event stores the hash of the previous one.

```go
func nextHash(prev []byte, canonicalPayload []byte) []byte {
    h := sha256.New()
    h.Write(prev)
    h.Write(canonicalPayload)
    return h.Sum(nil)
}
```

**Work:**

1. Define the event struct once, in a shared package, with a version field; use canonical JSON serialization so hashes are reproducible.
2. Emit asynchronously from the proxy through a buffered channel to a batcher, with a bounded queue and a documented overflow policy (for sensitive scopes, block rather than drop).
3. Capture **digests** of request and response by default; make payload capture opt-in and redactable.
4. Write a verifier command that walks a tenant's chain and reports the first broken link, and run it on a schedule.
5. Periodically sign a checkpoint (latest hash plus sequence number) and store it outside the primary database.
6. Fan out to the analytics store through a consumer, keeping the audit table authoritative.

**Done when:** modifying any historical row is detected by the verifier, and a load test shows events are not lost when the downstream consumer is stopped and restarted.

## 10. Revocation

**Goal:** kill an agent, task, or chain and have the proxy honor it within seconds.

**Work:**

1. `POST /revoke` with a scope: agent ID, task ID, or chain ID. Mark rows in Postgres and publish a deny entry on the push channel.
2. The proxy subscribes, keeps an in-memory deny set keyed by chain, task, agent, and token ID, and expires entries once the longest possible grant lifetime has passed.
3. On proxy start or reconnect, **full-sync the deny set from the control plane** so a missed message cannot leave a revoked grant alive.
4. Revoking a parent revokes children through the shared chain ID.
5. Emit `grant.revoked` and measure end-to-end revocation latency as a first-class metric.

**Done when:** a test starts a long-running proxied stream, revokes mid-stream, and the call is cut off within the target (under 5 seconds), including after a simulated disconnected subscriber.

## 11. Approvals

**Goal:** a human decision, bound to one specific request.

**Work:**

1. Table for approval requests holding the exact action, a hash of its parameters, the task, chain, and requester.
2. Notifier interface with Slack and email implementations; messages include enough detail for an informed decision and signed, single-use action links.
3. On approval, the grant service re-evaluates policy with `approval.status` set, and the proxy only honors approval for the request whose parameter hash matches. A changed parameter needs a new approval.
4. Add expiry, escalation, and an audit event for each state change.
5. SDK behavior: `grant.request` returns a pending handle the agent can await or poll, with a timeout and clear error.

**Done when:** approving one payment cannot be reused for a different amount, and an expired approval is rejected.

## 12. SDKs

**Goal:** a five-minute integration. Keep the surface tiny.

**TypeScript:**

```ts
import { Lanyard } from '@lanyard/sdk';

const lanyard = new Lanyard({ agentKey: process.env.AGENT_KEY!, tenant: 'acme' });

const grant = await lanyard.grants.request({
  subject: 'user:maria@acme.com',
  task: 'ticket-4821',
  purpose: 'ticket-resolution',
  resources: [{ connector: 'crm', actions: ['read'] }],
  ttlSeconds: 600,
});

const res = await grant.fetch('crm', '/accounts/42'); // goes through the proxy
```

**Work:**

1. Generate API clients from the OpenAPI spec, then wrap them in the hand-written ergonomic layer above.
2. The SDK holds the agent key, builds DPoP proofs, handles retries with backoff, and surfaces typed errors (denied, approval pending, revoked, expired).
3. Never log tokens; redact in error messages.
4. Mirror the API in Python with the same method names.
5. Add a test harness (`lanyard.testing`) with an in-memory fake so customers can unit-test agents without a network.
6. Publish with provenance (signed packages) and keep the changelog honest.

**Done when:** a new engineer follows the quickstart and makes a governed call in under 15 minutes, measured with a real person.

## 13. MCP Gateway

**Goal:** make any MCP server governable without changing the agent.

**Work:**

1. Implement the MCP authorization flow (OAuth 2.1 style) so MCP clients discover Lanyard as the authorization server.
2. The gateway fronts an upstream MCP server: it authenticates the client, maps each tool call to a Lanyard action and resource, runs the same policy and proxy pipeline, and injects upstream credentials.
3. Maintain a **tool catalog** that records each tool's parameter schema, so policy can reason about arguments and the gateway can reject malformed calls.
4. Treat tool descriptions and results from upstream servers as untrusted: do not let them alter policy or grants.
5. Support both stdio-wrapped and remote (HTTP) MCP servers.

**Done when:** an unmodified MCP client, pointed at the gateway, can use an upstream server, and a denied tool call shows a clear error rather than silent failure.

## 14. Connectors

**Goal:** add integrations quickly and safely with a declarative spec instead of bespoke code.

**Spec fields:** name, auth type (API key, OAuth client credentials, OAuth refresh, signed requests), allowed hosts, base URL, scope-to-action mapping, parameter schemas, response-scrubbing patterns, rate limits, and known quirks.

**Work:**

1. Define the spec in YAML with a JSON Schema validator.
2. Build the first 10 in priority order: GitHub, Slack, Google Workspace, Stripe, Salesforce, Jira, Notion, AWS, Postgres, Microsoft 365.
3. Each connector ships with **contract tests** against recorded fixtures and a nightly run against a sandbox account where available.
4. For OAuth providers, implement the consent flow and refresh-token storage in the vault, plus token exchange for short-lived upstream tokens where the provider supports scopes.

**Done when:** adding a connector for a simple API-key service takes under a day, including tests and docs.

## 15. Anomaly Detection and Replay (v1)

**Goal:** the feedback loop, starting simple.

**Work:**

1. Baselines per agent and per task type, computed from the events table: resources touched, call rates, response sizes, active hours.
2. Rules first: never-before-seen connector, volume above a multiple of the baseline, repeated denials, unusual chain depth. Emit `anomaly.flagged` with a score and evidence.
3. Actions: notify, require approval for the next call, throttle, or revoke, configurable per tenant.
4. **Replay view:** given a task ID, assemble the ordered events with decision context into a timeline.
5. **Least-privilege suggestions:** compare granted scope with used scope over a window and draft a tighter Cedar policy with the evidence attached.
6. Only after rules are trusted, evaluate learned models, and keep the rules as a safety net.

**Done when:** a staged misbehaving agent (probing new connectors, then bulk-reading) is flagged and throttled in a test, and the replay shows exactly why.

## 16. Dashboard

**Goal:** let a security engineer answer who, what, and why in under a minute.

**Screens, in build order:**

1. Agents and owners; connectors and secrets (write-only secret fields, never displayed).
2. Live activity feed with filters by agent, task, subject, outcome.
3. Task replay timeline.
4. Policy editor with validation errors inline, a simulate button, and staged rollout.
5. Approvals inbox.
6. Anomalies and revocation controls (a visible, always-available kill switch).
7. Audit export and compliance reports.

Use server-side pagination, strict CSP, and the same RBAC as the API. Never expose raw tokens in the UI.

**Done when:** a first-time user finds the answer to a specific incident question without help.

## 17. Testing Strategy

- **Unit tests:** every package, with table-driven cases; policy and attenuation get property-based tests.
- **Integration tests:** real Postgres, NATS, and a fake upstream API in containers, run in CI.
- **Security tests, built into CI:**
  - canary secret never leaks to responses, logs, traces, or error messages;
  - tenant isolation under adversarial queries;
  - SSRF, redirect, and header-smuggling cases against the proxy;
  - token tampering, replay, expiry, wrong audience, wrong key;
  - fuzzing of token and request parsers.
- **Performance tests:** a load generator (k6 or vegeta) measuring added proxy latency, with budgets that fail the build when exceeded.
- **Chaos tests:** kill the control plane, the push channel, and the database in turn, and verify static stability and the configured fail modes.
- **End-to-end tests:** the SDK quickstart run against a staging stack on every release.
- **External:** a third-party penetration test before launch, with retest of fixes.

## 18. Deployment

**Goal:** repeatable, reviewable infrastructure.

**Current repository status:** the container image uses a non-root Distroless runtime, but this deployment goal is not yet met. The proxy currently relies on an in-memory demo KMS and hardcoded demo secret and only starts when `ALLOW_INSECURE_DEMO=true`; the control plane returns `501` for grant issuance and `503` for readiness. Do not deploy this snapshot for production workloads. Persistent grant and secret storage, cloud KMS integration, authenticated grant issuance, revocation, durable audit, and reviewed Kubernetes/IAM infrastructure remain prerequisites.

**Work:**

1. Multi-stage Docker builds to minimal, non-root images; read-only filesystems; dropped capabilities.
2. Terraform for networking, Postgres (with backups and point-in-time recovery), KMS keys, the message bus, and the container platform.
3. Separate environments: dev, staging, production, each with its own keys and accounts.
4. Data plane deployed in at least two regions with regional vault replicas; control plane in one primary region first.
5. CI/CD: build, sign, deploy to staging, run the end-to-end suite, then canary to production with automatic rollback on error-rate or latency regression.
6. Secrets for Lanyard itself live in the cloud secret manager, never in the repo; rotate on a schedule.
7. Runbooks for key rotation, revocation storms, database failover, and a compromised-connector incident.
8. Customer-hosted data plane: package the proxy and a vault client as a Helm chart with an outbound-only connection to the control plane.

**Done when:** a destroyed staging environment is rebuilt from code and passes the end-to-end suite without manual steps.

## 19. Operating Lanyard

- **SLOs and alerts:** availability, proxy latency percentiles, revocation latency, event-pipeline lag, token-issuance error rate. Alert on burn rate, not single spikes.
- **Dogfooding:** Lanyard's internal automation and any internal agents run under Lanyard.
- **Incident process:** on-call rotation, severity levels, public status page, written post-incident reviews.
- **Privacy:** retention settings per tenant, deletion workflow, and a documented list of what is stored.

## 20. Build Order Mapped to the 90 Days

| Weeks | Focus | Steps |
| --- | --- | --- |
| 1 to 2 | Foundations | 1, 2, 3 |
| 3 to 4 | Secrets and identity | 4, 5 |
| 5 to 6 | Grants and proxy v1 | 7, 8 (basic), SDK skeleton |
| 7 | Events and first connectors | 9, 14 (first 5) |
| 8 | **Private alpha** with 3 design partners | 12 (TypeScript), minimal dashboard |
| 9 to 10 | Policy and revocation | 6, 10, 8 (hardening) |
| 11 | Approvals and delegation | 11, attenuation chains |
| 12 | MCP gateway and Python SDK | 13, 12 |
| 13 to 14 | **Beta** | 14 (to 30 connectors), 15 (replay) |
| 15 to 16 | Intelligence | 15 (anomalies, simulation, suggestions) |
| 17 | Enterprise readiness | SSO and SCIM, multi-region, customer-hosted preview |
| 18 to 19 | Hardening | 17 (pen test, chaos, load), 18 |
| 20 to 21 | Docs and billing | quickstarts, pricing, status page |
| 22 to 23 | **Public launch** | 19, launch checklist |

(Weeks overlap with the earlier 90-day phases; the point is dependency order, not rigid dates.)

## 21. Definition of Done for v1

- No code path returns a raw upstream secret to an agent.
- Child grants can never exceed parents (property-tested).
- Revocation is effective in under 5 seconds, including after reconnect.
- Tenant isolation holds under adversarial tests.
- Audit chain verifies end to end; checkpoints are stored externally.
- p99 added proxy latency is under 50 ms at target load.
- 25 or more connectors with contract tests.
- External penetration test complete with critical and high findings closed.
- Quickstart works in 15 minutes for a new user.
- Runbooks exist and have been exercised at least once.

## 22. First Week, Concretely

1. Day 1: repo, CI, compose file, ADR for the stack.
2. Day 2: migrations and RLS, with the isolation test.
3. Day 3: service skeletons, config, logging, health checks, and the log-scrubbing canary test.
4. Day 4: vault `Seal` and `Open` with the local KMS and full test suite.
5. Day 5: OpenAPI draft for the admin and grant APIs, reviewed by the whole team before any handler is written.

Start there. Everything else in this guide builds on those five days.
