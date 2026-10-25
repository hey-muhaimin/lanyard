# Lanyard: Task-Scoped Identity, Secrets, and Audit for Autonomous AI Agents

*A thesis paper on a new infrastructure layer for the agentic era. October 2026.*

## Abstract

Software is increasingly written and operated by AI agents. These agents call APIs, move money, read customer data, and spawn other agents, yet they authenticate using credentials designed for humans or long-lived services. This paper argues that agents are a new class of principal that needs its own identity, authorization, secrets, and audit infrastructure. We present **Lanyard**, a service that issues short-lived, task-scoped, least-privilege credentials to agents, keeps raw secrets out of the agent's reach through a brokering proxy, evaluates every action against policy, and records a verifiable delegation chain for each event. We describe the threat model, system architecture, credential and token design, policy engine, observability layer, reliability strategy, compliance posture, go-to-market, and a 90-day plan to a full-featured launch.

## 1. Problem Statement

When anyone can generate a working application with AI, the scarce resource shifts from writing code to running it safely. Three structural problems follow.

**Borrowed identity.** Most agents today operate with a human's API key, an OAuth token with broad scopes, or a shared service account. There is no record of which agent acted, for which task, or on whose behalf.

**Ambient authority.** A credential valid for months, held in an agent's context or environment, is one prompt injection away from exfiltration. Agents read untrusted content (web pages, emails, tickets) and then act, which is the classic confused-deputy setup.

**Opaque accountability.** Regulators and auditors ask who did what, with whose approval, under which policy. Generated, non-deterministic systems rarely produce that answer by default.

The existing identity stack (workforce IAM, customer IAM, cloud IAM, secrets managers) solves adjacent problems. None models a principal that is ephemeral, acts for a human, is non-deterministic, can be manipulated by data it reads, and may spawn children.

## 2. Thesis

1. Agents are a distinct principal type, defined by a triple: **(human or system on whose behalf, agent identity, task context)**.
2. Authority should be **minted per task and expire with it**, not provisioned per agent.
3. Agents should **never hold raw secrets**. Credentials are injected at the network edge, outside the model's context.
4. Every action must be **attributable through a delegation chain** and logged as structured, replayable data.
5. **Identity is the control plane; observability is the feedback loop.** Combined, they form a compounding data advantage that neither component has alone.

## 3. Threat Model

**Assets:** third-party credentials (API keys, OAuth refresh tokens), customer data reachable through tools, the ability to take irreversible actions (payments, deletions, emails), and the audit record itself.

**Adversaries and failure modes:**

- **Prompt injection:** untrusted content causes an agent to misuse its authority or leak secrets.
- **Over-privileged agents:** a legitimate agent does more than the task needs, by bug or by hallucination.
- **Credential theft:** tokens stolen from logs, memory, or traces and replayed elsewhere.
- **Delegation abuse:** a sub-agent acquires more authority than its parent had.
- **Malicious or compromised tool servers:** an MCP server or connector tries to harvest tokens.
- **Insider and tenant-boundary attacks:** cross-tenant access, or a Lanyard operator reading customer secrets.
- **Repudiation:** an action occurs and no trustworthy record exists.

**Out of scope:** model alignment itself, and security of the downstream SaaS APIs.

**Core security invariants:**

1. No raw long-lived secret is ever returned to an agent runtime.
2. A child's authority is always a subset of its parent's.
3. Every authorization decision and every proxied call produces an immutable event.
4. Revocation takes effect within a bounded, published time (target: under 5 seconds).

## 4. Design Principles

- **Default deny, task-scoped allow.** Access is requested with a stated purpose and resource set.
- **Short-lived and sender-constrained.** Tokens live minutes and are bound to a key so theft is not enough.
- **Standards first.** Build on OAuth 2.x extensions, MCP authorization, and SPIFFE-style workload identity rather than inventing protocols.
- **Out of the model's blast radius.** Secrets and enforcement live in infrastructure the model cannot read or influence.
- **Observable by construction.** The authorization path and the telemetry path are the same path.

## 5. System Architecture

Lanyard separates a **control plane** (decisions and configuration) from a **data plane** (latency-critical enforcement), fed by an **event pipeline**.

### 5.1 Control plane

- **Registry:** tenants, agents, owners, environments, connectors, and tool catalogs.
- **Policy service:** stores, versions, validates, and distributes policies.
- **Grant service:** evaluates grant requests, drives approvals, mints credentials.
- **Admin API and dashboard:** configuration, approvals, audit search, revocation.

### 5.2 Data plane

- **Token service:** issues and validates short-lived credentials and exchanges tokens with upstream providers.
- **Egress proxy (the broker):** terminates agent calls, checks the grant, injects secrets, forwards to the target, and emits events.
- **Policy decision point (PDP):** an embedded evaluator running next to the proxy, with policies cached locally for sub-millisecond decisions.
- **Revocation cache:** a pushed deny-list so the proxy honors kills without a round trip.

### 5.3 Secrets vault

- Envelope encryption: each secret is encrypted with a per-tenant data key, wrapped by a KMS-held master key (HSM-backed in enterprise tiers).
- Decryption happens only inside the proxy's memory, only at call time, and plaintext is never logged or persisted.
- Enterprise option: a customer-hosted data plane (VPC or on-premises) so secrets never leave the customer's boundary, while the control plane remains managed.

### 5.4 Event pipeline

- Proxy and grant service emit structured events to a log (Kafka-class) with an append-only, hash-chained audit store.
- A stream processor feeds the analytics store (columnar), the anomaly engine, and the replay service.

### 5.5 Request lifecycle

1. The task starts; the SDK calls `grant.request(task, resources, purpose, ttl)` with the agent's workload identity.
2. The grant service authenticates the agent, resolves its owner and delegation parent, and asks the PDP for a decision: **allow**, **deny**, or **require approval**.
3. On approval, Lanyard mints a **task grant**: a signed, sender-constrained token carrying scope, constraints, expiry, and chain.
4. The agent calls the target through the proxy (or the MCP wrapper) presenting the grant.
5. The proxy validates the grant, re-evaluates fine-grained policy on the concrete request (method, path, parameters, size), injects the secret or exchanges for an upstream token, and forwards.
6. The proxy emits an event with the full decision context; the response returns to the agent with secrets redacted.
7. The grant expires, or is revoked, and the audit record remains.

## 6. Identity and Credential Model

### 6.1 Agent identity

Each agent runtime obtains a **workload identity** through attestation. Options by environment: SPIFFE/SPIRE SVIDs, cloud instance or Kubernetes service-account attestation, or a signed bootstrap credential for hosted agent platforms. Identity answers: *which software instance is this?* It does not by itself confer authority.

### 6.2 Principals and the delegation triple

Every grant records:

- **Subject (on behalf of):** the human or service whose authority is being exercised.
- **Actor:** the agent instance acting.
- **Task:** a task identifier, stated purpose, and optional parent task.

This maps naturally onto the **actor claim (`act`)** in OAuth 2.0 Token Exchange (RFC 8693), which already expresses nested delegation.

### 6.3 Task grants

A grant is a signed token (JWT or a compact binary format) with:

- scope expressed as resource and action pairs, using the structure of **Rich Authorization Requests (RFC 9396)** for fine-grained constraints (for example, max amount, allowed recipients, row limits);
- audience restricted per RFC 8707 resource indicators;
- expiry measured in minutes, plus a maximum call count where useful;
- a **confirmation claim** binding it to the agent's key via **DPoP (RFC 9449)** or mutual TLS, so a stolen token is useless without the key;
- the full delegation chain and a policy-version hash.

### 6.4 Upstream credentials

Two patterns, chosen per connector:

- **Proxy injection:** the vault holds the upstream API key or OAuth refresh token; the proxy attaches it per call. The agent never sees it.
- **Token exchange:** Lanyard uses a stored refresh token to mint a short-lived, narrowly scoped upstream access token (where the provider supports scopes), still delivered only to the proxy, or to the agent when the provider offers sender-constrained tokens.

Where a provider offers only coarse keys, Lanyard compensates with proxy-side restrictions on method, path, and parameters.

### 6.5 Delegation

When agent A spawns agent B, B requests a child grant. The grant service enforces **attenuation**: scope(child) is a subset of scope(parent), expiry(child) is at most expiry(parent), and depth is capped. Attenuation can be checked offline using capability-style caveats (macaroon or biscuit-like), which lets sub-agents narrow their own grants without a network call and keeps the chain verifiable.

### 6.6 Revocation

Revocation targets agent, task, or the whole chain. Because grants are short-lived, revocation is a belt-and-suspenders mechanism: the control plane publishes a deny entry, the data plane receives it through a push channel into the local cache, and the proxy rejects matching grants immediately. Child grants are revoked transitively through the chain identifier.

## 7. The Secrets Broker

The proxy is Lanyard's most important component.

**Deployment shapes:**

- **Forward proxy / sidecar:** the agent runtime routes outbound calls through it (HTTP proxy or a local gateway address).
- **MCP gateway:** an MCP server wrapper that fronts upstream tools, so existing MCP clients work unchanged.
- **SDK-mediated:** the SDK calls the grant service and the proxy transparently.

**Functions:**

- Request validation and parameter-level policy checks.
- Secret injection into headers, bodies, or signed requests (including AWS SigV4 style signing, so even signing keys stay hidden).
- **Response scrubbing:** detect and redact secrets or tokens that an upstream echoes back, so they cannot enter the model's context.
- **Egress allow-listing:** an agent can only reach hosts its grant names, which blunts exfiltration through attacker-controlled URLs.
- Rate limits, budget limits, and size limits per grant.
- Idempotency keys and dry-run mode for irreversible actions.

**Performance budget:** target p50 under 5 ms and p99 under 50 ms of added latency, achieved through local policy caches, connection pooling, and no synchronous calls to the control plane on the hot path. Written in a memory-safe systems language (Rust or Go).

## 8. Policy Engine

### 8.1 Language choice

Policies are code: versioned, reviewed, testable. We recommend **Cedar** as the primary language because it is analyzable (decidable, with formal verification tooling), expressive for principal-action-resource-context decisions, and fast. OPA/Rego is supported as an alternative for teams already invested in it. A simple UI editor generates policy for non-engineers.

### 8.2 Example

```
permit (
  principal in Agent::"support-triage",
  action == Action::"crm:read",
  resource in Crm::"accounts"
) when { context.task.purpose == "ticket-resolution" && context.rows <= 100 };

forbid (
  principal,
  action == Action::"payments:create",
  resource
) unless { context.approval.status == "granted" };h
```

### 8.3 Decision outputs

**Allow**, **deny**, or **require approval**, each with a machine-readable reason and the matched policy IDs, which become part of the audit event.

### 8.4 Policy lifecycle

Draft, validate (type-check and conflict analysis), **simulate against historical events**, stage, roll out gradually, and keep a one-click rollback. Simulation is where identity and observability meet (Section 10).

## 9. Human-in-the-Loop Approvals

Approvals are first-class, not a bolt-on.

- Triggered by policy, by risk score from the anomaly engine, or by an agent's own request.
- Delivered through Slack, Teams, email, and a mobile push; the approver sees the exact action, parameters, requesting task, and chain.
- Approvals are **bound to the specific request**, not to a session, preventing approval laundering where a vetted action is swapped for a different one.
- Options: approve once, approve for this task, or approve with edits; time-limited; escalation paths.
- High-assurance actions can require step-up authentication or two-person approval.

## 10. Observability and Evaluation (the Feedback Loop)

### 10.1 Event schema

Every event carries: tenant, timestamp, event type (grant, decision, proxied call, approval, revocation), subject, actor, task and chain IDs, resource and action, policy version and matched rules, outcome, latency, cost, request and response digests (with optional redacted payload capture), and a hash link to the previous event for tamper evidence.

### 10.2 Storage tiers

- **Hot:** columnar store for dashboards, search, and anomaly features (days to weeks).
- **Warm:** object storage in open formats for long retention and customer export.
- **Immutable audit ledger:** hash-chained segments with periodic anchoring (signed checkpoints, optionally to a customer-controlled store) for compliance-grade integrity.

### 10.3 Anomaly detection

Start with transparent rules and baselines, then add learned models:

- New resource or tool never touched by this agent or this task type.
- Volume or velocity spikes, unusual data egress size, off-pattern timing.
- Chain-depth or fan-out irregularities.
- Policy near-misses: repeated denials suggest probing or a misbehaving agent. Outputs are risk scores that can trigger approvals, throttling, or automatic revocation.

### 10.4 Replay and simulation

- **Replay:** reconstruct a task as a timeline with the decision context for every step, so incident responders see exactly what happened.
- **Policy simulation:** evaluate a proposed policy against the last N days of events and report what it would have blocked or allowed, before it ships.
- **Least-privilege suggestions:** compare granted scope against used scope per agent and task type, then propose tighter policies with the evidence attached.

### 10.5 Evaluation of agents themselves

Because Lanyard sees action traces, it can power behavioral regression checks: did an agent's tool-use pattern change after a prompt or model update? Export traces to external eval and tracing tools through OpenTelemetry-compatible spans.

## 11. Integrations

- **MCP:** implement the MCP authorization model (OAuth 2.1 based) on both sides: Lanyard as an authorization server for agents, and as a client to upstream servers. Provide a gateway that adds policy, secrets, and audit to any MCP server.
- **Agent frameworks:** adapters for popular orchestration frameworks and agent SDKs, plus plain HTTP middleware.
- **Connectors:** a declarative connector spec (auth type, scopes, endpoints, parameter schemas, response-scrubbing rules). Start with about 10 (GitHub, Slack, Google Workspace, Stripe, Salesforce, Jira, Notion, AWS, Postgres, Microsoft 365), grow toward 100+. Community and partner-contributed connectors extend coverage.
- **Identity providers:** SSO via SAML and OIDC; SCIM for human owners and approvers; link agent owners to workforce directories.

## 12. Data Model (Core Entities)

- **Tenant, Environment**
- **Principal:** human, service, agent (with owner and attestation method)
- **Connector, Credential (vault reference), Resource**
- **Policy, PolicyVersion, PolicySet assignment**
- **Task, Grant, Chain (with parent link and depth)**
- **ApprovalRequest, ApprovalDecision**
- **Event, RevocationEntry, AnomalyAlert**

Primary stores: a relational database (Postgres) for control-plane state with row-level tenant isolation; the vault; the event log and columnar analytics store described above.

## 13. Reliability and Performance

Being in the call path makes availability existential.

- **Fail modes are explicit and customer-configurable:** fail-closed by default for sensitive scopes; optional fail-open for low-risk, read-only scopes, with a loud audit flag.
- **Static stability:** the data plane keeps working with cached policies, keys, and revocation lists if the control plane is down.
- **Multi-region active-active** data plane with regional vault replicas; control plane active-passive at first.
- **Customer-hosted data plane** for latency-sensitive or regulated deployments.
- SLOs: 99.9% at launch, 99.99% for enterprise; published status and post-incident reviews.
- Load shedding, per-tenant isolation, and noisy-neighbor protections.

## 14. Securing Lanyard Itself

- Memory-safe languages for the data plane; minimal dependencies; reproducible, signed builds with SBOMs.
- Zero standing human access to customer secrets; break-glass access requires dual approval and is itself audited and customer-visible.
- Per-tenant keys, optional customer-managed keys (BYOK/HYOK).
- Strong tenant isolation tests, regular external penetration tests, a public vulnerability disclosure and bug bounty program.
- Dogfooding: Lanyard's own internal agents run under Lanyard.

## 15. Compliance and Governance

- Roadmap: **SOC 2 Type 1** (during launch), Type 2 (months 6 to 12), ISO 27001, then HIPAA readiness and regional data residency (EU, and other regions as demand appears).
- Audit exports mapped to common control frameworks, plus agent-specific attestations: who approved what, least-privilege evidence, and revocation timelines.
- Data minimization: configurable payload capture, field-level redaction, retention controls, and deletion workflows.
- Alignment with emerging AI governance expectations (model and agent inventories, human oversight records).

## 16. Market, Positioning, and Business Model

**Positioning:** not another IAM suite, but **the authorization and audit layer purpose-built for non-human, task-scoped actors**. It complements the workforce identity provider rather than replacing it.

**Customers:**

- *Early:* AI-native startups and platform teams running many agents who need a drop-in SDK and want to pass their first enterprise security review.
- *Core:* regulated enterprises (financial services, healthcare, government contractors) where auditors will require agent accountability.

**Pricing:**

- Free tier (about 1,000 grants per month, limited retention).
- Team: usage-based on proxied actions and grants, with included retention.
- Enterprise: platform fee plus usage, customer-hosted data plane, BYOK, SSO, extended retention, compliance support, and SLAs.

**Competition and differentiation:** workforce IAM vendors (extending to agents), cloud IAM, secrets managers, API gateways, and model-provider tooling will all move here. Lanyard's differentiators are agent-native semantics (task, delegation, approvals), the secrets-never-touch-the-agent proxy, and the joined observability loop, delivered neutrally across model providers and clouds.

**Moat:**

- Call-path position and the switching costs it creates.
- Breadth and quality of connectors, each with auth quirks and scrubbing rules.
- Compliance certifications and enterprise trust accumulated over time.
- Cross-customer behavioral data (privacy-preserving) that improves anomaly detection and policy suggestions.
- Open specification and SDKs that make Lanyard the reference implementation.

## 17. The 90-Day Full-Featured Deployment Plan

### Team

Five people: two backend/security engineers (data plane, vault, token service), one SDK and developer-experience engineer, one full-stack engineer (dashboard, approvals), and a founder leading design partners, security review, and go-to-market. Contractors for pen test and brand design.

### Phase 0 (Days 1 to 14): Foundations

- Finalize name, domain, trademark search, and brand identity: deep navy with an amber active-badge accent, a badge-clip mark, and a calm, precise, docs-first voice.
- Write the threat model, event schema, API contracts, and security invariants (this paper is the seed).
- Choose stack: Rust or Go data plane, Postgres, a Kafka-class log, a columnar analytics store, KMS-backed vault, infrastructure as code from day one.
- Sign 5 to 10 design partners; schedule weekly feedback sessions.
- **Exit criteria:** architecture review passed, repos and CI with signed builds, partners committed.

### Phase 1 (Days 15 to 35): Core MVP and private alpha

- Vault with envelope encryption; token service; grant service with a static policy; proxy with secret injection and basic scrubbing.
- TypeScript and Python SDKs; an MCP gateway wrapper.
- 10 connectors; event emission and a basic audit log UI; revoke-by-agent.
- **Exit criteria:** three design partners running real agents through the proxy; p99 added latency under 100 ms (to be tightened later).

### Phase 2 (Days 36 to 60): Full control plane and beta

- Cedar policy engine with versioning and a UI editor; policy staging and rollback.
- Approvals through Slack and email, bound to specific requests.
- Delegation chains with attenuation; revoke by task and chain; DPoP-bound tokens.
- Connectors to 30; OAuth on-behalf-of flows; declarative connector spec published.
- Tracing and replay built on the event stream; search and filter UI.
- **Exit criteria:** all design partners on beta; revocation under 5 seconds; first policy written by a customer without our help.

### Phase 3 (Days 61 to 80): Trust, intelligence, and enterprise readiness

- Anomaly detection v1 (rules plus baselines); policy simulation against history; least-privilege suggestions.
- SSO/SAML, SCIM, RBAC, multi-tenancy hardening; compliance report exports.
- Multi-region data plane, load testing, chaos testing, static-stability verification; p99 under 50 ms.
- Start SOC 2 through an automation platform; commission an external penetration test and remediate findings.
- Customer-hosted data plane preview for one partner.
- **Exit criteria:** pen test critical and high findings closed; 99.9% measured uptime over 3 weeks.

### Phase 4 (Days 81 to 90): Launch

- Documentation, quickstarts, API reference, and a security whitepaper; pricing page and self-serve billing; status page and SLAs.
- Launch content: this thesis, an architecture deep dive, and two design-partner case studies.
- Public launch via developer communities and partner announcements; open-source the SDKs and connector spec.
- **Exit criteria:** public availability, on-call rotation, and incident process live.

### Day-90 targets

10 or more paying or committed design partners, 25+ connectors, p99 under 50 ms, 99.9% uptime, SOC 2 Type 1 in progress, one named reference customer, and zero known critical vulnerabilities.

## 18. Metrics

- **Product:** time to first grant (target under 15 minutes), grants and proxied actions per tenant, connector coverage, share of traffic using task-scoped versus broad grants.
- **Security outcomes:** percentage of agent calls using no raw secret, mean grant TTL, revocation latency, policy-blocked incidents, suggestions accepted.
- **Reliability:** added latency percentiles, availability, error budget burn.
- **Business:** design partners to paid conversion, net revenue retention, security-review wins.

## 19. Risks and Mitigations

- **Incumbents and model providers move in.** Mitigate with neutrality, depth in delegation and audit, and speed.
- **Standards commoditize the basics.** Implement standards better than anyone and differentiate above them (policy, simulation, approvals, intelligence).
- **Proxy reliability and latency.** Static stability, fail-mode controls, customer-hosted data plane, rigorous SLOs.
- **Connector maintenance burden.** Declarative specs, automated contract tests, partner contributions.
- **Trust barrier for a young vendor holding secrets.** BYOK, customer-hosted data plane, open-source SDKs, third-party audits, transparent incident practice.
- **Over-approval fatigue.** Risk-based approvals, batching, and learned policies so humans see only what matters.
- **Privacy of captured payloads.** Default to digests, make payload capture opt-in and redactable.

## 20. Roadmap Beyond Day 90

- **Months 4 to 6:** SOC 2 Type 2 observation, 100 connectors, learned anomaly models, agent-to-agent trust across organizations, HIPAA readiness.
- **Months 7 to 12:** federation between Lanyard tenants (cross-company agent delegation), hardware-backed agent keys, regional data residency, a policy marketplace for common agent roles, and deeper eval integrations.
- **Long term:** a neutral, open standard for agent delegation and audit records, with Lanyard as the reference implementation.

## 21. Conclusion

The agentic era will not be limited by how fast software can be generated, but by whether organizations can trust what that software does with their data and money. Task-scoped identity, secretless execution, and verifiable audit are the foundations of that trust. A company that owns the call path for agent authority, and learns from every action that crosses it, can become the system of record for what agents are allowed to do and what they did. Lanyard is a plan to build exactly that, within 90 days to a credible launch.
