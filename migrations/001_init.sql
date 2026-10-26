CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  owner_subject TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  attestation JSONB NOT NULL DEFAULT '{}'::JSONB,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connectors (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  allowed_hosts TEXT[] NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE TABLE IF NOT EXISTS secrets (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  connector_id UUID NOT NULL REFERENCES connectors(id),
  ciphertext BYTEA NOT NULL,
  wrapped_dek BYTEA NOT NULL,
  kms_key_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  version INT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS grants (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  agent_id UUID NOT NULL REFERENCES agents(id),
  task_id TEXT NOT NULL,
  parent_grant_id UUID REFERENCES grants(id),
  chain_id UUID NOT NULL,
  subject TEXT NOT NULL,
  scope JSONB NOT NULL,
  policy_version INT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  task_id TEXT NOT NULL,
  chain_id TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  action TEXT NOT NULL,
  parameter_hash BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS revocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, scope_type, scope_id)
);

CREATE TABLE IF NOT EXISTS events (
  seq BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  type TEXT NOT NULL,
  payload JSONB NOT NULL,
  prev_hash BYTEA NOT NULL,
  hash BYTEA NOT NULL
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connectors USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secrets USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policies USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON grants USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approval_requests USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE revocations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON revocations USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON events USING (tenant_id = current_setting('app.tenant_id')::UUID) WITH CHECK (tenant_id = current_setting('app.tenant_id')::UUID);
CREATE INDEX IF NOT EXISTS approval_requests_tenant_task_idx ON approval_requests (tenant_id, task_id);
CREATE INDEX IF NOT EXISTS revocations_tenant_scope_idx ON revocations (tenant_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS events_tenant_seq_idx ON events (tenant_id, seq);
