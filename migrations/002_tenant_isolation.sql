-- Additions to the deployed 001 schema plus tenant-isolation hardening.

CREATE FUNCTION pg_temp.ensure_constraint(tbl regclass, cname text, ddl text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = tbl AND conname = cname) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', tbl, cname, ddl);
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lanyard_app') THEN
    CREATE ROLE lanyard_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;
END $$;
ALTER ROLE lanyard_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;

CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

ALTER TABLE agents ADD COLUMN IF NOT EXISTS attestation JSONB NOT NULL DEFAULT '{}'::JSONB;

CREATE TABLE IF NOT EXISTS connectors (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  allowed_hosts TEXT[] NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::JSONB
);

ALTER TABLE connectors ADD COLUMN IF NOT EXISTS name TEXT;
WITH numbered AS (
  SELECT id, row_number() OVER (PARTITION BY tenant_id, kind ORDER BY id) AS position
  FROM connectors
  WHERE name IS NULL
)
UPDATE connectors AS c
SET name = CASE WHEN numbered.position = 1 THEN c.kind ELSE c.kind || '-' || c.id::TEXT END
FROM numbered
WHERE c.id = numbered.id;
ALTER TABLE connectors ALTER COLUMN name SET NOT NULL;
SELECT pg_temp.ensure_constraint('connectors', 'connectors_tenant_name_key', 'UNIQUE (tenant_id, name)');
SELECT pg_temp.ensure_constraint('connectors', 'connectors_id_tenant_key', 'UNIQUE (id, tenant_id)');

CREATE TABLE IF NOT EXISTS secrets (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  connector_id UUID NOT NULL REFERENCES connectors(id),
  ciphertext BYTEA NOT NULL,
  wrapped_dek BYTEA NOT NULL,
  kms_key_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE secrets ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
SELECT pg_temp.ensure_constraint('secrets', 'secrets_status_chk', $c$CHECK (status IN ('active','retired'))$c$);
SELECT pg_temp.ensure_constraint('secrets', 'secrets_connector_version_key', 'UNIQUE (connector_id, version)');
SELECT pg_temp.ensure_constraint('secrets', 'secrets_connector_tenant_fk',
  'FOREIGN KEY (connector_id, tenant_id) REFERENCES connectors (id, tenant_id)');
CREATE UNIQUE INDEX IF NOT EXISTS secrets_one_active_idx ON secrets (connector_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  version INT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  simulation_diff JSONB NOT NULL DEFAULT '[]'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, version)
);

SELECT pg_temp.ensure_constraint('policies', 'policies_status_chk',
  $c$CHECK (status IN ('draft','validated','simulated','staged','published','retired'))$c$);
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_published_idx ON policies (tenant_id) WHERE status = 'published';

ALTER TABLE grants ADD COLUMN IF NOT EXISTS parent_grant_id UUID;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS chain_id UUID;
UPDATE grants SET chain_id = gen_random_uuid() WHERE chain_id IS NULL;
ALTER TABLE grants ALTER COLUMN chain_id SET NOT NULL;
SELECT pg_temp.ensure_constraint('agents', 'agents_tenant_name_key', 'UNIQUE (tenant_id, name)');
SELECT pg_temp.ensure_constraint('agents', 'agents_id_tenant_key', 'UNIQUE (id, tenant_id)');
SELECT pg_temp.ensure_constraint('agents', 'agents_status_chk',
  $c$CHECK (status IN ('active','suspended','deleted'))$c$);
SELECT pg_temp.ensure_constraint('grants', 'grants_id_tenant_key', 'UNIQUE (id, tenant_id)');
SELECT pg_temp.ensure_constraint('grants', 'grants_agent_tenant_fk',
  'FOREIGN KEY (agent_id, tenant_id) REFERENCES agents (id, tenant_id)');
SELECT pg_temp.ensure_constraint('grants', 'grants_parent_tenant_fk',
  'FOREIGN KEY (parent_grant_id, tenant_id) REFERENCES grants (id, tenant_id)');
CREATE INDEX IF NOT EXISTS grants_tenant_expiry_idx ON grants (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS grants_tenant_chain_idx ON grants (tenant_id, chain_id);
CREATE INDEX IF NOT EXISTS grants_tenant_agent_idx ON grants (tenant_id, agent_id);

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

ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS decided_by TEXT;
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
SELECT pg_temp.ensure_constraint('approval_requests', 'approvals_status_chk',
  $c$CHECK (status IN ('pending','approved','denied','expired'))$c$);
SELECT pg_temp.ensure_constraint('approval_requests', 'approvals_no_self_approval_chk',
  'CHECK (decided_by IS NULL OR decided_by <> requester_id)');
CREATE INDEX IF NOT EXISTS approval_requests_tenant_task_idx ON approval_requests (tenant_id, task_id);

CREATE TABLE IF NOT EXISTS revocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, scope_type, scope_id)
);

SELECT pg_temp.ensure_constraint('revocations', 'revocations_scope_chk',
  $c$CHECK (scope_type IN ('agent','task','chain','token'))$c$);
CREATE INDEX IF NOT EXISTS revocations_tenant_scope_idx ON revocations (tenant_id, scope_type, scope_id);

ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_seq BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;
WITH numbered AS (
  SELECT seq, row_number() OVER (PARTITION BY tenant_id ORDER BY seq) AS position
  FROM events
)
UPDATE events AS e
SET tenant_seq = numbered.position
FROM numbered
WHERE e.seq = numbered.seq AND e.tenant_seq IS NULL;
ALTER TABLE events ALTER COLUMN tenant_seq SET NOT NULL;
SELECT pg_temp.ensure_constraint('events', 'events_tenant_seq_key', 'UNIQUE (tenant_id, tenant_seq)');
SELECT pg_temp.ensure_constraint('events', 'events_tenant_fk', 'FOREIGN KEY (tenant_id) REFERENCES tenants (id)');
CREATE INDEX IF NOT EXISTS events_tenant_seq_idx ON events (tenant_id, seq);

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['agents','connectors','secrets','policies','grants',
                           'approval_requests','revocations','events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END $$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_self ON tenants;
CREATE POLICY tenant_self ON tenants FOR SELECT USING (id = current_tenant());

CREATE OR REPLACE FUNCTION events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'events is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
DROP TRIGGER IF EXISTS events_no_change ON events;
CREATE TRIGGER events_no_change BEFORE UPDATE OR DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION events_append_only();
DROP TRIGGER IF EXISTS events_no_truncate ON events;
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
  FOR EACH STATEMENT EXECUTE FUNCTION events_append_only();

CREATE OR REPLACE FUNCTION create_tenant(p_id UUID, p_name TEXT) RETURNS UUID
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ INSERT INTO tenants (id, name) VALUES (p_id, p_name) RETURNING id $$;

CREATE OR REPLACE FUNCTION resolve_agent(p_agent UUID)
RETURNS TABLE (tenant_id UUID, public_key BYTEA, status TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS
$$ SELECT a.tenant_id, a.public_key, a.status FROM agents a WHERE a.id = p_agent $$;

REVOKE ALL ON FUNCTION create_tenant(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_agent(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_tenant(UUID, TEXT) TO lanyard_app;
GRANT EXECUTE ON FUNCTION resolve_agent(UUID) TO lanyard_app;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lanyard_app;
GRANT SELECT, INSERT, UPDATE ON agents, connectors, secrets, policies, grants,
                                approval_requests, revocations TO lanyard_app;
GRANT SELECT, INSERT ON events TO lanyard_app;
GRANT SELECT ON tenants TO lanyard_app;
GRANT USAGE ON SEQUENCE events_seq_seq TO lanyard_app;
