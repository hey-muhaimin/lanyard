UPDATE agents SET slug = id::text WHERE slug IS NULL OR slug = '';

ALTER TABLE secrets ADD COLUMN IF NOT EXISTS secret_id TEXT;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS encryption_context_version SMALLINT NOT NULL DEFAULT 1;

UPDATE secrets AS s
SET secret_id = COALESCE(NULLIF(c.name, ''), s.connector_id::text)
FROM connectors AS c
WHERE c.id = s.connector_id AND s.secret_id IS NULL;

UPDATE secrets
SET secret_id = connector_id::text
WHERE secret_id IS NULL;

ALTER TABLE secrets ALTER COLUMN secret_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS secrets_tenant_secret_version_key
  ON secrets (tenant_id, secret_id, version);
CREATE UNIQUE INDEX IF NOT EXISTS secrets_one_active_secret_id_idx
  ON secrets (tenant_id, secret_id) WHERE status = 'active';