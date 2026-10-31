-- E2E bootstrap for the production smoke test.
-- Placeholders substituted on the host: __TENANT__, __PUBKEY__.
INSERT INTO agents (id, tenant_id, name, owner_subject, public_key, status, slug)
VALUES (gen_random_uuid(), '__TENANT__', 'e2e-agent', 'user:ops',
        convert_to('__PUBKEY__', 'UTF8'), 'active', 'e2e-agent')
ON CONFLICT (tenant_id, slug) DO UPDATE
  SET public_key = EXCLUDED.public_key, status = 'active';

INSERT INTO policies (id, tenant_id, version, body, status)
VALUES (gen_random_uuid(), '__TENANT__', 1, $cedar$
permit (
  principal is Agent,
  action,
  resource is Resource
) when {
  principal.status == "active" &&
  principal.tenantId == context.tenantId &&
  context.connector == resource.connector &&
  context.rowLimit <= 1000 &&
  context.ttlSeconds <= 600
};
$cedar$, 'published')
ON CONFLICT (tenant_id, version) DO UPDATE
  SET body = EXCLUDED.body, status = 'published';
