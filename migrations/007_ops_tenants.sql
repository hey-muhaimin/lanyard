-- 007: platform-wide tenant listing for the ops console.
--
-- tenants carries the tenant_self RLS policy (id = current_tenant()), so the app
-- role sees zero rows without a tenant context. Ops staff are not a tenant, so
-- the listing is exposed through a SECURITY DEFINER function owned by the
-- migration role (the table owner), which bypasses RLS. RLS itself is unchanged
-- for every other caller.
--
-- state is derived from tenants.status only. 'over_quota' is part of the UI type
-- but no quota is stored, so this function never returns it.
-- plan is a settings->>'plan' hint with a conservative default; there is no
-- billing integration behind it.

CREATE OR REPLACE FUNCTION ops_list_tenants()
RETURNS TABLE (id text, name text, plan text, agents bigint, grants bigint, state text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT t.id::text,
         t.name,
         COALESCE(t.settings->>'plan', 'starter') AS plan,
         (SELECT count(*) FROM agents a WHERE a.tenant_id = t.id) AS agents,
         (SELECT count(*) FROM grants g
           WHERE g.tenant_id = t.id AND g.revoked_at IS NULL AND g.expires_at > now()) AS grants,
         CASE WHEN t.status = 'suspended' THEN 'suspended' ELSE 'active' END AS state
    FROM tenants t
   ORDER BY t.created_at DESC, t.id
$$;

REVOKE ALL ON FUNCTION ops_list_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops_list_tenants() TO lanyard_app;
