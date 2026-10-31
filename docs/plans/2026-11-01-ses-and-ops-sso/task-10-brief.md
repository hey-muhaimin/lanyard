# Task 10 — Migration 007: `ops_list_tenants()`

**Where this fits:** `/ops/tenants` must list **all** tenants. `tenants` has the
`tenant_self` RLS policy (`id = current_tenant()`), and ops staff have no tenant context,
so a plain `SELECT ... FROM tenants` returns zero rows. A SECURITY DEFINER function is the
only correct fix that keeps RLS intact for everyone else.

**Depends on:** nothing (005 already added `status`/`settings` to `tenants`).
**Blocks:** 13.

## Files

- `migrations/007_ops_tenants.sql` (create only)

## Shape returned to the ops UI

`web/ops/src/lib/types.ts` expects exactly:

```ts
{ id: string; name: string; plan: string; agents: number; grants: number;
  state: "active" | "suspended" | "over_quota" }
```

The database has no `plan` column and no quota concept. Pinned mapping:

| JSON field | Source |
|---|---|
| `id` | `tenants.id::text` |
| `name` | `tenants.name` |
| `plan` | `COALESCE(settings->>'plan', 'starter')` |
| `agents` | count of rows in `agents` for the tenant |
| `grants` | count of rows in `grants` for the tenant that are unrevoked and unexpired |
| `state` | `'suspended'` when `tenants.status = 'suspended'`, else `'active'` |

`over_quota` is never produced — no quota is stored anywhere, so inventing one would be a
lie. Say so in the migration comment.

## Exact file content

```sql
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
```

Do not touch the `tenant_self` / `tenant_self_update` policies or the `tenants` grants.

## Verification

With a migrated database:

```sh
export DATABASE_URL='postgres://lanyard:lanyard@localhost:5432/lanyard?sslmode=disable'
go run ./cmd/migrate
```

Then, **as the app role** (this is the case that matters — the direct `SELECT` must still
be empty):

```sh
psql "postgres://lanyard_app:...@localhost:5432/lanyard" \
  -c 'SELECT count(*) FROM tenants;' \
  -c 'SELECT * FROM ops_list_tenants();'
```

Expect the first query to return `0` and the second to return every tenant with a
non-null `plan`, integer counts and `state` in (`active`, `suspended`).

Also confirm the function signature and owner:

```sh
psql "$DATABASE_URL" -c '\df ops_list_tenants'
```

Then `go run ./cmd/migrate` again → "database migrations are up to date", and
`go test ./...` (CI migrates a fresh database).
