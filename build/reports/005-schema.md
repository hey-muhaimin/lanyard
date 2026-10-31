# 005 — `migrations/005_console_ops.sql`

**Status:** complete (static verification only; no database is reachable in this environment).
**File added:** `migrations/005_console_ops.sql` (167 lines).
**Files intentionally untouched:** `migrations/001_init.sql` … `004_secret_lookup.sql`,
`migrations/embed.go` (it embeds `*.sql` via a glob, so the new file is picked up without
an edit), all Go handlers, and all frontend files.

---

## Objects created

### New columns (additive, `IF NOT EXISTS`)

| Table | Column | Type / default |
| --- | --- | --- |
| `tenants` | `contact_email` | `TEXT` (nullable) |
| `tenants` | `status` | `TEXT NOT NULL DEFAULT 'active'` |
| `tenants` | `settings` | `JSONB NOT NULL DEFAULT '{}'::JSONB` |
| `approval_requests` | `parameters` | `JSONB NOT NULL DEFAULT '{}'::JSONB` |
| `approval_requests` | `requested_by` | `TEXT` (nullable) |

### New tables

1. **`ops_members`** — `id UUID PK DEFAULT gen_random_uuid()`, `email TEXT NOT NULL`,
   `role TEXT NOT NULL`, `status TEXT NOT NULL DEFAULT 'active'`,
   `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.
2. **`ops_login_codes`** — `email TEXT PK`, `code_hash BYTEA NOT NULL`,
   `expires_at TIMESTAMPTZ NOT NULL`, `attempts INT NOT NULL DEFAULT 0`,
   `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`. (Mirror of `login_codes`.)
3. **`ops_sessions`** — `token_hash BYTEA PK`, `member_id UUID NOT NULL REFERENCES
   ops_members(id) ON DELETE CASCADE`, `created_at`, `last_seen_at`, `expires_at`
   (all `TIMESTAMPTZ NOT NULL`, timestamps default `NOW()`). (Mirror of `sessions`, no tenant column.)
4. **`ops_actions`** — `id UUID PK DEFAULT gen_random_uuid()`, `type TEXT NOT NULL`,
   `tenant_id TEXT NOT NULL`, `reason TEXT NOT NULL`, `requested_by TEXT NOT NULL`,
   `status TEXT NOT NULL DEFAULT 'pending'`, `decided_by TEXT`, `decided_at TIMESTAMPTZ`,
   `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `expires_at TIMESTAMPTZ NOT NULL`.

### Constraints (all via `pg_temp.ensure_constraint`, idempotent)

| Table | Constraint | Definition |
| --- | --- | --- |
| `tenants` | `tenants_status_chk` | `CHECK (status IN ('active','suspended'))` |
| `ops_members` | `ops_members_email_lower_chk` | `CHECK (email = lower(email))` |
| `ops_members` | `ops_members_email_key` | `UNIQUE (email)` |
| `ops_members` | `ops_members_role_chk` | `CHECK (role IN ('ops_admin','ops_oncall','ops_support'))` |
| `ops_members` | `ops_members_status_chk` | `CHECK (status IN ('active','suspended'))` |
| `ops_actions` | `ops_actions_type_chk` | `CHECK (type IN ('suspend_tenant','rotate_signing_key','view_as_customer'))` |
| `ops_actions` | `ops_actions_reason_chk` | `CHECK (length(reason) >= 20)` |
| `ops_actions` | `ops_actions_status_chk` | `CHECK (status IN ('pending','executed','denied','expired'))` |
| `ops_actions` | `ops_actions_no_self_decide_chk` | `CHECK (decided_by IS NULL OR decided_by <> requested_by)` |

Primary keys are implicit (`ops_members_pkey`, `ops_login_codes_pkey`, `ops_sessions_pkey`,
`ops_actions_pkey`).

### Indexes

- `ops_sessions_member_idx` on `ops_sessions (member_id)`
- `ops_actions_status_created_idx` on `ops_actions (status, created_at)`

### Functions (all `SECURITY DEFINER`, `SET search_path = pg_catalog, public`)

| Function | Returns | Notes |
| --- | --- | --- |
| `ops_request_login(p_email text, p_hash bytea, p_expires timestamptz)` | `boolean` | active member only; 30-second throttle; upsert on `email` |
| `ops_verify_login(p_email text, p_hash bytea)` | `TABLE(member_id uuid, role text)` | `FOR UPDATE`, max 5 attempts, deletes the code on success |
| `ops_create_session(p_token bytea, p_member uuid, p_expires timestamptz)` | `void` | inserts only for an active member |
| `ops_get_session(p_token bytea, p_idle interval)` | `TABLE(member_id uuid, email text, role text)` | refreshes `last_seen_at`; expiry + idle + active checks |
| `ops_end_session(p_token bytea)` | `void` | deletes by `token_hash` |

`REVOKE ALL … FROM PUBLIC` and `GRANT EXECUTE … TO lanyard_app` on all five.

### Grants

- `GRANT SELECT, INSERT, UPDATE ON ops_members, ops_actions TO lanyard_app`
- `REVOKE ALL ON ops_sessions, ops_login_codes FROM PUBLIC` and `FROM lanyard_app`
  (no table-level access; these are function-only).
- No new grant on `tenants`; the existing `SELECT` from 002 already covers the new columns.

### RLS

- **None added.** `ops_members`, `ops_login_codes`, `ops_sessions`, `ops_actions` intentionally
  have no RLS (platform-scoped by design, per spec).
- `tenants` keeps its existing state from 002 (RLS enabled with only the `tenant_self` SELECT
  policy). No new policy is created in 005.
- No `CREATE POLICY` / `ENABLE ROW LEVEL SECURITY` statement exists in this file.

### Idempotency note

`pg_temp.ensure_constraint` is defined in 002 **inside the migration session's temp schema**.
On a *fresh* database the whole chain runs in one session and the helper exists; on an
*incremental* production deploy (001–004 already applied, only 005 pending) 002 is skipped and
the helper would be missing. 005 therefore re-declares it with `CREATE OR REPLACE FUNCTION
pg_temp.ensure_constraint(…)` (same signature) before first use. This is a re-assert, not a
modification of 002.

---

## Tenant isolation argument

- **`ops_*` is a platform control plane, not tenant data.** It must see all tenants, so it is
  deliberately *not* RLS-scoped. Isolation for these rows is the ops console's own authz layer
  (email-code → `ops_sessions` → role), plus the two-person rule enforced in
  `ops_actions_no_self_decide_chk`.
- **Sessions/codes cannot be read directly even by the app role.** `ops_sessions` and
  `ops_login_codes` receive no `SELECT`/`INSERT`/`UPDATE` grants; `lanyard_app` reaches them
  only through `SECURITY DEFINER` functions that store `sha256` hashes, never raw tokens/codes.
  The explicit `REVOKE … FROM lanyard_app` defends against any future `ALTER DEFAULT PRIVILEGES`.
- **Customer tenant data is unchanged.** `tenants` still has the 002 `tenant_self` SELECT policy
  (`id = current_tenant()`); the new `contact_email`/`status`/`settings` columns are therefore
  visible only to the owning tenant. `approval_requests` is still under the 002 `tenant_isolation`
  policy (`tenant_id = current_tenant()`), so the new `parameters`/`requested_by` columns are
  scoped the same way.
- **No unique/dedupe key is tenant-scoped because none needs to be:** `ops_members.email`,
  `ops_login_codes.email` and `ops_actions.id` are platform-global by definition. The tenant
  dedupe-key rule (sentinel finding A) applies to tenant tables; 005 adds no new tenant-scoped
  unique key.

---

## Verification performed (static; no DB available)

```
$ go build ./...
BUILD_OK

$ go test ./...
ok  github.com/example/lanyard/internal/db  0.139s
… all packages ok (exit 0)

$ awk 'length>120' migrations/005_console_ops.sql
(no output — no line exceeds 120 chars)

$ grep -n "CREATE POLICY|ENABLE ROW LEVEL" migrations/005_console_ops.sql
none (expected)

$ ensure_constraint table args
ops_actions, ops_members, tenants   (all three exist before their first use)
```

Manual re-read checks:
- Statement ordering: helper → tenant/approval columns → `ops_members` → `ops_login_codes` →
  `ops_sessions` (FK target already created) → `ops_actions` → constraints/indexes → functions
  (all after their tables) → REVOKE/GRANT. ✔
- `%ROWTYPE`: `DECLARE c ops_login_codes%ROWTYPE;` — valid composite type. ✔
- Every statement terminated with `;` (including `$$;` for each function body). ✔
- No policy is created on any table that has no RLS. ✔
- No migration 001–004 content was edited. ✔

---

## psql verification queries to run after deploy

Run as the migration/owner role (`DATABASE_URL` admin) unless noted. All are read-only.

### 1. Columns exist with the right shape

```sql
SELECT table_name, column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND (
    (table_name = 'tenants' AND column_name IN ('contact_email','status','settings'))
    OR (table_name = 'approval_requests' AND column_name IN ('parameters','requested_by'))
    OR (table_name IN ('ops_members','ops_login_codes','ops_sessions','ops_actions'))
  )
ORDER BY table_name, ordinal_position;
```

Expected: the 5 `tenants`/`approval_requests` columns plus every column of the 4 `ops_*` tables.
`tenants.status` and `.settings` must show `NO` in `is_nullable`.

### 2. Constraints exist (exact names)

```sql
SELECT e.tbl, e.name,
       EXISTS (
         SELECT 1 FROM pg_constraint c
         WHERE c.conrelid = e.tbl::regclass AND c.conname = e.name
       ) AS present,
       (SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
         WHERE c.conrelid = e.tbl::regclass AND c.conname = e.name) AS definition
FROM (VALUES
  ('tenants','tenants_status_chk'),
  ('ops_members','ops_members_email_lower_chk'),
  ('ops_members','ops_members_email_key'),
  ('ops_members','ops_members_role_chk'),
  ('ops_members','ops_members_status_chk'),
  ('ops_actions','ops_actions_type_chk'),
  ('ops_actions','ops_actions_reason_chk'),
  ('ops_actions','ops_actions_status_chk'),
  ('ops_actions','ops_actions_no_self_decide_chk')
) AS e(tbl, name)
ORDER BY e.tbl, e.name;
```

Every `present` must be `true`.

### 3. Indexes exist

```sql
SELECT indexname, tablename, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN ('ops_sessions_member_idx','ops_actions_status_created_idx');
```

### 4. Functions exist, are SECURITY DEFINER, and have the expected signatures

```sql
SELECT p.proname,
       pg_get_function_identity_arguments(p.oid) AS args,
       p.prosecdef                               AS security_definer,
       pg_get_function_result(p.oid)             AS result_type,
       p.proconfig                               AS config
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname ~ '^ops_'
ORDER BY p.proname;
```

Expected 5 rows, each `security_definer = true` and `config` containing
`search_path=pg_catalog, public`.

### 5. Function EXECUTE grants (PUBLIC revoked, app allowed)

```sql
SELECT p.proname, p.proacl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname ~ '^ops_'
ORDER BY p.proname;
```

Expected: `proacl` lists `lanyard_app=X/owner` and **no** bare `=X/…` entry (the latter would
mean PUBLIC can execute). Complement with:

```sql
SELECT p.proname,
       has_function_privilege('lanyard_app', p.oid, 'EXECUTE') AS app_can_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname ~ '^ops_'
ORDER BY p.proname;
```

Every `app_can_execute` must be `true`.

### 6. Table grants (app has ops_members/ops_actions only; no direct sessions/codes access)

```sql
SELECT t,
       has_table_privilege('lanyard_app', t, 'SELECT') AS can_select,
       has_table_privilege('lanyard_app', t, 'INSERT') AS can_insert,
       has_table_privilege('lanyard_app', t, 'UPDATE') AS can_update,
       has_table_privilege('lanyard_app', t, 'DELETE') AS can_delete
FROM (VALUES
  ('ops_members'), ('ops_actions'), ('ops_sessions'), ('ops_login_codes')
) AS v(t)
ORDER BY t;
```

Expected:

| table | select | insert | update | delete |
| --- | --- | --- | --- | --- |
| `ops_members` | true | true | true | false |
| `ops_actions` | true | true | true | false |
| `ops_sessions` | false | false | false | false |
| `ops_login_codes` | false | false | false | false |

### 7. No RLS was enabled on `ops_*`; `tenants` policy unchanged

```sql
SELECT relname, relrowsecurity
FROM pg_class
WHERE relnamespace = 'public'::regnamespace
  AND relname LIKE 'ops\_%' ESCAPE '\'
ORDER BY relname;
-- expect relrowsecurity = false for all four

SELECT tablename, policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'tenants';
-- expect only tenant_self, cmd = SELECT
```

### 8. Migration recorded with checksum

```sql
SELECT version, name, length(checksum) AS checksum_bytes, applied_at
FROM public.schema_migrations
ORDER BY version;
```

Expected: `version = 5`, `name = '005_console_ops.sql'`, `checksum_bytes = 32`.

---

## Risks / things Sentinel and the Go work must know

1. **`/admin/tenant` PATCH is not enabled by this migration.** `tenants` has RLS enabled by 002
   with only a `SELECT` (`tenant_self`) policy, and `lanyard_app` holds only `SELECT` on `tenants`.
   An `UPDATE` from the customer control plane will fail on both privilege and RLS. The brief said
   "keep it that way, just add the columns", so 005 deliberately does **not** add an UPDATE grant
   or policy. If `PATCH /admin/tenant` is shipped as specified, a follow-up migration must add
   `GRANT UPDATE ON tenants` plus a `tenant_self` UPDATE policy — call this out loudly.
   (Alternative: perform the update through a `SECURITY DEFINER` function.)

2. **Status vocabulary mismatch between spec and schema.** The console spec's decide payload is
   `{status: "approved"|"denied"}`, but `ops_actions.status` is
   `('pending','executed','denied','expired')`. The Go layer must map `approved` → `executed`
   (or the spec must change). 005 follows the brief exactly.

3. **Two-person rule identity space.** `ops_actions_no_self_decide_chk` compares
   `decided_by <> requested_by` as text. If the API writes an email in one column and a member id
   (or differently-cased email) in the other, the check is either bypassed or wrongly rejected.
   Go must use a single identity representation (recommend canonical lowercase email for both).
   Also, the CHECK does not tie `decided_by`/`decided_at` to `status`; Go must enforce coherence.

4. **Expiry is not enforced in SQL.** `ops_actions.expires_at` has no default and no
   `CHECK (expires_at > created_at)`. The 1-hour window is the Go layer's job (set
   `expires_at = now() + interval '1 hour'` and treat `expires_at <= now()` as expired).

5. **`ops_members.email` is globally unique and must be lowercase.** Both the `UNIQUE (email)` and
   `CHECK (email = lower(email))` will reject a mixed-case bootstrap address. The startup bootstrap
   using `OPS_BOOTSTRAP_EMAIL` must `lower(trim(...))` before insert, or migration succeeds but the
   bootstrap insert fails.

6. **Shared DB role.** `lanyard_app` is the same role used by the customer control plane and now
   granted `SELECT/INSERT/UPDATE` on all platform ops rows. Any SQL-injection or over-broad query
   path in the customer plane could read/modify ops members, actions and (via functions) sessions.
   The ops listener must remain on `127.0.0.1:8082` and authz must be enforced in Go; a separate
   DB role for the ops listener is a reasonable hardening follow-up (not in scope here).

7. **`tenants.settings` is now tenant-readable.** It is granted `SELECT` through the existing
   tenants grant, so never store platform-only secrets there. It is an empty JSON object today.

8. **No DB validation was possible.** All checks are static (build + tests + source review).
   The psql queries above are the deploy-time proof; run them as part of the migration rollout
   before starting the new binaries. The `pg_temp` helper re-declaration is specifically to make
   an incremental (only-005-pending) deploy safe.

---

# Amendment 1 — tenant self-service UPDATE (`PATCH /admin/tenant`)

**Applied to the same file, in place.** 005 has not been applied to any database, so no
checksum exists for it yet; editing is safe. **Supersedes:** the "No new grant on `tenants`"
line under *Grants*, the "No new policy" line under *RLS*, and Risk 1 above.

## Statements added (`migrations/005_console_ops.sql:31-40`)

```sql
GRANT UPDATE (name, contact_email) ON tenants TO lanyard_app;

DROP POLICY IF EXISTS tenant_self_update ON tenants;
CREATE POLICY tenant_self_update ON tenants FOR UPDATE
  USING (id = current_tenant()) WITH CHECK (id = current_tenant());
```

Ordering is GRANT first, policy second. Both are re-runnable (`GRANT` is additive; the policy is
dropped-if-exists before creation). `tenant_self` (SELECT, from 002) is untouched.

**Why the grant is column-scoped:** the customer only edits `name` and `contact_email`. `id` is
immutable, `status` is owned by the ops `suspend_tenant` two-person queue, and `settings` is
platform-managed. A column grant means the app role cannot rewrite lifecycle/ownership/config even
though the one row it may update is its own. PostgreSQL permits column-level `UPDATE` grants with
RLS; the policy is applied independently of the privilege check.

`UPDATE tenants SET … WHERE id = …` also reads `id`, which needs `SELECT`; that is already covered
by 002's table-level `GRANT SELECT ON tenants`.

## psql proof that the update path works

Run as `lanyard_app` (the `TEST_DATABASE_URL` role), substituting a real tenant UUID.

```sql
BEGIN;
SET LOCAL app.tenant_id = '<tenant-a-uuid>';
UPDATE tenants SET contact_email = 'updated-by-amendment-1' WHERE id = '<tenant-a-uuid>';
-- expected: UPDATE 1
SELECT id, name, contact_email FROM tenants WHERE id = '<tenant-a-uuid>';
-- expected: one row, owning tenant only
ROLLBACK;
```

Negative cases (same session role):

```sql
BEGIN;
SET LOCAL app.tenant_id = '<tenant-a-uuid>';
UPDATE tenants SET contact_email = 'x' WHERE id = '<tenant-b-uuid>';
-- expected: UPDATE 0  (RLS USING hides tenant B)
UPDATE tenants SET status = 'suspended' WHERE id = '<tenant-a-uuid>';
-- expected: ERROR 42501 permission denied (status is not in the column grant)
UPDATE tenants SET settings = '{}'::jsonb WHERE id = '<tenant-a-uuid>';
-- expected: ERROR 42501 permission denied
ROLLBACK;

UPDATE tenants SET contact_email = 'x' WHERE id = '<tenant-a-uuid>';
-- expected (no set_config / no tenant context): UPDATE 0
```

Preflight introspection:

```sql
SELECT has_column_privilege('lanyard_app','tenants','name','UPDATE')          AS name_upd,
       has_column_privilege('lanyard_app','tenants','contact_email','UPDATE') AS email_upd,
       has_column_privilege('lanyard_app','tenants','id','UPDATE')            AS id_upd,
       has_column_privilege('lanyard_app','tenants','status','UPDATE')        AS status_upd,
       has_column_privilege('lanyard_app','tenants','settings','UPDATE')      AS settings_upd;
-- expected: true, true, false, false, false

SELECT policyname, cmd, qual, with_check FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'tenants' ORDER BY policyname;
-- expected: tenant_self (SELECT, qual id = current_tenant())
--           tenant_self_update (UPDATE, both qual and with_check id = current_tenant())
```

**Runtime contract:** the handler must execute the PATCH inside `db.WithTenant` so
`app.tenant_id` is set; otherwise the UPDATE legitimately matches 0 rows.

## Verification (static; no DB or Docker in this environment)

```
$ go build ./...
BUILD_OK

$ go test ./...
… all packages ok (exit 0), internal/db 0.158s

$ awk 'length>120' migrations/005_console_ops.sql
(no output)

$ grep -n "GRANT UPDATE|tenant_self_update" migrations/005_console_ops.sql
34:GRANT UPDATE (name, contact_email) ON tenants TO lanyard_app;
38:DROP POLICY IF EXISTS tenant_self_update ON tenants;
```

No other statement in 005 was modified.
