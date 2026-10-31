-- 005: customer-console tenant profile fields and the platform ops console.
-- tenants is not tenant-scoped RLS-wise for the new columns: it already uses the
-- tenant_self SELECT policy from 002. ops_* tables are platform-scoped by design,
-- so they deliberately have no RLS; sessions and login codes are reachable only
-- through the SECURITY DEFINER functions below (hashes are stored, never raw).
--
-- The tenants UPDATE grant below is deliberately column-scoped to
-- (name, contact_email). Those are the only fields a customer edits from
-- PATCH /admin/tenant; id is immutable, status is driven only by the ops
-- two-person queue (suspend_tenant), and settings is platform-managed. Keeping
-- the grant narrow means the app role can never rewrite ownership, lifecycle or
-- platform config even though the row it may update is its own.

-- pg_temp.ensure_constraint is session-scoped and lives in 002. On an incremental
-- deploy 002 is skipped, so re-assert it here (idempotent; same signature).
CREATE OR REPLACE FUNCTION pg_temp.ensure_constraint(tbl regclass, cname text, ddl text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = tbl AND conname = cname) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', tbl, cname, ddl);
  END IF;
END $$;

-- Customer tenant profile.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact_email TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'::JSONB;
SELECT pg_temp.ensure_constraint('tenants', 'tenants_status_chk',
  $c$CHECK (status IN ('active','suspended'))$c$);

-- Customer self-service profile edits: the app role may update only its own
-- row, and only the two profile columns. id/status/settings stay unwritable
-- (see the header comment for why the column grant is narrow).
GRANT UPDATE (name, contact_email) ON tenants TO lanyard_app;

-- Pair the column grant with a self-scoped UPDATE policy; the 002 tenant_self
-- SELECT policy is left untouched.
DROP POLICY IF EXISTS tenant_self_update ON tenants;
CREATE POLICY tenant_self_update ON tenants FOR UPDATE
  USING (id = current_tenant()) WITH CHECK (id = current_tenant());

-- Approval request payload surfaced by the customer console.
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS parameters JSONB NOT NULL DEFAULT '{}'::JSONB;
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS requested_by TEXT;

-- Ops members. Email is globally unique (not tenant-scoped): ops staff are per platform.
CREATE TABLE IF NOT EXISTS ops_members (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email      TEXT NOT NULL,
  role       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT pg_temp.ensure_constraint('ops_members', 'ops_members_email_lower_chk',
  $c$CHECK (email = lower(email))$c$);
SELECT pg_temp.ensure_constraint('ops_members', 'ops_members_email_key', 'UNIQUE (email)');
SELECT pg_temp.ensure_constraint('ops_members', 'ops_members_role_chk',
  $c$CHECK (role IN ('ops_admin','ops_oncall','ops_support'))$c$);
SELECT pg_temp.ensure_constraint('ops_members', 'ops_members_status_chk',
  $c$CHECK (status IN ('active','suspended'))$c$);

-- Mirror of login_codes: one outstanding code per email, hashed at rest.
CREATE TABLE IF NOT EXISTS ops_login_codes (
  email      TEXT PRIMARY KEY,
  code_hash  BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts   INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Mirror of sessions, keyed by member instead of (member, tenant).
CREATE TABLE IF NOT EXISTS ops_sessions (
  token_hash   BYTEA PRIMARY KEY,
  member_id    UUID NOT NULL REFERENCES ops_members(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ops_sessions_member_idx ON ops_sessions (member_id);

-- Two-person write queue. tenant_id stays TEXT: it is a lookup key, not an FK,
-- and ops actions may target a tenant that no longer exists.
CREATE TABLE IF NOT EXISTS ops_actions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type         TEXT NOT NULL,
  tenant_id    TEXT NOT NULL,
  reason       TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  decided_by   TEXT,
  decided_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL
);

SELECT pg_temp.ensure_constraint('ops_actions', 'ops_actions_type_chk',
  $c$CHECK (type IN ('suspend_tenant','rotate_signing_key','view_as_customer'))$c$);
SELECT pg_temp.ensure_constraint('ops_actions', 'ops_actions_reason_chk',
  'CHECK (length(reason) >= 20)');
SELECT pg_temp.ensure_constraint('ops_actions', 'ops_actions_status_chk',
  $c$CHECK (status IN ('pending','executed','denied','expired'))$c$);
SELECT pg_temp.ensure_constraint('ops_actions', 'ops_actions_no_self_decide_chk',
  'CHECK (decided_by IS NULL OR decided_by <> requested_by)');
CREATE INDEX IF NOT EXISTS ops_actions_status_created_idx ON ops_actions (status, created_at);

-- Ops auth functions mirror 003. Every failure path returns empty/false rather
-- than raising, so callers get no enumeration signal.
CREATE OR REPLACE FUNCTION ops_request_login(p_email text, p_hash bytea, p_expires timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ops_members WHERE email = p_email AND status = 'active') THEN
    RETURN FALSE;
  END IF;
  IF EXISTS (SELECT 1 FROM ops_login_codes WHERE email = p_email AND created_at > now() - interval '30 seconds') THEN
    RETURN FALSE;
  END IF;
  INSERT INTO ops_login_codes (email, code_hash, expires_at) VALUES (p_email, p_hash, p_expires)
  ON CONFLICT (email) DO UPDATE
    SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = 0, created_at = now();
  RETURN TRUE;
END $$;

CREATE OR REPLACE FUNCTION ops_verify_login(p_email text, p_hash bytea)
RETURNS TABLE (member_id uuid, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE c ops_login_codes%ROWTYPE;
BEGIN
  SELECT * INTO c FROM ops_login_codes WHERE email = p_email FOR UPDATE;
  IF NOT FOUND OR c.expires_at <= now() OR c.attempts >= 5 THEN
    RETURN;
  END IF;
  IF c.code_hash <> p_hash THEN
    UPDATE ops_login_codes SET attempts = attempts + 1 WHERE email = p_email;
    RETURN;
  END IF;
  DELETE FROM ops_login_codes WHERE email = p_email;
  RETURN QUERY SELECT m.id, m.role FROM ops_members m WHERE m.email = p_email AND m.status = 'active';
END $$;

CREATE OR REPLACE FUNCTION ops_create_session(p_token bytea, p_member uuid, p_expires timestamptz)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO ops_sessions (token_hash, member_id, expires_at)
  SELECT p_token, m.id, p_expires FROM ops_members m WHERE m.id = p_member AND m.status = 'active'
$$;

-- Valid while unexpired, not idle past p_idle, and the member is still active. Refreshes last_seen_at.
CREATE OR REPLACE FUNCTION ops_get_session(p_token bytea, p_idle interval)
RETURNS TABLE (member_id uuid, email text, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
BEGIN
  RETURN QUERY
  WITH s AS (
    UPDATE ops_sessions SET last_seen_at = now()
     WHERE token_hash = p_token AND expires_at > now() AND last_seen_at > now() - p_idle
    RETURNING ops_sessions.member_id
  )
  SELECT s.member_id, m.email, m.role
    FROM s JOIN ops_members m ON m.id = s.member_id AND m.status = 'active';
END $$;

CREATE OR REPLACE FUNCTION ops_end_session(p_token bytea)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  DELETE FROM ops_sessions WHERE token_hash = p_token
$$;

REVOKE ALL ON FUNCTION ops_request_login(text, bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops_verify_login(text, bytea)               FROM PUBLIC;
REVOKE ALL ON FUNCTION ops_create_session(bytea, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops_get_session(bytea, interval)            FROM PUBLIC;
REVOKE ALL ON FUNCTION ops_end_session(bytea)                      FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops_request_login(text, bytea, timestamptz) TO lanyard_app;
GRANT EXECUTE ON FUNCTION ops_verify_login(text, bytea)               TO lanyard_app;
GRANT EXECUTE ON FUNCTION ops_create_session(bytea, uuid, timestamptz) TO lanyard_app;
GRANT EXECUTE ON FUNCTION ops_get_session(bytea, interval)            TO lanyard_app;
GRANT EXECUTE ON FUNCTION ops_end_session(bytea)                      TO lanyard_app;

-- ops_members/ops_actions are platform-scoped and read/written directly by the ops API.
-- sessions and login codes are function-only: revoke explicitly so no default
-- privilege ever exposes them, and grant nothing.
REVOKE ALL ON ops_sessions, ops_login_codes FROM PUBLIC;
REVOKE ALL ON ops_sessions, ops_login_codes FROM lanyard_app;
GRANT SELECT, INSERT, UPDATE ON ops_members, ops_actions TO lanyard_app;
