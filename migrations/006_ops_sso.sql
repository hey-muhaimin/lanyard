-- 006: bind ops staff to Cognito identities and record whether the sign-in used
-- a hardware security key. 005 stays immutable; this migration evolves it.
-- ops_* tables remain platform-scoped (no RLS) by design, matching 005.
--
-- No shipped binary calls ops_create_session/ops_get_session yet (the ops handler
-- was never mounted), so replacing them cannot break a rolling rollback.

-- pg_temp.ensure_constraint is session-scoped and defined in 002/005. Re-assert it
-- here so this migration also applies on its own (idempotent; same signature).
CREATE OR REPLACE FUNCTION pg_temp.ensure_constraint(tbl regclass, cname text, ddl text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = tbl AND conname = cname) THEN
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', tbl, cname, ddl);
  END IF;
END $$;

-- Cognito subject for SSO-provisioned members. Nullable so members provisioned by
-- hand before SSO keep working; unique when present (partial index keeps NULLs free).
ALTER TABLE ops_members ADD COLUMN IF NOT EXISTS cognito_sub TEXT;
SELECT pg_temp.ensure_constraint('ops_members', 'ops_members_cognito_sub_chk',
  $c$CHECK (cognito_sub IS NULL OR length(cognito_sub) > 0)$c$);
CREATE UNIQUE INDEX IF NOT EXISTS ops_members_cognito_sub_key
  ON ops_members (cognito_sub) WHERE cognito_sub IS NOT NULL;

-- Per-session hardware-key result, so /ops/auth/me can report it without storing
-- ID tokens anywhere.
ALTER TABLE ops_sessions ADD COLUMN IF NOT EXISTS hardware_key BOOLEAN NOT NULL DEFAULT FALSE;

-- Replace the 3-argument session creator with the 4-argument form: every session
-- must state whether a hardware key was used.
DROP FUNCTION IF EXISTS ops_create_session(bytea, uuid, timestamptz);
CREATE FUNCTION ops_create_session(p_token bytea, p_member uuid, p_expires timestamptz, p_hardware_key boolean)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO ops_sessions (token_hash, member_id, expires_at, hardware_key)
  SELECT p_token, m.id, p_expires, p_hardware_key
    FROM ops_members m
   WHERE m.id = p_member AND m.status = 'active'
$$;

-- The return type gains hardware_key, so the function must be recreated.
DROP FUNCTION IF EXISTS ops_get_session(bytea, interval);
CREATE FUNCTION ops_get_session(p_token bytea, p_idle interval)
RETURNS TABLE (member_id uuid, email text, role text, hardware_key boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
BEGIN
  RETURN QUERY
  WITH s AS (
    UPDATE ops_sessions SET last_seen_at = now()
     WHERE token_hash = p_token AND expires_at > now() AND last_seen_at > now() - p_idle
    RETURNING ops_sessions.member_id, ops_sessions.hardware_key
  )
  SELECT s.member_id, m.email, m.role, s.hardware_key
    FROM s JOIN ops_members m ON m.id = s.member_id AND m.status = 'active';
END $$;

REVOKE ALL ON FUNCTION ops_create_session(bytea, uuid, timestamptz, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION ops_get_session(bytea, interval)                      FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops_create_session(bytea, uuid, timestamptz, boolean) TO lanyard_app;
GRANT EXECUTE ON FUNCTION ops_get_session(bytea, interval)                      TO lanyard_app;
