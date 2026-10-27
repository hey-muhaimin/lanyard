-- 003: members, email-code sign-in and sessions for the customer console.
-- login_codes and sessions have no policy and no grants for lanyard_app: the app reaches them
-- only through the SECURITY DEFINER functions below, which store hashes, never raw codes or tokens.

CREATE TABLE IF NOT EXISTS members (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  email        TEXT NOT NULL,
  role         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active',
  mfa_enrolled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT members_email_lower_chk CHECK (email = lower(email)),
  CONSTRAINT members_email_key UNIQUE (email),           -- alpha: one tenant per email
  CONSTRAINT members_id_tenant_key UNIQUE (id, tenant_id),
  CONSTRAINT members_role_chk CHECK (role IN ('admin','security','agent_owner','approver','auditor')),
  CONSTRAINT members_status_chk CHECK (status IN ('active','suspended'))
);

CREATE TABLE IF NOT EXISTS login_codes (
  email      TEXT PRIMARY KEY,
  code_hash  BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts   INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash   BYTEA PRIMARY KEY,
  tenant_id    UUID NOT NULL,
  member_id    UUID NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (member_id, tenant_id) REFERENCES members (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS sessions_member_idx ON sessions (member_id);

ALTER TABLE members     ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions    ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON members;
CREATE POLICY tenant_isolation ON members
  USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- Issue a code for an active member; false when unknown or throttled (one code per 30 seconds).
CREATE OR REPLACE FUNCTION auth_request_login(p_email text, p_hash bytea, p_expires timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM members WHERE email = p_email AND status = 'active') THEN
    RETURN FALSE;
  END IF;
  IF EXISTS (SELECT 1 FROM login_codes WHERE email = p_email AND created_at > now() - interval '30 seconds') THEN
    RETURN FALSE;
  END IF;
  INSERT INTO login_codes (email, code_hash, expires_at) VALUES (p_email, p_hash, p_expires)
  ON CONFLICT (email) DO UPDATE
    SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = 0, created_at = now();
  RETURN TRUE;
END $$;

-- Consume the code on a match; count wrong guesses and lock the code after 5.
CREATE OR REPLACE FUNCTION auth_verify_login(p_email text, p_hash bytea)
RETURNS TABLE (member_id uuid, tenant_id uuid, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
DECLARE c login_codes%ROWTYPE;
BEGIN
  SELECT * INTO c FROM login_codes WHERE email = p_email FOR UPDATE;
  IF NOT FOUND OR c.expires_at <= now() OR c.attempts >= 5 THEN
    RETURN;
  END IF;
  IF c.code_hash <> p_hash THEN
    UPDATE login_codes SET attempts = attempts + 1 WHERE email = p_email;
    RETURN;
  END IF;
  DELETE FROM login_codes WHERE email = p_email;
  RETURN QUERY SELECT m.id, m.tenant_id, m.role FROM members m WHERE m.email = p_email AND m.status = 'active';
END $$;

CREATE OR REPLACE FUNCTION auth_create_session(p_token bytea, p_member uuid, p_expires timestamptz)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO sessions (token_hash, tenant_id, member_id, expires_at)
  SELECT p_token, m.tenant_id, m.id, p_expires FROM members m WHERE m.id = p_member AND m.status = 'active'
$$;

-- Valid while unexpired, not idle past p_idle, and the member is still active. Refreshes last_seen_at.
CREATE OR REPLACE FUNCTION auth_get_session(p_token bytea, p_idle interval)
RETURNS TABLE (tenant_id uuid, member_id uuid, email text, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
#variable_conflict use_column
BEGIN
  RETURN QUERY
  WITH s AS (
    UPDATE sessions SET last_seen_at = now()
     WHERE token_hash = p_token AND expires_at > now() AND last_seen_at > now() - p_idle
    RETURNING sessions.tenant_id, sessions.member_id
  )
  SELECT s.tenant_id, s.member_id, m.email, m.role
    FROM s JOIN members m ON m.id = s.member_id AND m.status = 'active';
END $$;

CREATE OR REPLACE FUNCTION auth_end_session(p_token bytea)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  DELETE FROM sessions WHERE token_hash = p_token
$$;

REVOKE ALL ON FUNCTION auth_request_login(text, bytea, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_verify_login(text, bytea)               FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_create_session(bytea, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_get_session(bytea, interval)            FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_end_session(bytea)                      FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_request_login(text, bytea, timestamptz) TO lanyard_app;
GRANT EXECUTE ON FUNCTION auth_verify_login(text, bytea)               TO lanyard_app;
GRANT EXECUTE ON FUNCTION auth_create_session(bytea, uuid, timestamptz) TO lanyard_app;
GRANT EXECUTE ON FUNCTION auth_get_session(bytea, interval)            TO lanyard_app;
GRANT EXECUTE ON FUNCTION auth_end_session(bytea)                      TO lanyard_app;

-- members are managed inside a tenant (RLS applies); sessions and codes are not reachable directly.
GRANT SELECT, INSERT, UPDATE ON members TO lanyard_app;
