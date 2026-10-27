package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func connectIntegration(t *testing.T, env string) *pgx.Conn {
	t.Helper()
	url := os.Getenv(env)
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s must be set in CI", env)
		}
		t.Skipf("%s not set", env)
	}
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func TestTenantIsolationSchema(t *testing.T) {
	ctx := context.Background()
	app := connectIntegration(t, "TEST_DATABASE_URL")
	admin := connectIntegration(t, "TEST_ADMIN_DATABASE_URL")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	var tenantA, tenantB, agentA string
	must(admin.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&tenantA))
	must(admin.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&tenantB))
	_, err := admin.Exec(ctx, "INSERT INTO tenants (id, name) VALUES ($1::uuid, 'a'), ($2::uuid, 'b')", tenantA, tenantB)
	must(err)
	must(admin.QueryRow(ctx, `
		INSERT INTO agents (id, tenant_id, name, owner_subject, public_key)
		VALUES (gen_random_uuid(), $1::uuid, 'agent-a', 'owner', $2)
		RETURNING id::text`, tenantA, []byte{1}).Scan(&agentA))

	t.Run("app role cannot bypass RLS and owns nothing", func(t *testing.T) {
		var super, bypass bool
		var owner, currentUser string
		must(app.QueryRow(ctx, `
			SELECT r.rolsuper, r.rolbypassrls, r.rolname
			FROM pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &currentUser))
		must(app.QueryRow(ctx, "SELECT tableowner FROM pg_tables WHERE tablename = 'agents'").Scan(&owner))
		if super || bypass || owner == currentUser {
			t.Fatalf("lanyard_app must not be superuser, BYPASSRLS or owner (super=%v bypass=%v owner=%s user=%s)", super, bypass, owner, currentUser)
		}
	})

	t.Run("no tenant set returns no rows", func(t *testing.T) {
		var count int
		must(app.QueryRow(ctx, "SELECT count(*) FROM agents").Scan(&count))
		if count != 0 {
			t.Fatalf("unscoped query saw %d agents", count)
		}
	})

	t.Run("other tenant sees nothing", func(t *testing.T) {
		must(WithTenant(ctx, app, tenantB, func(tx pgx.Tx) error {
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM agents").Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatalf("tenant B saw %d agents", count)
			}
			return nil
		}))
	})

	t.Run("cross-tenant insert is rejected", func(t *testing.T) {
		err := WithTenant(ctx, app, tenantB, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO agents (id, tenant_id, name, owner_subject, public_key)
				VALUES (gen_random_uuid(), $1::uuid, 'x', 'o', $2)`, tenantA, []byte{1})
			return err
		})
		if err == nil {
			t.Fatal("tenant B inserted an agent into tenant A")
		}
	})

	t.Run("grant cannot reference another tenant's agent", func(t *testing.T) {
		err := WithTenant(ctx, app, tenantB, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO grants (id, tenant_id, agent_id, task_id, chain_id, subject, scope, policy_version, expires_at)
				VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'task', gen_random_uuid(), 'subject', '{}'::jsonb, 1, now() + interval '1 minute')`,
				tenantB, agentA)
			return err
		})
		if err == nil {
			t.Fatal("composite foreign key did not block the cross-tenant grant")
		}
	})

	t.Run("resolve_agent finds tenant without tenant context", func(t *testing.T) {
		var tenant, status string
		must(app.QueryRow(ctx, "SELECT tenant_id::text, status FROM resolve_agent($1::uuid)", agentA).Scan(&tenant, &status))
		if tenant != tenantA || status != "active" {
			t.Fatalf("got tenant %s status %s", tenant, status)
		}
	})

	t.Run("events are append-only for app and owner", func(t *testing.T) {
		must(WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO events (tenant_id, tenant_seq, type, payload, prev_hash, hash)
				VALUES ($1::uuid, 1, 'test', '{}'::jsonb, $2, $3)`, tenantA, []byte{0}, []byte{1})
			return err
		}))
		for _, statement := range []string{"UPDATE events SET type = 'changed'", "DELETE FROM events"} {
			if err := WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, statement)
				return err
			}); err == nil {
				t.Fatalf("app role ran %q", statement)
			}
			if _, err := admin.Exec(ctx, statement); err == nil {
				t.Fatalf("owner ran %q", statement)
			}
		}
	})

	t.Run("nobody approves their own request", func(t *testing.T) {
		err := WithTenant(ctx, app, tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `
				INSERT INTO approval_requests (id, tenant_id, task_id, chain_id, requester_id, action, parameter_hash, expires_at)
				VALUES (gen_random_uuid(), $1::uuid, 'task', 'chain', 'requester', 'pay', $2, now() + interval '1 minute')`,
				tenantA, []byte{1}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `
				UPDATE approval_requests
				SET status = 'approved', decided_by = 'requester'
				WHERE requester_id = 'requester'`)
			return err
		})
		if err == nil {
			t.Fatal("self-approval was accepted")
		}
	})
}
