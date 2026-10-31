package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/example/lanyard/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLegacySchemaUpgradePreservesData(t *testing.T) {
	ctx := context.Background()
	adminURL := os.Getenv("TEST_ADMIN_DATABASE_URL")
	if adminURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("TEST_ADMIN_DATABASE_URL must be set in CI")
		}
		t.Skipf("TEST_ADMIN_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	admin := pool

	// Reset schema to simulate a fresh pre-versioning database
	if _, err := admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO PUBLIC;
	`); err != nil {
		t.Fatal(err)
	}

	// Create legacy schema matching the pre-versioning baseline
	if _, err := admin.Exec(ctx, `
		CREATE TABLE tenants (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE agents (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES tenants(id),
			name TEXT NOT NULL,
			owner_subject TEXT NOT NULL,
			public_key BYTEA NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE grants (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES tenants(id),
			agent_id UUID NOT NULL REFERENCES agents(id),
			task_id TEXT NOT NULL,
			subject TEXT NOT NULL,
			scope JSONB NOT NULL,
			policy_version INT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ NULL
		);

		CREATE TABLE events (
			seq BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL,
			ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			type TEXT NOT NULL,
			payload JSONB NOT NULL,
			prev_hash BYTEA NOT NULL,
			hash BYTEA NOT NULL
		);

		ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
		CREATE POLICY tenant_isolation ON grants
			USING (tenant_id = current_setting('app.tenant_id')::UUID);
	`); err != nil {
		t.Fatal(err)
	}

	var tenantID string
	var agentID string
	var grantID string
	if err := admin.QueryRow(ctx, `INSERT INTO tenants (id, name) VALUES (gen_random_uuid(), 'legacy-tenant') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		INSERT INTO agents (id, tenant_id, name, owner_subject, public_key)
		VALUES (gen_random_uuid(), $1::uuid, 'legacy-agent', 'owner', $2)
		RETURNING id::text`, tenantID, []byte{0x01, 0x02}).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		INSERT INTO grants (id, tenant_id, agent_id, task_id, subject, scope, policy_version, expires_at)
		VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'task-legacy', 'user:alice', '{"actions":["read"]}'::jsonb, 1, now() + interval '1 day')
		RETURNING id::text`, tenantID, agentID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}

	// Run versioned migrations against legacy schema
	if err := ApplyMigrations(ctx, admin, migrations.Files); err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}

	// Verify data survived
	var countTenants, countAgents, countGrants int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE id = $1::uuid", tenantID).Scan(&countTenants); err != nil {
		t.Fatal(err)
	}
	if countTenants != 1 {
		t.Fatalf("tenant lost: %d", countTenants)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid", agentID, tenantID).Scan(&countAgents); err != nil {
		t.Fatal(err)
	}
	if countAgents != 1 {
		t.Fatalf("agent lost: %d", countAgents)
	}
	var agentSlug string
	if err := admin.QueryRow(ctx, "SELECT slug FROM agents WHERE id = $1::uuid", agentID).Scan(&agentSlug); err != nil {
		t.Fatal(err)
	}
	if agentSlug != agentID {
		t.Fatalf("legacy agent slug = %q, want stable id %q", agentSlug, agentID)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM grants WHERE id = $1::uuid AND tenant_id = $2::uuid AND agent_id = $3::uuid", grantID, tenantID, agentID).Scan(&countGrants); err != nil {
		t.Fatal(err)
	}
	if countGrants != 1 {
		t.Fatalf("grant lost: %d", countGrants)
	}

	// Verify all migrations are recorded
	rows, err := admin.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var applied []int
	for rows.Next() {
		var v int
		var name string
		var checksum []byte
		if err := rows.Scan(&v, &name, &checksum); err != nil {
			t.Fatal(err)
		}
		applied = append(applied, v)
		if len(checksum) != sha256.Size {
			t.Fatalf("invalid checksum length for %s", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	migrationCount := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			migrationCount++
		}
	}
	if len(applied) != migrationCount {
		t.Fatalf("expected %d migrations recorded, got %v", migrationCount, applied)
	}

	// Second run must be safe (idempotent)
	if err := ApplyMigrations(ctx, admin, migrations.Files); err != nil {
		t.Fatalf("second ApplyMigrations() error = %v", err)
	}

	// Verify still the same data
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE id = $1::uuid", tenantID).Scan(&countTenants); err != nil {
		t.Fatal(err)
	}
	if countTenants != 1 {
		t.Fatalf("tenant lost after second run: %d", countTenants)
	}
}

// Helper to ensure hex import isn't unused if needed
var _ = hex.EncodeToString
