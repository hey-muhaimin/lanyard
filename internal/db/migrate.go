package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 0x4c414e59415244

type migration struct {
	version int
	name    string
	sql     []byte
	hash    [sha256.Size]byte
}

// ApplyMigrations applies numbered SQL migrations in order and records their checksums.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, files fs.FS) (retErr error) {
	if pool == nil || files == nil {
		return errors.New("database pool and migration files are required")
	}

	migrations, err := loadMigrations(files)
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return errors.New("no SQL migrations found")
	}

	acquired, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer acquired.Release()
	conn := acquired.Conn()

	defer func() {
		if _, unlockErr := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID); unlockErr != nil {
			_ = conn.Close(context.Background())
			if retErr == nil {
				retErr = fmt.Errorf("unlock migrations: %w", unlockErr)
			} else {
				retErr = errors.Join(retErr, fmt.Errorf("unlock migrations: %w", unlockErr))
			}
		}
	}()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS public.schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum BYTEA NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create migration history: %w", err)
	}

	applied, err := readAppliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	for version, checksum := range applied {
		if version < 1 || version > len(migrations) {
			return fmt.Errorf("database has unknown migration version %d", version)
		}
		current := migrations[version-1]
		if checksum != current.hash {
			return fmt.Errorf("migration %s checksum differs from the applied version", current.name)
		}
	}
	for version := 1; version <= len(applied); version++ {
		if _, ok := applied[version]; !ok {
			return fmt.Errorf("migration history is incomplete: version %03d is missing", version)
		}
	}
	if len(applied) == 0 {
		initialized, err := hasLegacySchema(ctx, conn)
		if err != nil {
			return err
		}
		if initialized {
			first := migrations[0]
			if first.version != 1 {
				return errors.New("legacy schema detected but migration 001 is missing")
			}
			if err := recordMigration(ctx, conn, first); err != nil {
				return fmt.Errorf("record already-applied migration %s: %w", first.name, err)
			}
			applied[first.version] = first.hash
		}
	}

	for _, current := range migrations {
		if checksum, ok := applied[current.version]; ok {
			if checksum != current.hash {
				return fmt.Errorf("migration %s checksum differs from the applied version", current.name)
			}
			continue
		}
		if err := applyMigration(ctx, conn, current); err != nil {
			return fmt.Errorf("apply migration %s: %w", current.name, err)
		}
	}
	return nil
}

func loadMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read migration files: %w", err)
	}
	var result []migration
	seen := make(map[int]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) != 2 || len(parts[0]) < 3 {
			return nil, fmt.Errorf("migration filename %q must start with a zero-padded number and underscore", entry.Name())
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("migration filename %q has an invalid version", entry.Name())
		}
		if _, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d", version)
		}
		seen[version] = struct{}{}
		content, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		result = append(result, migration{
			version: version,
			name:    entry.Name(),
			sql:     content,
			hash:    sha256.Sum256(content),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	for i, current := range result {
		if current.version != i+1 {
			return nil, fmt.Errorf("migration sequence is incomplete: expected version %03d, found %03d", i+1, current.version)
		}
	}
	return result, nil
}

func readAppliedMigrations(ctx context.Context, conn *pgx.Conn) (map[int][sha256.Size]byte, error) {
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM public.schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read migration history: %w", err)
	}
	defer rows.Close()
	applied := make(map[int][sha256.Size]byte)
	for rows.Next() {
		var version int
		var checksum []byte
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan migration history: %w", err)
		}
		if len(checksum) != sha256.Size {
			return nil, fmt.Errorf("migration %d has an invalid checksum length", version)
		}
		var sum [sha256.Size]byte
		copy(sum[:], checksum)
		applied[version] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration history: %w", err)
	}
	return applied, nil
}

func hasLegacySchema(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var existing int
	if err := conn.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
		  AND c.relname IN ('tenants', 'agents', 'grants', 'events')`).Scan(&existing); err != nil {
		return false, fmt.Errorf("inspect legacy schema: %w", err)
	}
	if existing == 0 {
		return false, nil
	}
	if existing != 4 {
		return false, fmt.Errorf("partial legacy schema detected: found %d of 4 baseline tables", existing)
	}

	var baselinePolicy bool
	if err := conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_policies
			WHERE schemaname = 'public' AND tablename = 'grants'
			  AND policyname = 'tenant_isolation'
		)`).Scan(&baselinePolicy); err != nil {
		return false, fmt.Errorf("inspect legacy grants policy: %w", err)
	}
	if !baselinePolicy {
		return false, errors.New("legacy tables exist without the baseline grants policy")
	}
	return true, nil
}

func recordMigration(ctx context.Context, conn *pgx.Conn, current migration) error {
	_, err := conn.Exec(ctx, `
		INSERT INTO public.schema_migrations (version, name, checksum)
		VALUES ($1, $2, $3)`, current.version, current.name, current.hash[:])
	return err
}

func applyMigration(ctx context.Context, conn *pgx.Conn, current migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Conn().PgConn().Exec(ctx, string(current.sql)).ReadAll(); err != nil {
		return fmt.Errorf("execute SQL: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.schema_migrations (version, name, checksum)
		VALUES ($1, $2, $3)`, current.version, current.name, current.hash[:]); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
