package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/example/lanyard/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
	kms  KMS
}

func NewPostgresStore(pool *pgxpool.Pool, kms KMS) *PostgresStore {
	return &PostgresStore{pool: pool, kms: kms}
}

func (s *PostgresStore) Get(ctx context.Context, secretID, tenantID string) ([]byte, error) {
	if secretID == "" {
		return nil, errors.New("vault: secret id is required")
	}
	var record SecretRecord
	var contextVersion int
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id::text, kms_key_id, ciphertext, wrapped_dek, version, encryption_context_version
			FROM secrets
			WHERE secret_id = $1 AND status = 'active'
			ORDER BY version DESC
			LIMIT 1`, secretID).Scan(&record.TenantID, &record.KMSKeyID, &record.Ciphertext, &record.WrappedKey, &record.Version, &contextVersion)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("vault: secret %q not found", secretID)
		}
		return nil, fmt.Errorf("vault: load secret %q: %w", secretID, err)
	}
	if record.Version != secretVersion {
		return nil, fmt.Errorf("vault: secret %q has unsupported version %d: %w", secretID, record.Version, ErrUnsupportedVersion)
	}
	return openPostgresSecret(ctx, s.kms, record.KMSKeyID, record.TenantID, secretID, record.Ciphertext, record.WrappedKey, contextVersion)
}

func (s *PostgresStore) PutForConnector(ctx context.Context, keyID, tenantID, connectorID, secretID string, plaintext []byte) error {
	if tenantID == "" {
		return ErrInvalidTenant
	}
	if connectorID == "" || secretID == "" {
		return errors.New("vault: connector id and secret id are required")
	}
	ciphertext, wrappedKey, err := sealSecret(ctx, s.kms, keyID, tenantID, secretID, plaintext)
	if err != nil {
		return err
	}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		lockKey := tenantID + ":" + secretID
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			return fmt.Errorf("lock secret version: %w", err)
		}
		var version int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM secrets WHERE secret_id = $1`, secretID).Scan(&version); err != nil {
			return fmt.Errorf("read next secret version: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE secrets SET status = 'retired' WHERE secret_id = $1 AND status = 'active'`, secretID); err != nil {
			return fmt.Errorf("retire previous secret version: %w", err)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO secrets (id, tenant_id, connector_id, secret_id, ciphertext, wrapped_dek, kms_key_id, version, status, encryption_context_version)
			VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, $5, $6, $7, 'active', 2)`,
			tenantID, connectorID, secretID, ciphertext, wrappedKey, keyID, version)
		if err != nil {
			return fmt.Errorf("insert secret version: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("vault: persist secret %q: %w", secretID, err)
	}
	return nil
}

func openPostgresSecret(ctx context.Context, kms KMS, keyID, tenantID, secretID string, ciphertext, wrappedKey []byte, contextVersion int) ([]byte, error) {
	switch contextVersion {
	case 1:
		return openSecret(ctx, kms, keyID, tenantID, "", ciphertext, wrappedKey)
	case 2:
		return openSecret(ctx, kms, keyID, tenantID, secretID, ciphertext, wrappedKey)
	default:
		return nil, fmt.Errorf("vault: unsupported encryption context version %d: %w", contextVersion, ErrUnsupportedVersion)
	}
}

func (s *PostgresStore) EnsureForConnector(ctx context.Context, keyID, tenantID, connectorID, secretID string, plaintext []byte) error {
	existing, err := s.Get(ctx, secretID, tenantID)
	if err == nil {
		defer clear(existing)
		if bytes.Equal(existing, plaintext) {
			return nil
		}
	} else if !errors.Is(err, ErrSecretNotFound) {
		return err
	}
	return s.PutForConnector(ctx, keyID, tenantID, connectorID, secretID, plaintext)
}
