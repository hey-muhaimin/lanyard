package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/lanyard/internal/db"
	"github.com/jackc/pgx/v5"
)

type PostgresPolicyRepository struct {
	Pool TenantDB
}

func (r PostgresPolicyRepository) CreatePolicyVersion(ctx context.Context, policy PolicyVersion) error {
	return db.WithTenant(ctx, r.Pool, policy.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO policies (id, tenant_id, version, body, status, simulation_diff, created_at) VALUES (gen_random_uuid(), $1::uuid, $2, $3, $4, '[]'::jsonb, $5)`, policy.TenantID, policy.Version, string(policy.Body), policy.State, policy.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert policy version: %w", err)
		}
		return nil
	})
}

func (r PostgresPolicyRepository) GetPolicyVersion(ctx context.Context, tenantID string, version int) (PolicyVersion, error) {
	var policy PolicyVersion
	err := db.WithTenant(ctx, r.Pool, tenantID, func(tx pgx.Tx) error {
		var body string
		var changes []byte
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, version, body, status, simulation_diff, created_at FROM policies WHERE tenant_id = $1::uuid AND version = $2`, tenantID, version).Scan(&policy.TenantID, &policy.Version, &body, &policy.State, &changes, &policy.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("policy version not found")
			}
			return fmt.Errorf("load policy version: %w", err)
		}
		policy.Body = []byte(body)
		if err := json.Unmarshal(changes, &policy.Changes); err != nil {
			return fmt.Errorf("decode policy simulation diff: %w", err)
		}
		return nil
	})
	if err != nil {
		return PolicyVersion{}, err
	}
	return policy, nil
}

func (r PostgresPolicyRepository) SetPolicyVersionState(ctx context.Context, tenantID string, version int, state VersionState, changes []SimulationChange, expected VersionState) error {
	serialized, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("encode policy simulation diff: %w", err)
	}
	return db.WithTenant(ctx, r.Pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE policies SET status = $3, simulation_diff = $4::jsonb WHERE tenant_id = $1::uuid AND version = $2 AND status = $5`, tenantID, version, state, string(serialized), expected)
		if err != nil {
			return fmt.Errorf("update policy version state: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("policy version missing or state transition conflict")
		}
		return nil
	})
}
