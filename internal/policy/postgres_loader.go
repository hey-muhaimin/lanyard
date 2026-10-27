package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/example/lanyard/internal/db"
	"github.com/jackc/pgx/v5"
)

var ErrTenantEntityNotFound = errors.New("tenant entity not found")

type TenantDB interface {
	db.TxBeginner
}

type PostgresEntityLoader struct {
	Pool TenantDB
}

func (l PostgresEntityLoader) LoadTenantEntities(ctx context.Context, tenantID, actor, connector, _ string) (cedar.EntityMap, error) {
	var entities cedar.EntityMap
	err := db.WithTenant(ctx, l.Pool, tenantID, func(tx pgx.Tx) error {
		var agentID, agentTenant, status string
		if err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, status FROM agents WHERE id::text = $1`, actor).Scan(&agentID, &agentTenant, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("load Cedar agent: %w", ErrTenantEntityNotFound)
			}
			return fmt.Errorf("load Cedar agent: %w", err)
		}
		var connectorID, connectorTenant string
		if err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text FROM connectors WHERE id::text = $1`, connector).Scan(&connectorID, &connectorTenant); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("load Cedar connector: %w", ErrTenantEntityNotFound)
			}
			return fmt.Errorf("load Cedar connector: %w", err)
		}
		if agentTenant != tenantID || connectorTenant != tenantID {
			return fmt.Errorf("loaded Cedar entities do not belong to tenant: %w", ErrTenantEntityNotFound)
		}
		encoded, err := json.Marshal([]map[string]any{
			{"uid": map[string]string{"type": "Agent", "id": agentID}, "attrs": map[string]any{"status": status, "tenantId": agentTenant}, "parents": []any{}},
			{"uid": map[string]string{"type": "Connector", "id": connectorID}, "attrs": map[string]any{"tenantId": connectorTenant}, "parents": []any{}},
		})
		if err != nil {
			return err
		}
		entities = make(cedar.EntityMap)
		if err := json.Unmarshal(encoded, &entities); err != nil {
			return fmt.Errorf("decode Cedar tenant entities: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entities, nil
}

type PublishedPolicy struct {
	Version int
	Body    []byte
}

type PublishedPolicySource interface {
	LoadPublishedPolicy(context.Context, string) (PublishedPolicy, error)
}

type PostgresPolicySource struct {
	Pool TenantDB
}

func (s PostgresPolicySource) LoadPublishedPolicy(ctx context.Context, tenantID string) (PublishedPolicy, error) {
	var policy PublishedPolicy
	err := db.WithTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version, body FROM policies WHERE tenant_id::text = $1 AND status = 'published' ORDER BY version DESC LIMIT 1`, tenantID).Scan(&policy.Version, &policy.Body)
	})
	if err != nil {
		return PublishedPolicy{}, fmt.Errorf("load published tenant policy: %w", err)
	}
	return policy, nil
}
