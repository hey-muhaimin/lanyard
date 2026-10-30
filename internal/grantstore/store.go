package grantstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/lanyard/internal/db"
)

// Store is a DB-backed registry for the grant service. All reads and writes are
// tenant-scoped: the caller must set the tenant ID on the context (key tenantID)
// and the store uses db.WithTenant to scope every query to that tenant.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a Store backed by the supplied pgx pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ValidateAgent checks that the agent exists, belongs to the current tenant, and is active.
func (s *Store) ValidateAgent(ctx context.Context, id string) error {
	tenantID := tenantFromContext(ctx)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required on context for ValidateAgent")
	}
	var status string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM agents WHERE slug = $1`, id).Scan(&status)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("unknown agent %s", id)
		}
		return fmt.Errorf("validate agent: %w", err)
	}
	if status != "active" {
		return fmt.Errorf("agent %s is not active", id)
	}
	return nil
}

// GetAgent returns the agent record for id.
func (s *Store) GetAgent(ctx context.Context, id string) (Agent, bool) {
	tenantID := tenantFromContext(ctx)
	if tenantID == "" {
		return Agent{}, false
	}
	var agent Agent
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, name, owner_subject, public_key, status
			FROM agents WHERE slug = $1
		`, id).Scan(&agent.TenantID, &agent.Name, &agent.OwnerSubject, &agent.PublicKey, &agent.Status)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, false
		}
		return Agent{}, false
	}
	return agent, true
}

// TenantForAgent returns the tenant for the agent.
func (s *Store) TenantForAgent(ctx context.Context, id string) (string, error) {
	tenantID := tenantFromContext(ctx)
	if tenantID == "" {
		return "", fmt.Errorf("tenant id is required on context for TenantForAgent")
	}
	var tenant string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id FROM agents WHERE slug = $1`, id).Scan(&tenant)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("unknown agent %s", id)
		}
		return "", fmt.Errorf("tenant for agent: %w", err)
	}
	return tenant, nil
}

// RegisterAgent inserts the agent into the store.
func (s *Store) RegisterAgent(ctx context.Context, agent Agent) error {
	return db.WithTenant(ctx, s.pool, agent.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO agents (id, tenant_id, name, owner_subject, public_key, status, slug)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, agent.ID, agent.TenantID, agent.Name, agent.OwnerSubject, agent.PublicKey, agent.Status, agent.ID)
		return err
	})
}

// CreateTenant creates a tenant in the store.
func (s *Store) CreateTenant(ctx context.Context, id, name string) error {
	return db.WithTenant(ctx, s.pool, id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
		return err
	})
}

// RegisterConnector registers a connector in the store.
func (s *Store) RegisterConnector(ctx context.Context, connector Connector) error {
	return db.WithTenant(ctx, s.pool, connector.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO connectors (id, tenant_id, kind, allowed_hosts, config)
			VALUES ($1, $2, $3, $4, $5)
		`, connector.ID, connector.TenantID, connector.Kind, connector.AllowedHosts, connector.Config)
		return err
	})
}

// Agent is the DB-backed representation of a registry.Agent.
type Agent struct {
	ID           string
	TenantID     string
	Name         string
	OwnerSubject string
	PublicKey    string
	Status       string
}

// Connector is the DB-backed representation of a registry.Connector.
type Connector struct {
	ID           string
	TenantID     string
	Kind         string
	AllowedHosts []string
	Config       map[string]any
}

// tenantFromContext extracts the tenant ID from the context.
func tenantFromContext(ctx context.Context) string {
	if v := ctx.Value(TenantKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// TenantKey is the context key for the tenant ID.
type TenantKey struct{}

// WithTenant sets the tenant ID on the context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantKey{}, tenantID)
}
