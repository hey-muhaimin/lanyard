package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type TxBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// WithTenant scopes every query in fn to the supplied tenant for this transaction.
func WithTenant(ctx context.Context, pool TxBeginner, tenantID string, fn func(pgx.Tx) error) error {
	if pool == nil || tenantID == "" || fn == nil {
		return errors.New("database pool, tenant ID, and transaction function are required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant transaction context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}
