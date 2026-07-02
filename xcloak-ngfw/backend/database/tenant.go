package database

// WithTenantTx opens a transaction, sets the per-transaction GUC that RLS
// policies check (app.tenant_id), calls fn, and commits or rolls back.
//
// Use this for any query path where you need the PostgreSQL RLS safety net
// in addition to the application-level WHERE tenant_id = $N clause.
//
//	err := database.WithTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
//	    _, err := tx.Exec(`DELETE FROM agents WHERE id = $1`, agentID)
//	    return err
//	})
//
// SET LOCAL resets automatically when the transaction ends, making it safe
// under PgBouncer transaction pooling — the server connection is recycled
// clean after each commit/rollback.

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// WithTenantTx runs fn inside a transaction scoped to tenantID.
// The GUC app.tenant_id is set with SET LOCAL so it lasts only for this
// transaction and cannot bleed into subsequent uses of the same connection.
func WithTenantTx(ctx context.Context, tenantID int, fn func(*sql.Tx) error) error {
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("WithTenantTx begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // superseded by Commit below

	if _, err := tx.ExecContext(ctx,
		"SET LOCAL app.tenant_id = "+strconv.Itoa(tenantID),
	); err != nil {
		return fmt.Errorf("WithTenantTx set tenant: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// SetTenantLocal sets the app.tenant_id GUC on an already-open transaction.
// Use when you need to set the context on a tx you opened yourself.
func SetTenantLocal(ctx context.Context, tx *sql.Tx, tenantID int) error {
	_, err := tx.ExecContext(ctx,
		"SET LOCAL app.tenant_id = "+strconv.Itoa(tenantID),
	)
	return err
}
