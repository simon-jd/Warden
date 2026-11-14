package store

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_init.sql
var initialSchema string

//go:embed migrations/002_execution.sql
var executionSchema string

//go:embed migrations/003_jit.sql
var jitSchema string

//go:embed migrations/004_scim.sql
var scimSchema string

// Migrate applies versioned DDL atomically. The advisory lock serializes startup.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(74617264656)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)`); err != nil {
		return err
	}
	for i, schema := range []string{initialSchema, executionSchema, jitSchema, scimSchema} {
		version := i + 1
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err = tx.Exec(ctx, schema); err != nil {
				return fmt.Errorf("migration %d: %w", version, err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
