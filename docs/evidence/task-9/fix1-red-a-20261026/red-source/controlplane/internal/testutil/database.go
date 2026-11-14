// Package testutil owns disposable schemas for real PostgreSQL integration tests.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
	"warden/controlplane/internal/store"
)

func Database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("WARDEN_TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("WARDEN_TEST_DATABASE_URL required; run scripts/test-postgres.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	var b [12]byte
	if _, err = rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	schema := "warden_test_" + hex.EncodeToString(b[:])
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	if err = store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}
