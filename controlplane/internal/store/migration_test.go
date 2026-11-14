package store_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/store"
	"warden/controlplane/internal/testutil"
)

// Break caught: migration 2 drops existing queued work, rewrites its audit chain,
// fails on a real version-1 database, or cannot be safely reapplied.
func TestExecutionMigrationPreservesVersionOneRunsAndAudit(t *testing.T) {
	ctx := context.Background()
	pool := testutil.Database(t)
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// Reconstruct version 1 from the shipped DDL in this test's disposable schema.
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "DROP SCHEMA "+name+" CASCADE; CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	ddl, err := os.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "CREATE TABLE schema_migrations(version integer PRIMARY KEY); INSERT INTO schema_migrations VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	s := &runs.Store{Pool: pool}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "legacy-tenant", "legacy-key", spec)
	if err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err = pool.QueryRow(ctx, "SELECT hash FROM audit_entries WHERE seq=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = store.Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	run, err := s.Get(ctx, "legacy-tenant", id)
	if err != nil || run.State != "queued" || run.Logs.Status != "pending" || string(run.Spec) != string(spec) {
		t.Fatalf("legacy run changed: %+v %v", run, err)
	}
	var after []byte
	if err = pool.QueryRow(ctx, "SELECT hash FROM audit_entries WHERE seq=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("legacy audit hash changed")
	}
	if err = (&audit.Log{Pool: pool}).Verify(1, 1); err != nil {
		t.Fatal(err)
	}
}

// Break caught: adding durable JIT state rewrites existing runs/audit or cannot
// upgrade an actual version-two database and be safely reapplied.
func TestJITMigrationPreservesVersionTwoRunsAndAudit(t *testing.T) {
	ctx := context.Background()
	pool := testutil.Database(t)
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	name := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "DROP SCHEMA "+name+" CASCADE; CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"migrations/001_init.sql", "migrations/002_execution.sql"} {
		ddl, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(ddl)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, "CREATE TABLE schema_migrations(version integer PRIMARY KEY); INSERT INTO schema_migrations VALUES(1),(2)"); err != nil {
		t.Fatal(err)
	}
	s := &runs.Store{Pool: pool}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "legacy-tenant", "legacy-v2-key", spec)
	if err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err = pool.QueryRow(ctx, "SELECT hash FROM audit_entries WHERE seq=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = store.Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	run, err := s.Get(ctx, "legacy-tenant", id)
	if err != nil || run.State != "queued" || string(run.Spec) != string(spec) {
		t.Fatalf("legacy run changed: %+v %v", run, err)
	}
	var after []byte
	if err = pool.QueryRow(ctx, "SELECT hash FROM audit_entries WHERE seq=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("legacy audit changed")
	}
	if err = (&audit.Log{Pool: pool}).Verify(1, 1); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM jit_requests").Scan(&count); err != nil || count != 0 {
		t.Fatalf("new JIT table: count=%d error=%v", count, err)
	}
}
