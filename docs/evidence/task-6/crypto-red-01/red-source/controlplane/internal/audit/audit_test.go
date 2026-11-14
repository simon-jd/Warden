package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/testutil"
)

func event() audit.Event {
	return audit.Event{TenantID: "A", Type: "test", RunID: "run", Payload: json.RawMessage(`{"z":2,"a":1}`)}
}

// Break caught: verification does not locate a modified middle entry.
func TestAuditChainDetectsTamper(t *testing.T) {
	pool := testutil.Database(t)
	log := &audit.Log{Pool: pool}
	for i := 0; i < 3; i++ {
		if _, _, err := log.Append(event()); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Verify(1, 3); err != nil {
		t.Fatal(err)
	}
	// Test database superuser deliberately bypasses the append-only guard to simulate disk/admin corruption.
	_, err := pool.Exec(context.Background(), `ALTER TABLE audit_entries DISABLE TRIGGER audit_no_mutation; UPDATE audit_entries SET canonical_event=convert_to('{"tampered":true}','UTF8') WHERE seq=2; ALTER TABLE audit_entries ENABLE TRIGGER audit_no_mutation`)
	if err != nil {
		t.Fatal(err)
	}
	var integrity *audit.IntegrityError
	if err = log.Verify(1, 3); !errors.As(err, &integrity) || integrity.Seq != 2 {
		t.Fatalf("want integrity error seq=2, got %v", err)
	}
}

// Break caught: updates/deletes/truncate erase or rewrite durable audit evidence.
func TestAppendOnlyGuards(t *testing.T) {
	p := testutil.Database(t)
	l := &audit.Log{Pool: p}
	if _, _, err := l.Append(event()); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE audit_entries SET canonical_event='{}' WHERE seq=1`, `DELETE FROM audit_entries WHERE seq=1`, `TRUNCATE audit_entries`} {
		if _, err := p.Exec(context.Background(), q); err == nil {
			t.Errorf("mutation accepted: %s", q)
		}
	}
	if err := l.Verify(1, 1); err != nil {
		t.Fatal(err)
	}
}

// Break caught: unsynchronized appends fork the chain or skip committed sequence numbers.
func TestConcurrentAppendAndCanonicalHash(t *testing.T) {
	p := testutil.Database(t)
	l := &audit.Log{Pool: p}
	seq, hash, err := l.Append(event())
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"payload":{"a":1,"z":2},"run_id":"run","tenant_id":"A","type":"test"}`
	expected := sha256.Sum256(append(make([]byte, 32), []byte(canonical)...))
	if seq != 1 || hash != expected {
		t.Fatalf("canonical hash mismatch seq=%d hash=%x expected=%x", seq, hash, expected)
	}
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := l.Append(event())
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if err = l.Verify(1, n+1); err != nil {
		t.Fatal(err)
	}
	if err = l.Verify(10, 20); err != nil {
		t.Fatal(err)
	}
	if err = l.Verify(1, n+2); err == nil {
		t.Fatal("missing terminal entry not detected")
	}
}

// Break caught: caller mutation changes a previously appended event or duplicate keys hash ambiguously.
func TestAppendSnapshotsPayloadAndRejectsAmbiguity(t *testing.T) {
	p := testutil.Database(t)
	l := &audit.Log{Pool: p}
	e := event()
	if _, _, err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	copy(e.Payload, []byte(`{"z":9,"a":8}`))
	if err := l.Verify(1, 1); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := p.QueryRow(context.Background(), "SELECT canonical_event FROM audit_entries WHERE seq=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"payload":{"a":1,"z":2},"run_id":"run","tenant_id":"A","type":"test"}` {
		t.Fatalf("mutable payload persisted: %s", raw)
	}
	for _, body := range []string{`{"a":1,"a":2}`, `{"x":{"a":1,"a":2}}`, `{} {}`, `NaN`} {
		e.Payload = json.RawMessage(body)
		if _, _, err := l.Append(e); err == nil {
			t.Errorf("ambiguous payload accepted: %s", body)
		}
	}
	if err := l.Verify(1, 1); err != nil {
		t.Fatal(err)
	}
}

// Break caught: a rolled-back head sequence is accepted when all entries still exist.
func TestVerifyDetectsHeadSequenceRollback(t *testing.T) {
	p := testutil.Database(t)
	l := &audit.Log{Pool: p}
	for i := 0; i < 3; i++ {
		if _, _, err := l.Append(event()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(context.Background(), `UPDATE audit_head SET last_seq=2 WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	var integrity *audit.IntegrityError
	if err := l.Verify(1, 3); !errors.As(err, &integrity) || integrity.Seq != 3 {
		t.Fatalf("want integrity error seq=3 for head rollback, got %v", err)
	}
}
