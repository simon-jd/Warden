package runs_test

import (
	"context"
	"errors"
	"testing"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/testutil"
	"warden/runtimes"
	"warden/runtimes/gate"
)

// Break caught: two durable claimants can execute one queued run, or old owners overwrite recovery.
func TestDurableClaimAndFencedTransitions(t *testing.T) {
	ctx := context.Background()
	s := &runs.Store{Pool: testutil.Database(t)}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "A", "claim", spec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Close()
	if claim.Recovery {
		t.Fatal("queued claim marked recovery")
	}
	if second, err := s.Claim(ctx, id, "node-A"); !errors.Is(err, runs.ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second claim: %v", err)
	}
	if err := claim.Running(ctx); err != nil {
		t.Fatal(err)
	}
	claim.Close()
	recovered, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !recovered.Recovery {
		t.Fatal("running run was eligible to restart")
	}
	if err := recovered.Finish(ctx, runs.Completion{State: "interrupted", ErrorCode: "worker_lost", Logs: runs.Logs{Status: "lost", Lines: []string{}}}); err != nil {
		t.Fatal(err)
	}
	if err := claim.Finish(ctx, runs.Completion{State: "succeeded"}); !errors.Is(err, runs.ErrStale) {
		t.Fatalf("stale write: %v", err)
	}
	run, err := s.Get(ctx, "A", id)
	if err != nil || run.State != "interrupted" || run.Logs.Status != "lost" {
		t.Fatalf("run=%+v err=%v", run, err)
	}
	var n uint64
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_entries").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("audit events %d", n)
	}
	if err := (&audit.Log{Pool: s.Pool}).Verify(1, n); err != nil {
		t.Fatal(err)
	}
}

// Break caught: the same recovery owner overwrites a final result after completion.
func TestRecoveryClaimCannotOverwriteTerminalResult(t *testing.T) {
	ctx := context.Background()
	s := &runs.Store{Pool: testutil.Database(t)}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "A", "terminal", spec)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	recovery, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	if err = recovery.Finish(ctx, runs.Completion{State: "interrupted", Logs: runs.Logs{Status: "lost"}}); err != nil {
		t.Fatal(err)
	}
	if err = recovery.Finish(ctx, runs.Completion{State: "failed", ErrorCode: "overwrite", Logs: runs.Logs{Status: "lost"}}); !errors.Is(err, runs.ErrStale) {
		t.Fatalf("terminal overwrite allowed: %v", err)
	}
}

// Break caught: a launch can be marked successful before running or while its
// cgroup is populated, making a cleanup failure look like successful completion.
func TestSuccessRequiresRunningAndCleanExit(t *testing.T) {
	ctx := context.Background()
	s := &runs.Store{Pool: testutil.Database(t)}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "A", "success", spec)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	complete := runs.Completion{State: "succeeded", Result: &runtimes.Exit{CgroupEmpty: true}, Logs: runs.Logs{Status: "complete"}}
	if err = c.Finish(ctx, complete); err == nil {
		t.Fatal("success before running accepted")
	}
	if err = c.Running(ctx); err != nil {
		t.Fatal(err)
	}
	complete.Result.CgroupEmpty = false
	if err = c.Finish(ctx, complete); err == nil {
		t.Fatal("populated cgroup success accepted")
	}
	complete.Result.CgroupEmpty = true
	if err = c.Finish(ctx, complete); err != nil {
		t.Fatal(err)
	}
}

// Break caught: a caller's zero proof clears pending state without original
// authority/run-bound kernel evidence or a recovery claim.
func TestForgedReconciliationCannotClearPending(t *testing.T) {
	ctx := context.Background()
	s := &runs.Store{Pool: testutil.Database(t)}
	spec, err := runs.Normalize([]byte(`{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx, "A", "forged-proof", spec)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Finish(ctx, runs.Completion{State: "failed", ErrorCode: "runtime_start_ambiguous", CleanupPending: true, Logs: runs.Logs{Status: "lost"}}); err != nil {
		t.Fatal(err)
	}
	first.Close()
	recovery, err := s.Claim(ctx, id, "node-A")
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	for _, proof := range []*gate.Reconciliation{nil, new(gate.Reconciliation)} {
		if err = recovery.Finish(ctx, runs.Completion{State: "interrupted", ErrorCode: "node_retired", Logs: runs.Logs{Status: "lost"}, Reconciliation: proof}); err == nil {
			t.Fatal("forged proof accepted")
		}
	}
	if err = recovery.Finish(ctx, runs.Completion{State: "interrupted", ErrorCode: "worker_lost", Logs: runs.Logs{Status: "lost"}}); err == nil {
		t.Fatal("boolean cleanup cleared ambiguity")
	}
	if err = recovery.Finish(ctx, runs.Completion{State: "failed", ErrorCode: "cleanup_failed", CleanupPending: true, Logs: runs.Logs{Status: "lost"}}); err == nil {
		t.Fatal("ambiguous creation label laundered for a later boolean clear")
	}
	got, err := s.Get(ctx, "A", id)
	if err != nil || !got.CleanupPending {
		t.Fatalf("pending lost: %+v %v", got, err)
	}
}
