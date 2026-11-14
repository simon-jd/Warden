package scheduler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/testutil"
	"warden/runtimes"
	"warden/runtimes/gate"
)

const valid = `{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`

type fakeRuntime struct {
	reader                                      io.ReadCloser
	starts, reaps, kills                        atomic.Int32
	started                                     chan runtimes.Spec
	release                                     chan struct{}
	exit                                        runtimes.Exit
	startErr, waitErr, reapErr, logErr, killErr error
	output                                      string
}

func (f *fakeRuntime) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	f.starts.Add(1)
	if f.started != nil {
		f.started <- s
	}
	if f.startErr != nil {
		return nil, f.startErr
	}
	return f, nil
}
func (f *fakeRuntime) Reap(ctx context.Context, id string) error { f.reaps.Add(1); return f.reapErr }
func (f *fakeRuntime) Wait(ctx context.Context) (runtimes.Exit, error) {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return runtimes.Exit{}, ctx.Err()
		}
	}
	return f.exit, f.waitErr
}
func (f *fakeRuntime) Kill() error { f.kills.Add(1); return f.killErr }
func (f *fakeRuntime) Logs() io.ReadCloser {
	if f.reader != nil {
		return f.reader
	}
	if f.logErr != nil {
		return failingReader{f.logErr}
	}
	return io.NopCloser(strings.NewReader(f.output))
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
func (r failingReader) Close() error             { return nil }
func setup(t *testing.T, f *fakeRuntime) (*scheduler.Scheduler, *runs.Store) {
	t.Helper()
	s := &runs.Store{Pool: testutil.Database(t)}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(dir, "node-A", f)
	if err != nil {
		t.Fatal(err)
	}
	return &scheduler.Scheduler{Store: s, Drivers: map[string]*gate.Gate{"runc": g}, Node: "node-A", PollInterval: 10 * time.Millisecond, OperationTimeout: 500 * time.Millisecond}, s
}
func create(t *testing.T, s *runs.Store, key string) string {
	t.Helper()
	spec, e := runs.Normalize([]byte(valid))
	if e != nil {
		t.Fatal(e)
	}
	id, e := s.Create(context.Background(), "A", key, spec)
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func read(t *testing.T, s *runs.Store, id string) runs.Run {
	t.Helper()
	r, e := s.Get(context.Background(), "A", id)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func verify(t *testing.T, s *runs.Store) {
	t.Helper()
	var n uint64
	if err := s.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_entries").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := (&audit.Log{Pool: s.Pool}).Verify(1, n); err != nil {
		t.Fatal(err)
	}
}

// Break caught: competing durable workers execute the same run or retry its idempotency key.
func TestConcurrentWorkersExecuteOnce(t *testing.T) {
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}, output: "hello\n"}
	w, s := setup(t, f)
	id := create(t, s, "once")
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Process(context.Background(), id); err != nil && !errors.Is(err, runs.ErrBusy) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if r := read(t, s, id); r.State != "succeeded" || r.Result == nil || !r.Result.CgroupEmpty || r.Logs.Status != "complete" || strings.Join(r.Logs.Lines, "") != "hello\n" {
		t.Fatalf("run %+v", r)
	}
	if again := create(t, s, "once"); again != id {
		t.Fatal("idempotency lost")
	}
	_ = w.Process(context.Background(), id)
	if f.starts.Load() != 1 {
		t.Fatalf("starts=%d", f.starts.Load())
	}
	verify(t, s)
}

// Break caught: dequeuing bypasses current trusted policy or silently falls back to another driver.
func TestPolicyAndMissingDriverFailClosed(t *testing.T) {
	for _, mode := range []string{"revoked", "unavailable", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeRuntime{}
			w, s := setup(t, f)
			id := create(t, s, "policy")
			if mode == "missing" {
				w.Drivers = map[string]*gate.Gate{}
			} else {
				s.Policies = runs.PolicyFunc(func(_ context.Context, tenant string) (*runs.Policy, error) {
					if tenant != "A" {
						t.Errorf("wrong stored tenant %s", tenant)
					}
					if mode == "unavailable" {
						return nil, errors.New("secret db URL")
					}
					return &runs.Policy{TenantID: "A", AllowedRuntimes: []string{}}, nil
				})
			}
			if err := w.Process(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			r := read(t, s, id)
			want := "failed"
			if mode == "revoked" {
				want = "denied"
			}
			if r.State != want || r.ErrorCode == "" || f.starts.Load() != 0 {
				t.Fatalf("run %+v starts=%d", r, f.starts.Load())
			}
			verify(t, s)
		})
	}
}

// Break caught: execution outcomes are lost, falsely successful, or expose raw runtime errors.
func TestOutcomesAndLogMetadata(t *testing.T) {
	cases := []struct {
		name                        string
		exit                        runtimes.Exit
		startErr, waitErr, logErr   error
		output, state, code, status string
		pending                     bool
	}{
		{name: "nonzero", exit: runtimes.Exit{Code: 7, CgroupEmpty: true}, state: "failed", code: "exit_nonzero", status: "complete"},
		{name: "oom", exit: runtimes.Exit{Code: 137, OOMKilled: true, CgroupEmpty: true}, state: "failed", code: "oom_killed", status: "complete"},
		{name: "timeout", exit: runtimes.Exit{TimedOut: true, CgroupEmpty: true}, state: "failed", code: "timed_out", status: "complete"},
		{name: "cleanup", exit: runtimes.Exit{Code: 0, CgroupEmpty: false}, waitErr: errors.New("secret /host/path"), state: "failed", code: "runtime_wait_failed", status: "complete", pending: true},
		{name: "start", startErr: errors.New("secret start"), state: "failed", code: "runtime_start_ambiguous", status: "lost", pending: true},
		{name: "logs", exit: runtimes.Exit{CgroupEmpty: true}, logErr: errors.New("secret read"), state: "failed", code: "log_read_failed", status: "lost"},
		{name: "empty", exit: runtimes.Exit{CgroupEmpty: true}, state: "succeeded", status: "complete"},
		{name: "truncated", exit: runtimes.Exit{CgroupEmpty: true, DroppedLogBytes: 5, LogsTruncated: true}, output: strings.Repeat("x", (1<<20)+17), state: "succeeded", status: "complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRuntime{exit: tc.exit, startErr: tc.startErr, waitErr: tc.waitErr, logErr: tc.logErr, output: tc.output}
			w, s := setup(t, f)
			id := create(t, s, tc.name)
			if err := w.Process(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			r := read(t, s, id)
			if r.State != tc.state || r.ErrorCode != tc.code || r.Logs.Status != tc.status || r.CleanupPending != tc.pending {
				t.Fatalf("run %+v", r)
			}
			if tc.name == "truncated" {
				if len(strings.Join(r.Logs.Lines, "")) != 1<<20 || !r.Logs.Truncated || r.Logs.DroppedBytes != 22 {
					t.Fatalf("log cap=%d dropped=%d", len(strings.Join(r.Logs.Lines, "")), r.Logs.DroppedBytes)
				}
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "secret") {
				t.Fatal("runtime error leaked")
			}
			verify(t, s)
		})
	}
}

// Break caught: recovery restarts crashed work or steals an active worker's session.
func TestRecoveryReapsOnlyAndPreservesLiveOwner(t *testing.T) {
	for _, state := range []string{"starting", "running"} {
		t.Run(state, func(t *testing.T) {
			f := &fakeRuntime{}
			w, s := setup(t, f)
			id := create(t, s, state)
			claim, err := s.Claim(context.Background(), id, w.Authority())
			if err != nil {
				t.Fatal(err)
			}
			if state == "running" {
				if err = claim.Running(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if err = w.Process(context.Background(), id); !errors.Is(err, runs.ErrBusy) {
				t.Fatalf("active owner: %v", err)
			}
			if f.reaps.Load() != 0 {
				t.Fatal("stole live claim")
			}
			claim.Close()
			if err = w.Process(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			r := read(t, s, id)
			if r.State != "interrupted" || r.Logs.Status != "lost" || r.CleanupPending || f.starts.Load() != 0 || f.reaps.Load() != 1 {
				t.Fatalf("recovered %+v starts %d reaps %d", r, f.starts.Load(), f.reaps.Load())
			}
			verify(t, s)
		})
	}
}

// Break caught: failed cleanup is forgotten or recovery launches a replacement.
func TestCleanupFailureRemainsRetryable(t *testing.T) {
	f := &fakeRuntime{reapErr: errors.New("unavailable")}
	w, s := setup(t, f)
	id := create(t, s, "cleanup")
	claim, err := s.Claim(context.Background(), id, w.Authority())
	if err != nil {
		t.Fatal(err)
	}
	claim.Close()
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); !r.CleanupPending || r.ErrorCode != "cleanup_failed" {
		t.Fatalf("run %+v", r)
	}
	f.reapErr = nil
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); r.CleanupPending || r.State != "interrupted" {
		t.Fatalf("run %+v", r)
	}
	if f.starts.Load() != 0 || f.reaps.Load() != 2 {
		t.Fatal("bad recovery behavior")
	}
	verify(t, s)
}

// Break caught: shutdown leaves handles alive, or worker concurrency exceeds its bound.
func TestWorkerLifecycleBoundedConcurrencyAndShutdown(t *testing.T) {
	f := &fakeRuntime{started: make(chan runtimes.Spec, 8), release: make(chan struct{}), exit: runtimes.Exit{CgroupEmpty: true}}
	w, s := setup(t, f)
	w.Concurrency = 2
	for i := range 4 {
		create(t, s, fmt.Sprint(i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	for range 2 {
		select {
		case <-f.started:
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-f.started:
		t.Error("concurrency exceeded")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown unbounded")
	}
	if f.kills.Load() != 2 {
		t.Fatalf("kills=%d", f.kills.Load())
	}
	var lost int
	if err := s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM runs WHERE state='interrupted' AND logs->>'status'='lost'`).Scan(&lost); err != nil {
		t.Fatal(err)
	}
	if lost != 2 {
		t.Fatalf("shutdown falsely reported complete empty output: lost=%d", lost)
	}
	verify(t, s)
}

// Break caught: recovery on another runtime node falsely reports remote cleanup.
func TestRecoveryCannotMoveRuntimeNodes(t *testing.T) {
	f := &fakeRuntime{}
	w, s := setup(t, f)
	id := create(t, s, "node")
	c, err := s.Claim(context.Background(), id, "node-original")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err = w.Process(context.Background(), id); err == nil {
		t.Fatal("wrong node acquired recovery")
	}
	ids, err := s.Candidates(context.Background(), "node-A", 10)
	if err != nil || len(ids) != 0 {
		t.Fatalf("node candidates %v %v", ids, err)
	}
	if r := read(t, s, id); r.State != "starting" || f.reaps.Load() != 0 {
		t.Fatal("wrong node reported cleanup")
	}
}

// Break caught: terminal logs/state survive an audit append failure.
func TestTerminalAuditFailureRollsBackLogsAndResult(t *testing.T) {
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}, output: "atomic output"}
	w, s := setup(t, f)
	id := create(t, s, "atomic")
	_, err := s.Pool.Exec(context.Background(), `CREATE FUNCTION fail_terminal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.canonical_event,'UTF8')::jsonb->>'type'='run.succeeded' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_terminal BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fail_terminal_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Process(context.Background(), id); err == nil {
		t.Fatal("audit failure ignored")
	}
	if r := read(t, s, id); r.State != "running" || r.Result != nil || len(r.Logs.Lines) != 0 || r.Logs.Status != "pending" {
		t.Fatalf("partial terminal commit %+v", r)
	}
	verify(t, s)
	if _, err = s.Pool.Exec(context.Background(), `DROP TRIGGER fail_terminal ON audit_entries`); err != nil {
		t.Fatal(err)
	}
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); r.State != "interrupted" || r.Logs.Status != "lost" || f.starts.Load() != 1 {
		t.Fatalf("bad recovery %+v", r)
	}
	verify(t, s)
}

// Break caught: a failed or ambiguous claim commit can still call Start.
func TestClaimCommitTimeoutNeverStarts(t *testing.T) {
	f := &fakeRuntime{}
	w, s := setup(t, f)
	id := create(t, s, "commit")
	_, err := s.Pool.Exec(context.Background(), `CREATE FUNCTION delay_claim_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.canonical_event,'UTF8')::jsonb->>'type'='run.claimed' THEN PERFORM pg_sleep(0.3); END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER delay_claim AFTER INSERT ON audit_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_claim_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	w.OperationTimeout = 40 * time.Millisecond
	if err = w.Process(context.Background(), id); err == nil {
		t.Fatal("claim commit did not time out")
	}
	if f.starts.Load() != 0 {
		t.Fatal("uncertain claim launched")
	}
	// Rollback may still be completing when the client sees the cancellation.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = s.Pool.Exec(ctx, `DROP TRIGGER delay_claim ON audit_entries`); err != nil {
		t.Fatal(err)
	}
	verify(t, s)
}

// Break caught: a DB-disconnected worker paused before the runtime gate launches
// after another worker has already Reaped and committed interrupted.
func TestLostSessionBeforeLaunchCannotCreateAfterRecovery(t *testing.T) {
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}}
	w, s := setup(t, f)
	id := create(t, s, "stale")
	entered, release := make(chan struct{}), make(chan struct{})
	s.Policies = runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) { close(entered); <-release; return nil, nil })
	done := make(chan error, 1)
	go func() { done <- w.Process(context.Background(), id) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("policy not reached")
	}
	var pid int
	if err := s.Pool.QueryRow(context.Background(), `SELECT owner_pid FROM run_executions WHERE run_id=$1`, id).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	if err := w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stale worker committed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale worker stuck")
	}
	if r := read(t, s, id); r.State != "interrupted" || r.CleanupPending || f.starts.Load() != 0 {
		t.Fatalf("stale orphan state=%s pending=%t starts=%d", r.State, r.CleanupPending, f.starts.Load())
	}
	verify(t, s)
}

// Break caught: a disconnected Start still inside the gate permits false clean recovery.
func TestLostSessionInsideLaunchLeavesPendingCleanup(t *testing.T) {
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}}
	w, s := setup(t, f)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	blocked := &blockedStart{fakeRuntime: f, entered: make(chan struct{}), release: make(chan struct{})}
	g, err := gate.New(dir, "node-A", blocked)
	if err != nil {
		t.Fatal(err)
	}
	w.Drivers["runc"] = g
	// Long enough for manual disconnect before Start's deadline, short recovery bound.
	w.OperationTimeout = 200 * time.Millisecond
	id := create(t, s, "inflight")
	done := make(chan error, 1)
	go func() { done <- w.Process(context.Background(), id) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("start not reached")
	}
	var pid int
	if err = s.Pool.QueryRow(context.Background(), `SELECT owner_pid FROM run_executions WHERE run_id=$1`, id).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); !r.CleanupPending || r.ErrorCode != "cleanup_failed" {
		t.Fatalf("inflight start falsely clean: %+v", r)
	}
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old start did not finish")
	}
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); r.CleanupPending || r.State != "interrupted" {
		t.Fatalf("cleanup retry failed: %+v", r)
	}
	if f.starts.Load() != 1 {
		t.Fatalf("starts %d", f.starts.Load())
	}
	verify(t, s)
}

type blockedStart struct {
	*fakeRuntime
	entered, release chan struct{}
}

func (b *blockedStart) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	close(b.entered)
	<-b.release
	return b.fakeRuntime.Start(ctx, s)
}

// Break caught: process-local coordination permits two independent worker
// processes to launch one durable run.
func TestIndependentProcessesExecuteOnce(t *testing.T) {
	f := &fakeRuntime{}
	_, s := setup(t, f)
	id := create(t, s, "processes")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := s.Pool.QueryRow(context.Background(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]*exec.Cmd, 4)
	outputs := make([]strings.Builder, 4)
	for i := range commands {
		cmd := exec.Command(exe, "-test.run=^TestSchedulerProcessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "WARDEN_SCHEDULER_CHILD=1", "WARDEN_CHILD_SCHEMA="+schema, "WARDEN_CHILD_RUN="+id, "WARDEN_CHILD_GATE="+dir)
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		commands[i] = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	starts := 0
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v %s", err, outputs[i].String())
		}
		starts += strings.Count(outputs[i].String(), "runtime-started")
	}
	if starts != 1 {
		t.Fatalf("independent process starts=%d", starts)
	}
	if r := read(t, s, id); r.State != "succeeded" {
		t.Fatalf("run state %s", r.State)
	}
	verify(t, s)
}
func TestSchedulerProcessHelper(t *testing.T) {
	if os.Getenv("WARDEN_SCHEDULER_CHILD") != "1" {
		return
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("WARDEN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = os.Getenv("WARDEN_CHILD_SCHEMA")
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}}
	g, err := gate.New(os.Getenv("WARDEN_CHILD_GATE"), "node-A", f)
	if err != nil {
		t.Fatal(err)
	}
	w := scheduler.Scheduler{Store: &runs.Store{Pool: pool}, Node: "node-A", Drivers: map[string]*gate.Gate{"runc": g}}
	if err = w.Process(context.Background(), os.Getenv("WARDEN_CHILD_RUN")); err != nil && !errors.Is(err, runs.ErrBusy) {
		t.Fatal(err)
	}
	if f.starts.Load() > 0 {
		fmt.Println("runtime-started")
	}
}

// Break caught: a stalled log snapshot hangs shutdown or is never closed on timeout.
func TestLogSnapshotDeadlineClosesReaderAndMarksLost(t *testing.T) {
	reader := &blockedReader{closed: make(chan struct{})}
	t.Cleanup(func() { _ = reader.Close() })
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}, reader: reader}
	w, s := setup(t, f)
	w.OperationTimeout = 50 * time.Millisecond
	id := create(t, s, "stalled-log")
	if err := w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); r.Logs.Status != "lost" || r.State != "failed" || r.ErrorCode != "log_read_failed" {
		t.Fatalf("run %+v", r)
	}
	select {
	case <-reader.closed:
	case <-time.After(time.Second):
		t.Fatal("timed out snapshot was not closed")
	}
}

type blockedReader struct {
	closed chan struct{}
	once   sync.Once
}

func (r *blockedReader) Read([]byte) (int, error) {
	<-r.closed
	return 0, errors.New("snapshot closed")
}
func (r *blockedReader) Close() error { r.once.Do(func() { close(r.closed) }); return nil }

// Break caught: arbitrary guest bytes are silently replaced or NUL prevents the
// atomic JSONB terminal commit, losing otherwise valid runtime output.
func TestBinaryLogsPersistWithoutLoss(t *testing.T) {
	output := string([]byte{0, 255, 'x', '\n'})
	f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: true}, output: output}
	w, s := setup(t, f)
	id := create(t, s, "binary")
	if err := w.Process(context.Background(), id); err != nil {
		t.Fatalf("binary output prevented terminal commit: %v", err)
	}
	r := read(t, s, id)
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(r.Logs.Lines, ""))
	if err != nil || string(decoded) != output || r.Logs.Encoding != "base64" || r.Logs.Status != "complete" || r.State != "succeeded" {
		t.Fatalf("binary output lost: encoding=%q status=%q decoded=%x err=%v", r.Logs.Encoding, r.Logs.Status, decoded, err)
	}
}

// Break caught: execution retains run/audit transaction locks across guest Wait,
// or dispatches defaults different from the persisted secure specification.
func TestActiveGuestDoesNotHoldAuditLockAndUsesStoredSpec(t *testing.T) {
	f := &fakeRuntime{started: make(chan runtimes.Spec, 1), release: make(chan struct{}), exit: runtimes.Exit{CgroupEmpty: true}}
	w, s := setup(t, f)
	id := create(t, s, "long")
	done := make(chan error, 1)
	go func() { done <- w.Process(context.Background(), id) }()
	var spec runtimes.Spec
	select {
	case spec = <-f.started:
	case <-time.After(time.Second):
		t.Fatal("worker not started")
	}
	defer close(f.release)
	if spec.RunID != id || spec.ImageDigest != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || len(spec.Cmd) != 1 || spec.Cmd[0] != "/bin/true" || spec.Network != "none" || spec.Limits.CPU != 1 || spec.Limits.MemoryMiB != 512 || spec.Limits.Pids != 128 || spec.Limits.TimeoutS != 300 {
		t.Fatalf("wrong dispatch %+v", spec)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	normalized, err := runs.Normalize([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(ctx, "B", "during-guest", normalized); err != nil {
		t.Fatalf("guest held audit lock: %v", err)
	}
	// Release explicitly before testing the terminal audit; disable deferred close.
	f.release <- struct{}{}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	verify(t, s)
}

// Break caught: retrying Reap clears ambiguous remote creation on a mere not-found.
func TestAmbiguousStartRemainsPendingAcrossRecovery(t *testing.T) {
	f := &fakeRuntime{startErr: errors.New("transport response lost")}
	w, s := setup(t, f)
	id := create(t, s, "ambiguous")
	if err := w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); !r.CleanupPending || r.ErrorCode != "runtime_start_ambiguous" {
		t.Fatalf("ambiguity hidden %+v", r)
	}
	if err := w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if r := read(t, s, id); !r.CleanupPending || r.ErrorCode != "creation_outcome_unknown" || r.State != "failed" {
		t.Fatalf("uncertainty cleared by retry %+v", r)
	}
	if f.starts.Load() != 1 || f.reaps.Load() != 2 {
		t.Fatalf("start=%d reap=%d", f.starts.Load(), f.reaps.Load())
	}
	verify(t, s)
}

// Break caught: a runtime returning both a handle and an error leaves the owned
// handle uncollected while the remote creation outcome remains uncertain.
func TestStartErrorStillKillsReturnedHandle(t *testing.T) {
	f := &fakeRuntime{}
	w, s := setup(t, f)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(dir, "node-A", &partialStart{f})
	if err != nil {
		t.Fatal(err)
	}
	w.Drivers["runc"] = g
	id := create(t, s, "partial-start")
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if f.kills.Load() != 1 {
		t.Fatal("returned handle was not killed")
	}
	if r := read(t, s, id); !r.CleanupPending || r.ErrorCode != "runtime_start_ambiguous" {
		t.Fatalf("ambiguous start hidden %+v", r)
	}
}

type partialStart struct{ *fakeRuntime }

func (f *partialStart) Start(context.Context, runtimes.Spec) (runtimes.Handle, error) {
	return f.fakeRuntime, errors.New("creation acknowledgement not persisted")
}

// Break caught: an ambiguous Start is considered clean after an absent Reap,
// or a new worker misses/deletes the wrong late resource or executes again.
func TestLateRemoteCreationIsReapedByNewWorkerWithoutClearingAmbiguity(t *testing.T) {
	_, store := setup(t, &fakeRuntime{})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	remote := &delayedRemoteState{release: make(chan struct{}), materialized: make(chan struct{}), resources: map[string]bool{"unrelated-run": true}}
	t.Cleanup(remote.releaseCreation)
	newWorker := func() *scheduler.Scheduler {
		t.Helper()
		// Backend state outlives both the client adapter and the worker/gate instance.
		guarded, err := gate.New(dir, "node-A", &delayedRemoteRuntime{remote: remote})
		if err != nil {
			t.Fatal(err)
		}
		return &scheduler.Scheduler{Store: &runs.Store{Pool: store.Pool}, Node: "node-A", Drivers: map[string]*gate.Gate{"runc": guarded}, OperationTimeout: time.Second}
	}
	worker := newWorker()
	authority := worker.Authority()
	id := create(t, store, "late-remote-creation")
	assertPending := func(code string) {
		t.Helper()
		run := read(t, store, id)
		if run.State != "failed" || !run.CleanupPending || run.ErrorCode != code || run.Result != nil {
			t.Fatalf("uncertain creation reported terminal-clean: state=%s pending=%t code=%s result=%+v", run.State, run.CleanupPending, run.ErrorCode, run.Result)
		}
	}
	if err := worker.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	assertPending("runtime_start_ambiguous")
	starts, reaps, resources := remote.snapshot()
	if len(starts) != 1 || starts[0] != id || len(reaps) != 1 || reaps[0].runID != id || reaps[0].existed || resources[id] || !resources["unrelated-run"] {
		t.Fatalf("first absent cleanup: starts=%v reaps=%+v resources=%v", starts, reaps, resources)
	}
	// The server finishes the previously submitted Create only after the first
	// successful absent Reap and its durable failed/pending transition.
	remote.releaseCreation()
	select {
	case <-remote.materialized:
	case <-time.After(time.Second):
		t.Fatal("remote creation did not materialize")
	}
	_, _, resources = remote.snapshot()
	if !resources[id] {
		t.Fatal("fixture failed to create the late same-run resource")
	}
	for attempt := 0; attempt < 2; attempt++ {
		recovered := newWorker()
		if recovered.Authority() != authority {
			t.Fatal("worker restart changed runtime authority")
		}
		if err := recovered.Process(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		assertPending("creation_outcome_unknown")
		starts, reaps, resources = remote.snapshot()
		if len(starts) != 1 || len(reaps) != attempt+2 || resources[id] || !resources["unrelated-run"] {
			t.Fatalf("recovery changed launch identity or failed exact cleanup: starts=%v reaps=%+v resources=%v", starts, reaps, resources)
		}
		last := reaps[len(reaps)-1]
		if last.runID != id || last.existed != (attempt == 0) {
			t.Fatalf("wrong recovery target/materialization state: %+v", last)
		}
	}
	var generation int
	var node string
	if err := store.Pool.QueryRow(context.Background(), `SELECT generation,runtime_node FROM run_executions WHERE run_id=$1`, id).Scan(&generation, &node); err != nil {
		t.Fatal(err)
	}
	if generation != 3 || node != authority {
		t.Fatalf("durable recovery identity changed: generation=%d node=%q", generation, node)
	}
	verify(t, store)
}

type reapObservation struct {
	runID   string
	existed bool
}
type delayedRemoteState struct {
	mu                    sync.Mutex
	release, materialized chan struct{}
	releaseOnce           sync.Once
	resources             map[string]bool
	starts                []string
	reaps                 []reapObservation
}

func (s *delayedRemoteState) releaseCreation() { s.releaseOnce.Do(func() { close(s.release) }) }
func (s *delayedRemoteState) snapshot() ([]string, []reapObservation, map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resources := make(map[string]bool, len(s.resources))
	for id, present := range s.resources {
		resources[id] = present
	}
	return append([]string(nil), s.starts...), append([]reapObservation(nil), s.reaps...), resources
}

type delayedRemoteRuntime struct{ remote *delayedRemoteState }

func (d *delayedRemoteRuntime) Start(_ context.Context, spec runtimes.Spec) (runtimes.Handle, error) {
	state := d.remote
	state.mu.Lock()
	state.starts = append(state.starts, spec.RunID)
	first := len(state.starts) == 1
	state.mu.Unlock()
	if first {
		go func() {
			<-state.release
			state.mu.Lock()
			state.resources[spec.RunID] = true
			state.mu.Unlock()
			close(state.materialized)
		}()
	}
	return nil, errors.New("creation response lost while server operation remains pending")
}
func (d *delayedRemoteRuntime) Reap(_ context.Context, id string) error {
	state := d.remote
	state.mu.Lock()
	defer state.mu.Unlock()
	state.reaps = append(state.reaps, reapObservation{runID: id, existed: state.resources[id]})
	delete(state.resources, id)
	return nil
}
