// This fixture uses the shipped API/Store/scheduler/runc implementation. The
// token verifier and lost-ack barrier are explicitly test-only, not Entra auth.
package apilab_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"warden/controlplane/internal/api"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/tenant"
	"warden/controlplane/internal/testutil"
	"warden/runtimes"
	"warden/runtimes/gate"
	"warden/runtimes/runc"
)

func required(t *testing.T, err error, phase string) {
	t.Helper()
	if err != nil {
		t.Fatal(phase + " failed (details suppressed to protect fixture credentials)")
	}
}
func config(t *testing.T) scheduler.Config {
	t.Helper()
	pid, err := strconv.Atoi(os.Getenv("WARDEN_LAB_DAEMON_PID"))
	required(t, err, "daemon identity")
	uid, err := strconv.Atoi(os.Getenv("WARDEN_LAB_OWNER_UID"))
	required(t, err, "owner identity")
	return scheduler.Config{Node: "api-lab", GateDir: os.Getenv("WARDEN_API_GATE_DIR"), Concurrency: 2, PollMS: 20, OperationTimeoutS: 20, Drivers: map[string]scheduler.DriverConfig{"runc": {Socket: os.Getenv("WARDEN_LAB_SOCKET"), ExpectedDaemonPID: pid, TrustedOwnerUID: uid, CgroupRoot: "/sys/fs/cgroup/warden-lab", Images: map[string]string{os.Getenv("WARDEN_LAB_IMAGE_DIGEST"): os.Getenv("WARDEN_LAB_IMAGE_NAME")}}}}
}
func fixtureURL() string {
	return "postgres://postgres:" + url.QueryEscape(os.Getenv("WARDEN_API_PASSWORD")) + "@127.0.0.1:5432/warden_api_lab?sslmode=disable"
}

// The only boundary injection is AFTER real runc Start returns an actual handle,
// BEFORE gate durably records its acknowledgement. Parent kills the worker at
// this barrier, leaving a real task plus the original launching marker.
type lostAck struct {
	*runc.Driver
	event *os.File
}

func (d *lostAck) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	h, err := d.Driver.Start(ctx, s)
	if err == nil && len(s.Cmd) == 2 && s.Cmd[1] == "hold" {
		_, _ = fmt.Fprintln(d.event, s.RunID)
		<-ctx.Done()
		return h, errors.New("fixture lost acknowledgement")
	}
	return h, err
}
func worker(t *testing.T) {
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(fixtureURL())
	required(t, err, "worker database config")
	cfg.ConnConfig.RuntimeParams["search_path"] = os.Getenv("WARDEN_API_SCHEMA")
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	required(t, err, "worker database")
	defer pool.Close()
	c := config(t)
	dc := c.Drivers["runc"]
	d, err := runc.New(runc.Config{Socket: dc.Socket, ExpectedDaemonPID: dc.ExpectedDaemonPID, TrustedOwnerUID: dc.TrustedOwnerUID, CgroupRoot: dc.CgroupRoot, Images: dc.Images})
	required(t, err, "worker runtime")
	g, err := gate.New(c.GateDir, c.Node, &lostAck{Driver: d, event: os.NewFile(4, "ack-event")})
	required(t, err, "worker gate")
	s := &runs.Store{Pool: pool, Policies: fixturePolicy(pool)}
	w, err := c.Scheduler(s)
	required(t, err, "worker scheduler")
	w.Drivers["runc"] = g
	// No claim or runtime launch is possible before the supervisor captures both
	// process pidfds and the complete cgroup membership.
	var release [1]byte
	_, err = io.ReadFull(os.NewFile(3, "release"), release[:])
	required(t, err, "worker release")
	required(t, w.Run(ctx), "worker loop")
}
func fixturePolicy(pool *pgxpool.Pool) runs.PolicyProvider {
	return runs.PolicyFunc(func(ctx context.Context, tid string) (*runs.Policy, error) {
		var allowed bool
		if err := pool.QueryRow(ctx, "SELECT allowed FROM lab_policy WHERE tenant=$1", tid).Scan(&allowed); err != nil {
			return nil, err
		}
		runtimes := []string{}
		if allowed {
			runtimes = []string{"runc"}
		}
		return &runs.Policy{TenantID: tid, AllowedRuntimes: runtimes}, nil
	})
}

// Break caught: the HTTP queue never reaches the explicit gated runc registry,
// logs/results do not commit together, tenant/idempotency fences are bypassed,
// or recovery restarts a consumed run / clears uncertain creation without proof.
func TestHTTPPostgresRuntime(t *testing.T) {
	if os.Getenv("WARDEN_LAB_ACK") != "dedicated-warden-lab" {
		t.Skip("NOT EXECUTED: reviewed dedicated API/runc lab acknowledgement required")
	}
	if os.Getenv("WARDEN_API_WORKER") == "1" {
		worker(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if os.Getenv("WARDEN_API_PASSWORD") == "" {
		t.Fatal("owned fixture password required")
	}
	t.Setenv("WARDEN_TEST_DATABASE_URL", fixtureURL())
	pool := testutil.Database(t)
	var version string
	required(t, pool.QueryRow(ctx, "SELECT version()").Scan(&version), "PostgreSQL version")
	t.Log("private fixture PostgreSQL:", version)
	_, err := pool.Exec(ctx, "CREATE TABLE lab_policy(tenant text PRIMARY KEY,allowed boolean NOT NULL); INSERT INTO lab_policy VALUES ('fixture-A',true),('fixture-B',true)")
	required(t, err, "fixture policy")
	var schema string
	required(t, pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema), "schema")
	s := &runs.Store{Pool: pool, Policies: fixturePolicy(pool)}
	var verified atomic.Int64
	verifier := tenant.VerifyFunc(func(_ context.Context, token string) (tenant.Claims, error) {
		if token != "fixture-A" && token != "fixture-B" {
			return tenant.Claims{}, errors.New("invalid fixture token")
		}
		verified.Add(1)
		return tenant.Claims{TenantID: token}, nil
	})
	server := httptest.NewServer(api.New(s, verifier))
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(method, path, tenant, key string, body []byte, out any) int {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		required(t, e, "HTTP request")
		req.Header.Set("Authorization", "Bearer "+tenant)
		req.Header.Set("Idempotency-Key", key)
		response, e := client.Do(req)
		required(t, e, "HTTP transport")
		defer response.Body.Close()
		if out != nil {
			required(t, json.NewDecoder(response.Body).Decode(out), "HTTP decode")
		}
		return response.StatusCode
	}
	post := func(key, mode string, seconds int) string {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"image_digest": os.Getenv("WARDEN_LAB_IMAGE_DIGEST"), "cmd": []string{"/warden-probe", mode}, "runtime": "runc", "limits": map[string]any{"cpu": 0.5, "memory_mib": 64, "pids": 32, "timeout_s": seconds}})
		var out map[string]string
		if status := request("POST", "/v1/runs", "fixture-A", key, raw, &out); status != 201 {
			t.Fatal("POST status", status)
		}
		return out["run_id"]
	}
	read := func(id string) runs.Run {
		var out runs.Run
		if request("GET", "/v1/runs/"+id, "fixture-A", "", nil, &out) != 200 {
			t.Fatal("GET failed")
		}
		return out
	}
	await := func(id string, predicate func(runs.Run) bool) runs.Run {
		t.Helper()
		for ctx.Err() == nil {
			out := read(id)
			if predicate(out) {
				return out
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("run did not reach expected state")
		return runs.Run{}
	}
	terminal := func(out runs.Run) bool {
		return out.State == "succeeded" || out.State == "failed" || out.State == "denied" || out.State == "interrupted"
	}
	c := config(t)
	required(t, os.Mkdir(c.GateDir, 0700), "durable gate directory")
	w, err := c.Scheduler(s)
	required(t, err, "explicit registry")
	executable, err := os.Executable()
	required(t, err, "fixture executable")
	releaseR, releaseW, err := os.Pipe()
	required(t, err, "release pipe")
	defer releaseR.Close()
	defer releaseW.Close()
	eventR, eventW, err := os.Pipe()
	required(t, err, "event pipe")
	defer eventR.Close()
	defer eventW.Close()
	service, err := os.Open("/sys/fs/cgroup/warden-lab/service")
	required(t, err, "controlled worker cgroup")
	defer service.Close()
	cmd := exec.Command(executable, "-test.run", "^TestHTTPPostgresRuntime$", "-test.v")
	cmd.Env = append(os.Environ(), "WARDEN_API_WORKER=1", "WARDEN_API_SCHEMA="+schema)
	cmd.ExtraFiles = []*os.File{releaseR, eventW}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(service.Fd())}
	required(t, cmd.Start(), "fixed worker")
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	binding, err := w.Drivers["runc"].BindRetirement(ctx, cmd.Process.Pid)
	required(t, err, "original node binding")
	defer binding.Close()
	// Queue then revoke while the worker is held: stored tenant is reauthorized.
	denied := post("denied", "uid", 10)
	_, err = pool.Exec(ctx, "UPDATE lab_policy SET allowed=false WHERE tenant='fixture-A'")
	required(t, err, "revoke fixture policy")
	_, err = releaseW.Write([]byte{1})
	required(t, err, "worker release")
	if out := await(denied, terminal); out.State != "denied" || out.CleanupPending {
		t.Fatalf("stored policy not enforced: %+v", out)
	}
	_, err = pool.Exec(ctx, "UPDATE lab_policy SET allowed=true WHERE tenant='fixture-A'")
	required(t, err, "restore fixture policy")
	for _, tc := range []struct {
		mode, state, code string
		seconds           int
	}{{"uid", "succeeded", "", 10}, {"invalid-fixed-mode", "failed", "exit_nonzero", 10}, {"timeout", "failed", "timed_out", 1}} {
		id := post(tc.mode, tc.mode, tc.seconds)
		out := await(id, terminal)
		if out.State != tc.state || out.ErrorCode != tc.code || out.Result == nil || !out.Result.CgroupEmpty || out.CleanupPending || out.Logs.Status != "complete" {
			t.Fatalf("runtime result mismatch: %+v", out)
		}
		if tc.mode == "timeout" && !out.Result.TimedOut {
			t.Fatal("missing timeout evidence")
		}
		if tc.mode == "uid" {
			if !strings.Contains(strings.Join(out.Logs.Lines, ""), "PASS uid") {
				t.Fatal("guest output not persisted")
			}
			if post(tc.mode, tc.mode, tc.seconds) != id {
				t.Fatal("idempotency changed run")
			}
			var n int
			required(t, pool.QueryRow(ctx, "SELECT count(*) FROM audit_entries WHERE convert_from(canonical_event,'UTF8')::jsonb->>'run_id'=$1 AND convert_from(canonical_event,'UTF8')::jsonb->>'type'='run.running'", id).Scan(&n), "execution count")
			if n != 1 {
				t.Fatal("idempotent run executed more than once")
			}
		}
		var logs runs.Logs
		if request("GET", "/v1/runs/"+id+"/logs", "fixture-A", "", nil, &logs) != 200 || strings.Join(logs.Lines, "") != strings.Join(out.Logs.Lines, "") {
			t.Fatal("durable logs endpoint mismatch")
		}
		for _, suffix := range []string{"", "/logs"} {
			if request("GET", "/v1/runs/"+id+suffix, "fixture-B", "", nil, nil) != 404 {
				t.Fatal("cross tenant disclosure")
			}
		}
		raw, _ := json.Marshal(out)
		t.Logf("HTTP runtime result node=%s daemon=%d %s", w.Authority(), c.Drivers["runc"].ExpectedDaemonPID, raw)
	}
	acknowledged := post("recovery-ack", "timeout", 120)
	await(acknowledged, func(r runs.Run) bool { return r.State == "running" })
	ambiguous := post("recovery-ambiguous", "hold", 120)
	event := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(eventR)
		if scanner.Scan() {
			event <- scanner.Text()
		}
	}()
	select {
	case id := <-event:
		if id != ambiguous {
			t.Fatal("wrong remote acknowledgement")
		}
	case <-ctx.Done():
		t.Fatal("real creation barrier unavailable")
	}
	required(t, cmd.Process.Kill(), "stop original worker")
	_ = cmd.Wait()
	waited = true
	recoverRun := func(id string) {
		t.Helper()
		for {
			err := w.Process(ctx, id)
			if errors.Is(err, runs.ErrBusy) && ctx.Err() == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			required(t, err, "original run recovery")
			return
		}
	}
	// Reap on the real original daemon, with no retry Start of either RunID.
	recoverRun(acknowledged)
	if out := read(acknowledged); out.State != "interrupted" || out.CleanupPending || out.Result != nil {
		t.Fatalf("ack recovery mismatch: %+v", out)
	}
	recoverRun(ambiguous)
	if out := read(ambiguous); !out.CleanupPending || out.ErrorCode != "creation_outcome_unknown" {
		t.Fatalf("ambiguous creation cleared early: %+v", out)
	}
	if proof, e := w.Drivers["runc"].Reconciliation(ctx, ambiguous); e == nil || proof != nil {
		t.Fatal("live daemon accepted as quiescent")
	}
	required(t, binding.Retire(ctx), "original node kernel retirement")
	if err = binding.Finalize(ctx); err == nil {
		t.Fatal("unreaped daemon/data cleanup was skipped")
	}
	if proof, e := w.Drivers["runc"].Reconciliation(ctx, ambiguous); e == nil || proof != nil {
		t.Fatal("kernel-only retirement accepted")
	}
	supervisorFD, err := strconv.Atoi(os.Getenv("WARDEN_API_SUPERVISOR_FD"))
	required(t, err, "supervisor identity")
	supervisor := os.NewFile(uintptr(supervisorFD), "fixed-supervisor")
	defer supervisor.Close()
	_, err = supervisor.Write([]byte("RETIRE"))
	required(t, err, "request original-owner cleanup")
	response := make([]byte, 64)
	responseSize, err := supervisor.Read(response)
	required(t, err, "supervisor cleanup")
	if string(response[:responseSize]) != "CLEANED" {
		t.Fatal("original-owner cleanup failed")
	}
	required(t, binding.Finalize(ctx), "kernel and original data cleanup proof")

	proof, err := w.Drivers["runc"].Reconciliation(ctx, ambiguous)
	required(t, err, "bound reconciliation proof")
	if proof.ValidFor(acknowledged, w.Authority()) || proof.ValidFor(ambiguous, "other-node") {
		t.Fatal("proof transferable")
	}
	recoverRun(ambiguous)
	if out := read(ambiguous); out.State != "interrupted" || out.CleanupPending || out.ErrorCode != "node_retired" || out.Result != nil {
		t.Fatalf("retirement result mismatch: %+v", out)
	}
	// Reopen the same gate and verify its authority and permanent Start refusal.
	reopened, err := gate.New(c.GateDir, c.Node, w.Drivers["runc"])
	required(t, err, "reopen gate")
	if reopened.Authority() != w.Authority() {
		t.Fatal("authority changed")
	}
	if _, err = reopened.Start(ctx, runtimes.Spec{RunID: "ZZZZZZZZZZZZZZZZZZZZZZZZZZ"}); !errors.Is(err, gate.ErrRetired) {
		t.Fatal("retired node admitted launch")
	}
	marker, err := os.ReadFile(filepath.Join(c.GateDir, ambiguous))
	required(t, err, "retained uncertain marker")
	if string(marker) != "revoked-uncertain\n" {
		t.Fatal("ambiguous marker was cleared")
	}
	var payload []byte
	required(t, pool.QueryRow(ctx, "SELECT canonical_event FROM audit_entries WHERE convert_from(canonical_event,'UTF8')::jsonb->>'run_id'=$1 AND convert_from(canonical_event,'UTF8')::jsonb->>'type'='run.interrupted' ORDER BY seq DESC LIMIT 1", ambiguous).Scan(&payload), "reconciliation audit")
	if !bytes.Contains(payload, []byte(proof.Evidence()["sha256"])) {
		t.Fatal("audit proof digest missing")
	}
	for _, id := range []string{acknowledged, ambiguous} {
		var claims int
		required(t, pool.QueryRow(ctx, "SELECT count(*) FROM audit_entries WHERE convert_from(canonical_event,'UTF8')::jsonb->>'run_id'=$1 AND convert_from(canonical_event,'UTF8')::jsonb->>'type'='run.claimed'", id).Scan(&claims), "recovery launch count")
		if claims != 1 {
			t.Fatal("recovery relaunched original run")
		}
		raw, _ := json.Marshal(read(id))
		t.Logf("HTTP recovered node=%s daemon=%d %s", w.Authority(), c.Drivers["runc"].ExpectedDaemonPID, raw)
	}
	var n uint64
	required(t, pool.QueryRow(ctx, "SELECT count(*) FROM audit_entries").Scan(&n), "audit length")
	required(t, (&audit.Log{Pool: pool}).Verify(1, n), "audit Verify")
	if verified.Load() == 0 {
		t.Fatal("fixture verifier not used")
	}
	t.Logf("retirement run=%s acknowledged_run=%s proof=%v audit_entries=%d Verify=PASS", ambiguous, acknowledged, proof.Evidence(), n)
}
