package scheduler_test

// In-lab half of `make test-egress-runc` (Task 10). It runs inside the
// dedicated runc lab container (scripts/runtime_lab_docker.py egress), which
// sits on the egress lab's sandbox network next to Envoy. Every probe is a
// real runc sandbox in Network "allowlist": its own netns with one ipvlan
// address and no route beyond the proxy subnet. The sandbox address and the
// proxy grant come from EgressPool in the same order Scheduler.Process uses
// (Acquire -> Start -> Wait -> Release). TestAPIProcessRuncEgress runs that
// order through the HTTP API, PostgreSQL and Scheduler.Process.

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/controlplane/internal/api"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/tenant"
	"warden/controlplane/internal/testutil"
	"warden/runtimes"
	"warden/runtimes/gate"
	"warden/runtimes/runc"
)

type labProbe struct {
	Key          string  `json:"key"`
	OK           bool    `json:"ok"`
	Status       int     `json:"status"`
	ProxyStatus  int     `json:"proxy_status"`
	Body         string  `json:"body"`
	Error        string  `json:"error"`
	Resolved     string  `json:"resolved"`
	ResolveError string  `json:"resolve_error"`
	ConnectError string  `json:"connect_error"`
	Attempts     int     `json:"attempts"`
	SucceededAt  float64 `json:"succeeded_at"`
	PollingSince float64 `json:"polling_since"`
}

type runcEgressLab struct {
	driver   *runc.Driver
	pool     *scheduler.EgressPool
	dir      string
	digest   string
	ca       string
	prefix   netip.Prefix
	originIP string
	mu       sync.Mutex
	evidence map[string]any
}

func (l *runcEgressLab) record(k string, v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evidence[k] = v
}

func newRunID(t *testing.T) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

func startRuncEgressLab(t *testing.T) *runcEgressLab {
	t.Helper()
	if os.Getenv("WARDEN_LAB_ACK") != "dedicated-warden-lab" || os.Getenv("WARDEN_EGRESS_DIR") == "" {
		t.Skip("runc egress lab: runs only inside `make test-egress-runc`'s dedicated lab container")
	}
	pid, err := strconv.Atoi(os.Getenv("WARDEN_LAB_DAEMON_PID"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := strconv.Atoi(os.Getenv("WARDEN_LAB_OWNER_UID"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix(os.Getenv("WARDEN_EGRESS_PREFIX"))
	proxy := netip.MustParseAddr(os.Getenv("WARDEN_EGRESS_PROXY"))
	dir := os.Getenv("WARDEN_EGRESS_DIR")
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	digest := os.Getenv("WARDEN_LAB_IMAGE_DIGEST")
	d, err := runc.New(runc.Config{Socket: os.Getenv("WARDEN_LAB_SOCKET"), ExpectedDaemonPID: pid, TrustedOwnerUID: owner,
		CgroupRoot: "/sys/fs/cgroup/warden-lab", Images: map[string]string{digest: os.Getenv("WARDEN_LAB_IMAGE_NAME")},
		Egress: &runc.EgressNetwork{IPPath: "/usr/bin/ip", Parent: "eth0", Prefix: prefix, Proxy: netip.AddrPortFrom(proxy, scheduler.HTTPProxyPort)}})
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := scheduler.NewEgressController(dir)
	if err != nil {
		t.Fatal(err)
	}
	pool := &scheduler.EgressPool{Controller: ctl}
	base := prefix.Addr().As4()
	for i := 64; i < 72; i++ {
		base[3] = byte(i)
		pool.Sources = append(pool.Sources, netip.AddrFrom4(base))
	}
	l := &runcEgressLab{driver: d, pool: pool, dir: dir, digest: digest, ca: base64.StdEncoding.EncodeToString(ca),
		prefix: prefix, originIP: os.Getenv("WARDEN_EGRESS_ORIGIN_BLOCKED"), evidence: map[string]any{}}
	t.Cleanup(func() {
		load, _ := os.ReadFile("/proc/loadavg")
		l.record("host", map[string]any{"nproc": runtime.NumCPU(), "loadavg": strings.TrimSpace(string(load))})
		entries, _ := os.ReadDir("/run/netns")
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		l.record("netns_left_after_all_runs", names)
		b, _ := json.MarshalIndent(l.evidence, "", "  ")
		name := "runc-result.json"
		if t.Name() == "TestAPIProcessRuncEgress" {
			name = "api-chain-result.json"
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
			t.Error(err)
		}
	})
	return l
}

func parseProbes(t *testing.T, raw string) map[string]labProbe {
	t.Helper()
	out := map[string]labProbe{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var p labProbe
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatalf("bad probe line %q", line)
		}
		if p.PollingSince != 0 {
			continue
		}
		out[p.Key] = p
	}
	return out
}

type labRun struct {
	id     string
	source netip.Addr
	h      runtimes.Handle
}

// start follows Scheduler.Process: grant first, then the sandbox. A zero
// source skips the pool, for a sandbox the proxy has never heard of.
func (l *runcEgressLab) start(t *testing.T, name string, domains []string, source netip.Addr, cases ...string) *labRun {
	t.Helper()
	r := &labRun{id: newRunID(t), source: source}
	if !source.IsValid() {
		var err error
		if r.source, err = l.pool.Acquire(r.id, domains); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	h, err := l.driver.Start(ctx, runtimes.Spec{RunID: r.id, ImageDigest: l.digest, Cmd: append([]string{"/warden-probe", "egress", l.ca}, cases...),
		Limits: runtimes.Limits{CPU: 1, MemoryMiB: 128, Pids: 32, TimeoutS: 60}, Network: "allowlist", AllowDomains: domains, EgressSource: r.source})
	if err != nil {
		_ = l.pool.Release(r.id, false)
		t.Fatalf("%s: start: %v", name, err)
	}
	r.h = h
	return r
}

func (l *runcEgressLab) finish(t *testing.T, name string, r *labRun) map[string]labProbe {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	exit, err := r.h.Wait(ctx)
	logs := r.h.Logs()
	raw, _ := io.ReadAll(logs)
	logs.Close()
	_ = l.pool.Release(r.id, err == nil && exit.CgroupEmpty)
	_, nsErr := os.Stat("/run/netns/warden-" + r.id)
	lds, _ := os.ReadFile(filepath.Join(l.dir, scheduler.LDSFile))
	l.record(name+"_run", map[string]any{"run_id": r.id, "source": r.source.String(), "exit": exit,
		"netns_removed": os.IsNotExist(nsErr), "grant_removed": !strings.Contains(string(lds), "run_"+r.id)})
	if err != nil || exit.Code != 0 || !exit.CgroupEmpty {
		t.Fatalf("%s: runc run failed: %v %+v\n%s", name, err, exit, raw)
	}
	if !os.IsNotExist(nsErr) || strings.Contains(string(lds), "run_"+r.id) {
		t.Errorf("%s: netns or grant left after the run (netns err %v)", name, nsErr)
	}
	probes := parseProbes(t, string(raw))
	for k, p := range probes {
		l.record(k, p)
	}
	return probes
}

func (l *runcEgressLab) run(t *testing.T, name string, domains []string, cases ...string) map[string]labProbe {
	t.Helper()
	return l.finish(t, name, l.start(t, name, domains, netip.Addr{}, cases...))
}

func TestRuncEgressAllowlist(t *testing.T) {
	l := startRuncEgressLab(t)
	runA := []string{"allowed.warden.test", "*.cdn.warden.test"}
	t.Run("AllowlistedDomainReachable", func(t *testing.T) {
		p := l.run(t, "reach", runA,
			"reach_connect_allowed,connect,allowed.warden.test",
			"reach_connect_wildcard,connect,img.cdn.warden.test",
			"reach_http_allowed,http,allowed.warden.test",
			"reach_sni_allowed,sni,allowed.warden.test")
		for _, k := range []string{"reach_connect_allowed", "reach_connect_wildcard", "reach_http_allowed", "reach_sni_allowed"} {
			if !p[k].OK || p[k].Body != "origin-allowed" {
				t.Errorf("%s: %+v", k, p[k])
			}
		}
	})
	t.Run("NonAllowlistedBlocked", func(t *testing.T) {
		checks := map[string]func(labProbe) bool{
			"block_connect_other_domain":     func(p labProbe) bool { return p.ProxyStatus == 403 },
			"block_connect_suffix_trick":     func(p labProbe) bool { return p.ProxyStatus == 403 },
			"block_http_other_domain":        func(p labProbe) bool { return p.Status == 403 },
			"block_sni_other_domain":         func(p labProbe) bool { return !p.OK && p.Error != "" },
			"front_sni_allowed_host_blocked": func(p labProbe) bool { return p.Body != "origin-blocked" },
			"block_direct_bypass":            func(p labProbe) bool { return !p.OK && p.Resolved == "" && p.ConnectError != "" },
			"block_direct_internet":          func(p labProbe) bool { return !p.OK && p.ConnectError != "" },
			"block_run_b_no_domain":          func(p labProbe) bool { return p.ProxyStatus == 403 },
			"block_run_b_sni":                func(p labProbe) bool { return !p.OK && p.Error != "" },
			"block_unknown_source":           func(p labProbe) bool { return !p.OK && p.ProxyStatus == 0 },
		}
		got := map[string]labProbe{}
		for k, v := range l.run(t, "block_a", runA,
			"block_connect_other_domain,connect,blocked.warden.test",
			"block_connect_suffix_trick,connect,allowed.warden.test.blocked.warden.test",
			"block_http_other_domain,http,blocked.warden.test",
			"block_sni_other_domain,sni,blocked.warden.test",
			"front_sni_allowed_host_blocked,front,allowed.warden.test,blocked.warden.test",
			"block_direct_bypass,direct,blocked.warden.test,"+l.originIP,
			"block_direct_internet,direct,example.com,198.18.0.1") {
			got[k] = v
		}
		// Run B is allowlisted, but only for a different domain.
		for k, v := range l.run(t, "block_b", []string{"other.warden.test"},
			"block_run_b_no_domain,connect,allowed.warden.test",
			"block_run_b_sni,sni,allowed.warden.test") {
			got[k] = v
		}
		// A sandbox on the proxy subnet whose address has no grant at all.
		unknown := l.prefix.Addr().As4()
		unknown[3] = 200
		r := l.start(t, "block_unknown", []string{"allowed.warden.test"}, netip.AddrFrom4(unknown), "block_unknown_source,connect,allowed.warden.test")
		for k, v := range l.finish(t, "block_unknown", r) {
			got[k] = v
		}
		for k, check := range checks {
			if p, ok := got[k]; !ok || !check(p) {
				t.Errorf("%s: not blocked: %+v", k, p)
			}
		}
	})
	t.Run("EgressHotReload", func(t *testing.T) {
		measure := func(key string, domains []string, change func(r *labRun), until string) {
			r := l.start(t, key, domains, netip.Addr{}, "poll,poll,blocked.warden.test,"+until)
			deadline := time.Now().Add(20 * time.Second)
			for {
				logs := r.h.Logs()
				raw, _ := io.ReadAll(logs)
				logs.Close()
				if strings.Contains(string(raw), "polling_since") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s: poller did not start", key)
				}
				time.Sleep(100 * time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			t0 := time.Now()
			change(r)
			p := l.finish(t, key, r)["poll"]
			if p.OK != (until == "until-allowed") || p.SucceededAt == 0 {
				t.Fatalf("%s: change never observed: %+v", key, p)
			}
			ms := int((p.SucceededAt - float64(t0.UnixNano())/1e9) * 1000)
			l.record(key, map[string]any{"latency_ms": ms, "poll_attempts": p.Attempts, "final": p})
			t.Logf("%s: %d ms", key, ms)
		}
		both := []string{"allowed.warden.test", "blocked.warden.test"}
		measure("reload_grant_latency", []string{"allowed.warden.test"}, func(r *labRun) {
			if err := l.pool.Controller.Apply(scheduler.EgressGrant{RunID: r.id, Source: r.source, AllowDomains: both}); err != nil {
				t.Fatal(err)
			}
		}, "until-allowed")
		measure("reload_revoke_latency", both, func(r *labRun) {
			if err := l.pool.Controller.Remove(r.id); err != nil {
				t.Fatal(err)
			}
		}, "until-denied")
	})
}

// TestAPIProcessRuncEgress is the full chain: POST /v1/runs is stored in
// PostgreSQL, Scheduler.Process acquires the EgressPool grant, and the runc
// sandbox reaches Envoy. A direct driver call never enters this path.
func TestAPIProcessRuncEgress(t *testing.T) {
	if os.Getenv("WARDEN_LAB_ACK") != "dedicated-warden-lab" || os.Getenv("WARDEN_EGRESS_DIR") == "" {
		t.Skip("full chain egress: runs only inside `make test-egress-runc`")
	}
	if os.Getenv("WARDEN_TEST_DATABASE_URL") == "" {
		t.Fatal("lab postgres URL missing")
	}
	l := startRuncEgressLab(t)
	pool := testutil.Database(t)
	store := &runs.Store{Pool: pool, Policies: runs.PolicyFunc(func(_ context.Context, id string) (*runs.Policy, error) {
		if id != "fixture-A" {
			return nil, runs.ErrPolicyUnavailable
		}
		return &runs.Policy{TenantID: id, AllowDomains: []string{"allowed.warden.test"}}, nil
	})}
	// TempDir follows the process umask, so a 0022 umask leaves it 0755.
	// The gate requires exactly 0700.
	gateDir := filepath.Join(t.TempDir(), "gate")
	if err := os.Mkdir(gateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(gateDir, "egress-lab", l.driver)
	if err != nil {
		t.Fatal(err)
	}
	worker := &scheduler.Scheduler{Store: store, Drivers: map[string]*gate.Gate{"runc": g}, Node: "egress-lab", Concurrency: 1, PollInterval: 20 * time.Millisecond, OperationTimeout: 20 * time.Second, Egress: l.pool}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- worker.Run(ctx) }()
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(50 * time.Millisecond):
	}
	server := httptest.NewServer(api.New(store, tenant.VerifyFunc(func(_ context.Context, token string) (tenant.Claims, error) {
		if token != "fixture-A" {
			return tenant.Claims{}, errors.New("invalid fixture token")
		}
		return tenant.Claims{TenantID: token}, nil
	})))
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	post := func(key string, probe string) string {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"image_digest":  l.digest,
			"cmd":           []string{"/warden-probe", "egress", l.ca, probe},
			"network":       "allowlist",
			"allow_domains": []string{"allowed.warden.test"},
			"limits":        map[string]any{"memory_mib": 128, "pids": 32, "timeout_s": 60},
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/runs", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fixture-A")
		req.Header.Set("Idempotency-Key", key)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var created struct {
			RunID string `json:"run_id"`
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 201 || created.RunID == "" {
			t.Fatalf("create %s: status %d %s", key, resp.StatusCode, created.Error)
		}
		return created.RunID
	}
	await := func(id string) runs.Run {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+id, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer fixture-A")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var run runs.Run
			err = json.NewDecoder(resp.Body).Decode(&run)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("get %s: status %d %v", id, resp.StatusCode, err)
			}
			switch run.State {
			case "succeeded", "failed", "denied", "interrupted":
				return run
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s still %s", id, run.State)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	grantGone := func(id string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(l.dir, scheduler.LDSFile))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "run_"+id) {
			t.Errorf("grant for %s still in the proxy config", id)
		}
	}
	allowed := post("chain-allow", "reach,connect,allowed.warden.test")
	got := await(allowed)
	text := strings.Join(got.Logs.Lines, "\n")
	if got.State != "succeeded" || got.ErrorCode != "" || got.CleanupPending || got.Result == nil || !got.Result.CgroupEmpty || !strings.Contains(text, "origin-allowed") {
		t.Fatalf("allow chain: state=%s code=%s pending=%v result=%+v logs=%s", got.State, got.ErrorCode, got.CleanupPending, got.Result, text)
	}
	grantGone(allowed)
	l.record("api_allow", map[string]any{"run_id": allowed, "state": got.State})
	blocked := post("chain-block", "block,connect,blocked.warden.test")
	got = await(blocked)
	text = strings.Join(got.Logs.Lines, "\n")
	// The probe exits 0 after printing the denial. The 403 is the proxy's
	// answer, stored with the run, not a sandbox failure.
	if got.State != "succeeded" || got.ErrorCode != "" || got.CleanupPending || got.Result == nil || !got.Result.CgroupEmpty || !strings.Contains(text, `"ok":false`) || !strings.Contains(text, `"proxy_status":403`) {
		t.Fatalf("block chain: state=%s code=%s pending=%v result=%+v logs=%s", got.State, got.ErrorCode, got.CleanupPending, got.Result, text)
	}
	grantGone(blocked)
	l.record("api_block", map[string]any{"run_id": blocked, "state": got.State, "proxy_status": 403})
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not stop")
	}
}
