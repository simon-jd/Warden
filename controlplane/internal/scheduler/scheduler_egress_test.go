package scheduler_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/runtimes"
)

// Break caught: an allowlist run starts without a proxy grant, keeps its grant
// after it ends, or reuses an address whose sandbox may still be alive.
func TestAllowlistRunHoldsEgressGrantForItsLifetime(t *testing.T) {
	body := strings.TrimSuffix(valid, "}") + `,"network":"allowlist","allow_domains":["allowed.warden.test"]}`
	policy := runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
		return &runs.Policy{TenantID: "A", AllowDomains: []string{"allowed.warden.test"}}, nil
	})
	createAllowlist := func(t *testing.T, s *runs.Store, key string) string {
		t.Helper()
		spec, e := runs.Normalize([]byte(body))
		if e != nil {
			t.Fatal(e)
		}
		id, e := s.Create(context.Background(), "A", key, spec)
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	pool := func(t *testing.T) (*scheduler.EgressPool, string) {
		t.Helper()
		dir := t.TempDir()
		ctl, e := scheduler.NewEgressController(dir)
		if e != nil {
			t.Fatal(e)
		}
		return &scheduler.EgressPool{Controller: ctl, Sources: []netip.Addr{netip.MustParseAddr("10.231.7.64")}}, dir
	}
	lds := func(t *testing.T, dir string) string {
		t.Helper()
		b, e := os.ReadFile(filepath.Join(dir, scheduler.LDSFile))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	t.Run("granted-then-revoked", func(t *testing.T) {
		f := &fakeRuntime{started: make(chan runtimes.Spec, 1), release: make(chan struct{}), exit: runtimes.Exit{CgroupEmpty: true}}
		w, s := setup(t, f)
		s.Policies = policy
		var dir string
		w.Egress, dir = pool(t)
		id := createAllowlist(t, s, "allow")
		done := make(chan error, 1)
		go func() { done <- w.Process(context.Background(), id) }()
		spec := <-f.started
		if spec.EgressSource.String() != "10.231.7.64" || spec.Network != "allowlist" || len(spec.AllowDomains) != 1 {
			t.Fatalf("driver spec %+v", spec)
		}
		if live := lds(t, dir); !strings.Contains(live, "run_"+id) || !strings.Contains(live, `"address_prefix": "10.231.7.64"`) {
			t.Fatalf("grant not live while the run starts:\n%s", live)
		}
		close(f.release)
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if r := read(t, s, id); r.State != "succeeded" {
			t.Fatalf("run %+v", r)
		}
		if live := lds(t, dir); strings.Contains(live, "run_"+id) {
			t.Fatalf("grant survived the run:\n%s", live)
		}
		verify(t, s)
	})
	t.Run("pending-cleanup-quarantines-address", func(t *testing.T) {
		f := &fakeRuntime{exit: runtimes.Exit{CgroupEmpty: false}, waitErr: errors.New("lost")}
		w, s := setup(t, f)
		s.Policies = policy
		var dir string
		w.Egress, dir = pool(t)
		first := createAllowlist(t, s, "first")
		if e := w.Process(context.Background(), first); e != nil {
			t.Fatal(e)
		}
		if r := read(t, s, first); !r.CleanupPending {
			t.Fatalf("first run %+v", r)
		}
		if live := lds(t, dir); strings.Contains(live, "run_"+first) {
			t.Fatalf("grant survived a run with pending cleanup:\n%s", live)
		}
		second := createAllowlist(t, s, "second")
		if e := w.Process(context.Background(), second); e != nil {
			t.Fatal(e)
		}
		if r := read(t, s, second); r.State != "failed" || r.ErrorCode != "egress_unavailable" || f.starts.Load() != 1 {
			t.Fatalf("quarantined address reused: %+v starts=%d", r, f.starts.Load())
		}
		verify(t, s)
	})
	t.Run("no-pool-fails-closed", func(t *testing.T) {
		f := &fakeRuntime{}
		w, s := setup(t, f)
		s.Policies = policy
		id := createAllowlist(t, s, "nopool")
		if e := w.Process(context.Background(), id); e != nil {
			t.Fatal(e)
		}
		if r := read(t, s, id); r.State != "failed" || r.ErrorCode != "egress_unavailable" || f.starts.Load() != 0 {
			t.Fatalf("run %+v starts=%d", r, f.starts.Load())
		}
		verify(t, s)
	})
}
