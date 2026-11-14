package scheduler

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

const runC = "CCCCCCCCCCCCCCCCCCCCCCCCCC"

func newPool(t *testing.T, addrs ...string) (*EgressPool, string) {
	t.Helper()
	dir := t.TempDir()
	ctl, err := NewEgressController(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &EgressPool{Controller: ctl}
	for _, a := range addrs {
		p.Sources = append(p.Sources, netip.MustParseAddr(a))
	}
	return p, dir
}

func liveChains(t *testing.T, dir string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, LDSFile))
	if err != nil {
		t.Fatal(err)
	}
	_, chains := decodeLDS(t, b)
	out := map[string]string{}
	for _, c := range chains[HTTPProxyListener] {
		out[c.Name] = c.Match.Sources[0].Prefix
	}
	return out
}

func TestEgressPoolGrantsSourceForRunLifetime(t *testing.T) {
	p, dir := newPool(t, "10.231.7.64", "10.231.7.65")
	a, err := p.Acquire(runA, []string{"allowed.warden.test"})
	if err != nil || a.String() != "10.231.7.64" {
		t.Fatalf("acquire A: %v %v", a, err)
	}
	if got := liveChains(t, dir); got["run_"+runA] != "10.231.7.64" {
		t.Fatalf("grant for A not live: %v", got)
	}
	if _, err := p.Acquire(runA, []string{"allowed.warden.test"}); err == nil {
		t.Fatal("second acquire for the same run accepted")
	}
	b, err := p.Acquire(runB, []string{"allowed.warden.test"})
	if err != nil || b.String() != "10.231.7.65" {
		t.Fatalf("acquire B: %v %v", b, err)
	}
	if _, err := p.Acquire(runC, []string{"allowed.warden.test"}); err == nil {
		t.Fatal("exhausted pool handed out an address")
	}
	// A ended with its sandbox gone: grant revoked, address reusable.
	if err := p.Release(runA, true); err != nil {
		t.Fatal(err)
	}
	if got := liveChains(t, dir); got["run_"+runA] != "" || got["run_"+runB] == "" {
		t.Fatalf("after release A: %v", got)
	}
	c, err := p.Acquire(runC, []string{"allowed.warden.test"})
	if err != nil || c != a {
		t.Fatalf("freed address not reused: %v %v", c, err)
	}
	// B ended with cleanup pending: grant revoked, address never reissued.
	if err := p.Release(runB, false); err != nil {
		t.Fatal(err)
	}
	if got := liveChains(t, dir); got["run_"+runB] != "" {
		t.Fatalf("pending-cleanup run kept its grant: %v", got)
	}
	if err := p.Release(runC, true); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Acquire(runB, []string{"allowed.warden.test"}); err != nil || got != a {
		t.Fatalf("quarantined address reissued or pool broken: %v %v", got, err)
	}
	if err := p.Release("ZZZZZZZZZZZZZZZZZZZZZZZZZZ", true); err != nil {
		t.Fatalf("releasing an unknown run: %v", err)
	}
}

func TestEgressPoolRejectsBadGrantWithoutConsumingAddress(t *testing.T) {
	p, dir := newPool(t, "10.231.7.64")
	for _, domains := range [][]string{nil, {"http://x.example.com"}, {"10.0.0.1"}} {
		if _, err := p.Acquire(runA, domains); err == nil {
			t.Fatalf("grant %v accepted", domains)
		}
	}
	if got := liveChains(t, dir); len(got) != 0 {
		t.Fatalf("rejected grant left a chain: %v", got)
	}
	if a, err := p.Acquire(runA, []string{"allowed.warden.test"}); err != nil || a.String() != "10.231.7.64" {
		t.Fatalf("address consumed by rejected grant: %v %v", a, err)
	}
	var nilPool *EgressPool
	if _, err := nilPool.Acquire(runB, []string{"allowed.warden.test"}); err == nil {
		t.Fatal("nil pool handed out an address")
	}
}
