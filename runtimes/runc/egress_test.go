package runc

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"warden/runtimes"
)

const testRun = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func allowlistSpec() runtimes.Spec {
	s := validSpec()
	s.Network = "allowlist"
	s.AllowDomains = []string{"allowed.warden.test"}
	s.EgressSource = netip.MustParseAddr("10.231.7.64")
	return s
}

// fakeIP is an `ip` stand-in that appends its argv to a log and fails when
// argv contains the configured marker.
func fakeIP(t *testing.T, failOn string) (string, func() []string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n"
	if failOn != "" {
		script += "case \"$*\" in *'" + failOn + "'*) echo boom >&2; exit 2;; esac\n"
	}
	path := filepath.Join(dir, "ip")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, func() []string {
		b, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

func testEgress(ipPath string) *EgressNetwork {
	return &EgressNetwork{IPPath: ipPath, Parent: "eth0", Prefix: netip.MustParsePrefix("10.231.7.0/24"), Proxy: netip.MustParseAddrPort("10.231.7.2:3128")}
}

func TestAllowlistSpecJoinsAttachedNetnsWithProxyEnv(t *testing.T) {
	s, err := buildSpec(allowlistSpec(), "/warden-lab/warden-"+testRun, "/run/netns/warden-"+testRun, "http://10.231.7.2:3128")
	if err != nil {
		t.Fatal(err)
	}
	var netns string
	for _, n := range s.Linux.Namespaces {
		if n.Type == "network" {
			netns = n.Path
		} else if n.Path != "" {
			t.Fatalf("non-network namespace %s reuses a path", n.Type)
		}
	}
	if netns != "/run/netns/warden-"+testRun {
		t.Fatalf("network namespace path %q", netns)
	}
	for _, v := range []string{"HTTPS_PROXY=http://10.231.7.2:3128", "https_proxy=http://10.231.7.2:3128", "HTTP_PROXY=http://10.231.7.2:3128", "http_proxy=http://10.231.7.2:3128"} {
		if !slices.Contains(s.Process.Env, v) {
			t.Fatalf("missing %s in %v", v, s.Process.Env)
		}
	}
	// No host bind mounts on the allowlist path either.
	for _, m := range s.Mounts {
		if m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind") {
			t.Fatalf("allowlist sandbox bind-mounts %s", m.Destination)
		}
	}
	// The allowlist path must not loosen anything else.
	caps := s.Process.Capabilities
	if len(caps.Bounding)+len(caps.Effective)+len(caps.Permitted) != 0 || s.Process.User.UID != 65534 || !s.Root.Readonly || !s.Process.NoNewPrivileges {
		t.Fatal("allowlist spec loosened process security")
	}
	for _, bad := range []struct{ netns, proxy string }{
		{"", "http://10.231.7.2:3128"},
		{"/run/netns/other", "http://10.231.7.2:3128"},
		{"/proc/1/ns/net", "http://10.231.7.2:3128"},
		{"/run/netns/warden-" + testRun, ""},
	} {
		if _, err := buildSpec(allowlistSpec(), "/warden-lab/warden-"+testRun, bad.netns, bad.proxy); err == nil {
			t.Fatalf("accepted netns=%q proxy=%q", bad.netns, bad.proxy)
		}
	}
	// network none never gets a namespace path or proxy variables.
	if _, err := buildSpec(validSpec(), "/warden-lab/warden-"+testRun, "/run/netns/warden-"+testRun, "http://10.231.7.2:3128"); err == nil {
		t.Fatal("network none accepted an attached namespace")
	}
	none := allowlistSpec()
	none.EgressSource = netip.Addr{}
	if _, err := buildSpec(none, "/warden-lab/warden-"+testRun, "/run/netns/warden-"+testRun, "http://10.231.7.2:3128"); err == nil {
		t.Fatal("allowlist without a scheduler-assigned source accepted")
	}
}

func TestEgressNetworkValidation(t *testing.T) {
	ok := testEgress("/usr/bin/ip")
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*EgressNetwork){
		"relative-ip":     func(e *EgressNetwork) { e.IPPath = "ip" },
		"parent-flag":     func(e *EgressNetwork) { e.Parent = "-all" },
		"parent-long":     func(e *EgressNetwork) { e.Parent = "abcdefghijklmnop" },
		"ipv6-prefix":     func(e *EgressNetwork) { e.Prefix = netip.MustParsePrefix("fd00::/64") },
		"proxy-outside":   func(e *EgressNetwork) { e.Proxy = netip.MustParseAddrPort("10.9.9.2:3128") },
		"proxy-no-port":   func(e *EgressNetwork) { e.Proxy = netip.MustParseAddrPort("10.231.7.2:0") },
		"prefix-too-wide": func(e *EgressNetwork) { e.Prefix = netip.MustParsePrefix("10.0.0.0/8") },
	} {
		e := testEgress("/usr/bin/ip")
		mutate(e)
		if err := e.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAttachRunsFixedIPCommands(t *testing.T) {
	path, calls := fakeIP(t, "")
	e := testEgress(path)
	ns, err := e.attach(context.Background(), testRun, netip.MustParseAddr("10.231.7.64"))
	if err != nil {
		t.Fatal(err)
	}
	if ns != "/run/netns/warden-"+testRun {
		t.Fatalf("netns path %q", ns)
	}
	want := []string{
		"netns add warden-" + testRun,
		"link add link eth0 name wdABCDEFGHIJKL type ipvlan mode l2 private",
		"link set wdABCDEFGHIJKL netns warden-" + testRun,
		"-n warden-" + testRun + " link set lo up",
		"-n warden-" + testRun + " addr add 10.231.7.64/24 dev wdABCDEFGHIJKL",
		"-n warden-" + testRun + " link set wdABCDEFGHIJKL up",
	}
	if got := calls(); !slices.Equal(got, want) {
		t.Fatalf("ip calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range calls() {
		if strings.Contains(c, "route") {
			t.Fatalf("sandbox must have no route beyond its subnet: %s", c)
		}
	}
	if err := e.detach(context.Background(), testRun); err != nil {
		t.Fatal(err)
	}
	if got := calls(); got[len(got)-1] != "netns del warden-"+testRun {
		t.Fatalf("detach: %v", got)
	}
}

func TestAttachRejectsBadSourceBeforeAnyCommand(t *testing.T) {
	path, calls := fakeIP(t, "")
	e := testEgress(path)
	for _, src := range []string{"10.231.8.64", "10.231.7.0", "10.231.7.255", "10.231.7.2", "::1"} {
		if _, err := e.attach(context.Background(), testRun, netip.MustParseAddr(src)); err == nil {
			t.Errorf("source %s accepted", src)
		}
	}
	if _, err := e.attach(context.Background(), "../x", netip.MustParseAddr("10.231.7.64")); err == nil {
		t.Error("bad run ID accepted")
	}
	if got := calls(); len(got) != 1 || got[0] != "" {
		t.Fatalf("commands ran for rejected input: %v", got)
	}
}

func TestAttachFailureRemovesNamespace(t *testing.T) {
	path, calls := fakeIP(t, "addr add")
	e := testEgress(path)
	if _, err := e.attach(context.Background(), testRun, netip.MustParseAddr("10.231.7.64")); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected ip failure, got %v", err)
	}
	got := calls()
	if got[len(got)-1] != "netns del warden-"+testRun {
		t.Fatalf("namespace not removed after failure: %v", got)
	}
}

func TestStartAllowlistNeedsEgressConfig(t *testing.T) {
	name, _ := temporarySocket(t)
	d, e := New(socketConfig(name))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Start(context.Background(), allowlistSpec()); e == nil || !strings.Contains(e.Error(), "egress") {
		t.Fatalf("allowlist run started without an egress network: %v", e)
	}
	cfg := socketConfig(name)
	cfg.Egress = &EgressNetwork{IPPath: "ip"}
	if _, e = New(cfg); e == nil {
		t.Fatal("invalid egress network accepted")
	}
}
