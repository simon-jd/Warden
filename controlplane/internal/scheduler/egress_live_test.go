package scheduler

// Live egress lab (Task 10), opt-in: WARDEN_LIVE_EGRESS=1 (`make test-egress`).
//
// Topology, all on Docker networks created here and removed at the end:
//
//	sandbox net (--internal, no gateway) ── proxy (Envoy) ── upstream net (--internal)
//	  run A 10.x.y.10, run B .11, unknown .12          origin-allowed: allowed.warden.test, img.cdn.warden.test
//	                                                    origin-blocked: blocked.warden.test
//
// In the first three tests a "sandbox" is a short-lived python container on
// the sandbox network with a fixed source IP; TestRuncSandboxEgress repeats
// them with real runc sandboxes. Nothing in the lab can reach the internet.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	envoyImage  = envOr("WARDEN_ENVOY_IMAGE", "envoyproxy/envoy:v1.40.2")
	originImage = "nginx:1.29-alpine"
	clientImage = "python:3.14.4-alpine"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type egressLab struct {
	prefix, sbx, up, dir string
	subnet               string
	proxyIP              string
	ctl                  *EgressController
	mu                   sync.Mutex
	evidence             map[string]any
}

var (
	labOnce sync.Once
	lab     *egressLab
	labErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if lab != nil {
		if logs, err := docker("logs", lab.prefix+"-proxy"); err == nil {
			lab.record("proxy_access_log", strings.Split(logs, "\n"))
		}
		lab.close()
		// Teardown proof: nothing from this lab or the runc lab wrapper is left.
		left := map[string]string{}
		left["task10_containers"], _ = docker("ps", "-a", "-q", "--filter", "label=warden.test=task10")
		left["project_containers"], _ = docker("ps", "-a", "-q", "--filter", "label=project=warden")
		left["project_images"], _ = docker("image", "ls", "-q", "--filter", "label=project=warden")
		left["lab_networks"], _ = docker("network", "ls", "-q", "--filter", "name="+lab.prefix)
		lab.record("left_after_teardown", left)
		lab.writeEvidence()
	}
	os.Exit(code)
}

func docker(args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("docker %s: %v: %s", strings.Join(args[:min(3, len(args))], " "), err, errb.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func (l *egressLab) ip(last int) string {
	return strings.TrimSuffix(l.subnet, "0/24") + fmt.Sprint(last)
}

func (l *egressLab) record(k string, v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evidence[k] = v
}

func writePEM(t string, path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: t, Bytes: der}), 0o644)
}

// makeCerts writes a throwaway CA and one leaf for every origin name.
func makeCerts(dir string, names []string) error {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "warden-egress-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	// Sign with the parsed CA (which carries the generated SubjectKeyId) so the
	// leaf gets an Authority Key Identifier; Python's strict X.509 mode needs it.
	parent, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, parent, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	if err := writePEM("CERTIFICATE", filepath.Join(dir, "ca.pem"), caDER); err != nil {
		return err
	}
	if err := writePEM("CERTIFICATE", filepath.Join(dir, "origin.pem"), leafDER); err != nil {
		return err
	}
	return writePEM("EC PRIVATE KEY", filepath.Join(dir, "origin.key"), keyDER)
}

func startLab() (*egressLab, error) {
	var tag [4]byte
	_, _ = rand.Read(tag[:])
	l := &egressLab{prefix: "warden-egress-" + hex.EncodeToString(tag[:]), evidence: map[string]any{}}
	l.sbx, l.up = l.prefix+"-sbx", l.prefix+"-up"
	var err error
	if l.dir, err = os.MkdirTemp("", "warden-egress-"); err != nil {
		return nil, err
	}
	for _, sub := range []string{"proxy", "certs", "client"} {
		if err := os.Mkdir(filepath.Join(l.dir, sub), 0o755); err != nil {
			return l, err
		}
	}
	_ = os.Chmod(l.dir, 0o755)
	for range 10 {
		l.subnet = fmt.Sprintf("10.231.%d.0/24", mrand.IntN(250)+2)
		if _, err = docker("network", "create", "--internal", "--label", "warden.test=task10", "--subnet", l.subnet, l.sbx); err == nil {
			break
		}
	}
	if err != nil {
		return l, err
	}
	if _, err := docker("network", "create", "--internal", "--label", "warden.test=task10", l.up); err != nil {
		return l, err
	}
	if err := makeCerts(filepath.Join(l.dir, "certs"), []string{"allowed.warden.test", "img.cdn.warden.test", "blocked.warden.test"}); err != nil {
		return l, err
	}
	probe, err := os.ReadFile("testdata/egress_client.py")
	if err != nil {
		return l, err
	}
	if err := os.WriteFile(filepath.Join(l.dir, "client", "probe.py"), probe, 0o644); err != nil {
		return l, err
	}
	for name, aliases := range map[string][]string{"allowed": {"allowed.warden.test", "img.cdn.warden.test"}, "blocked": {"blocked.warden.test"}} {
		conf := fmt.Sprintf(`server { listen 443 ssl default_server; ssl_certificate /certs/origin.pem; ssl_certificate_key /certs/origin.key;
  default_type text/plain; location / { return 200 "origin-%s\n"; } }
server { listen 80 default_server; default_type text/plain; location / { return 200 "origin-%s\n"; } }
`, name, name)
		path := filepath.Join(l.dir, "certs", name+".conf")
		if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
			return l, err
		}
		args := []string{"run", "-d", "--name", l.prefix + "-origin-" + name, "--label", "warden.test=task10",
			"--network", l.up, "--memory", "64m", "--pids-limit", "64",
			"-v", path + ":/etc/nginx/conf.d/default.conf:ro", "-v", filepath.Join(l.dir, "certs") + ":/certs:ro"}
		for _, a := range aliases {
			args = append(args, "--network-alias", a)
		}
		if _, err := docker(append(args, originImage)...); err != nil {
			return l, err
		}
	}
	if l.ctl, err = NewEgressController(filepath.Join(l.dir, "proxy")); err != nil {
		return l, err
	}
	l.proxyIP = l.ip(2)
	if _, err := docker("run", "-d", "--name", l.prefix+"-proxy", "--label", "warden.test=task10",
		"--network", l.sbx, "--ip", l.proxyIP, "--memory", "256m", "--pids-limit", "256", "--read-only", "--tmpfs", "/tmp",
		"-v", filepath.Join(l.dir, "proxy")+":"+proxyConfigDir+":ro",
		envoyImage, "-c", proxyConfigDir+"/"+BootstrapFile, "--log-level", "warn"); err != nil {
		return l, err
	}
	if _, err := docker("network", "connect", l.up, l.prefix+"-proxy"); err != nil {
		return l, err
	}
	version, _ := docker("run", "--rm", "--network", "none", envoyImage, "--version")
	digests, _ := docker("image", "inspect", "--format", "{{json .RepoDigests}}", envoyImage)
	l.record("envoy_version", version)
	l.record("envoy_image", envoyImage+" "+digests)
	l.record("subnet", l.subnet)
	return l, nil
}

func (l *egressLab) close() {
	for _, c := range []string{"-proxy", "-origin-allowed", "-origin-blocked"} {
		_, _ = docker("rm", "-f", "-v", l.prefix+c)
	}
	_, _ = docker("network", "rm", l.sbx)
	_, _ = docker("network", "rm", l.up)
	if l.dir != "" {
		_ = os.RemoveAll(l.dir)
	}
}

func (l *egressLab) writeEvidence() {
	out := os.Getenv("EGRESS_OUT")
	if out == "" {
		return
	}
	load, _ := os.ReadFile("/proc/loadavg")
	l.record("host", map[string]any{"nproc": runtime.NumCPU(), "loadavg": strings.TrimSpace(string(load))})
	b, _ := json.MarshalIndent(l.evidence, "", "  ")
	_ = os.WriteFile(out, append(b, '\n'), 0o644)
}

func liveLab(t *testing.T) *egressLab {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_EGRESS") != "1" {
		t.Skip("live egress lab: run `make test-egress`")
	}
	labOnce.Do(func() {
		lab, labErr = startLab()
		if labErr == nil {
			labErr = lab.waitReady()
		}
	})
	if labErr != nil {
		t.Fatal(labErr)
	}
	return lab
}

type probe struct {
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
}

func (l *egressLab) clientArgs(src string, detach bool, args ...string) []string {
	run := []string{"run", "--rm", "--label", "warden.test=task10", "--network", l.sbx, "--ip", src,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "64m", "--pids-limit", "32",
		"-v", filepath.Join(l.dir, "client") + ":/probe:ro", "-v", filepath.Join(l.dir, "certs", "ca.pem") + ":/ca.pem:ro"}
	if detach {
		run = append(run[:1], append([]string{"-d"}, run[2:]...)...)
	}
	return append(append(run, clientImage, "python", "-I", "/probe/probe.py"), args...)
}

func (l *egressLab) probe(t *testing.T, key, src string, args ...string) probe {
	t.Helper()
	out, err := docker(l.clientArgs(src, false, args...)...)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var p probe
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &p); err != nil {
		t.Fatalf("%s: bad probe output %q", key, out)
	}
	l.record(key, p)
	return p
}

func (l *egressLab) waitReady() error {
	var out string
	var err error
	for range 60 {
		out, err = docker(l.clientArgs(l.ip(12), false, "http", l.proxyIP, "blocked.warden.test")...)
		// Listener up: an unknown source gets its connection closed or reset
		// by the default deny chain, not refused or timed out.
		if err == nil && (strings.Contains(out, "IndexError") || strings.Contains(out, "ConnectionResetError")) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := docker("logs", "--tail", "30", l.prefix+"-proxy")
	state, _ := docker("inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}}", l.prefix+"-proxy")
	return fmt.Errorf("envoy did not come up (%s); last probe: %q %v\n%s", state, out, err, logs)
}

func (l *egressLab) grant(t *testing.T, run string, last int, domains ...string) {
	t.Helper()
	if err := l.ctl.Apply(EgressGrant{RunID: run, Source: netip.MustParseAddr(l.ip(last)), AllowDomains: domains}); err != nil {
		t.Fatal(err)
	}
}

// waitApplied polls through the proxy until a fresh grant is live, so tests
// do not depend on reload timing (which TestEgressHotReload measures).
func (l *egressLab) waitApplied(t *testing.T, src, host string) {
	t.Helper()
	out, err := docker(l.clientArgs(src, false, "poll", l.proxyIP, host, "/ca.pem")...)
	if err != nil || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("grant for %s never became live: %v %s", host, err, out)
	}
}

func TestAllowlistedDomainReachable(t *testing.T) {
	l := liveLab(t)
	l.grant(t, runA, 10, "allowed.warden.test", "*.cdn.warden.test")
	l.grant(t, runB, 11)
	l.waitApplied(t, l.ip(10), "allowed.warden.test")
	for _, c := range []struct{ key, mode, host string }{
		{"reach_connect_allowed", "connect", "allowed.warden.test"},
		{"reach_connect_wildcard", "connect", "img.cdn.warden.test"},
		{"reach_http_allowed", "http", "allowed.warden.test"},
		{"reach_sni_allowed", "sni", "allowed.warden.test"},
	} {
		p := l.probe(t, c.key, l.ip(10), c.mode, l.proxyIP, c.host, "/ca.pem")
		if !p.OK || p.Body != "origin-allowed" {
			t.Errorf("%s: %+v", c.key, p)
		}
	}
}

func TestNonAllowlistedBlocked(t *testing.T) {
	l := liveLab(t)
	l.grant(t, runA, 10, "allowed.warden.test", "*.cdn.warden.test")
	l.grant(t, runB, 11)
	l.waitApplied(t, l.ip(10), "allowed.warden.test")
	originIP, err := docker("inspect", "--format", "{{(index .NetworkSettings.Networks \""+l.up+"\").IPAddress}}", l.prefix+"-origin-blocked")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key, src, mode, host, extra string
		check                       func(probe) bool
	}{
		{"block_connect_other_domain", l.ip(10), "connect", "blocked.warden.test", "", func(p probe) bool { return p.ProxyStatus == 403 }},
		{"block_connect_suffix_trick", l.ip(10), "connect", "allowed.warden.test.blocked.warden.test", "", func(p probe) bool { return p.ProxyStatus == 403 }},
		{"block_http_other_domain", l.ip(10), "http", "blocked.warden.test", "", func(p probe) bool { return p.Status == 403 }},
		{"block_sni_other_domain", l.ip(10), "sni", "blocked.warden.test", "", func(p probe) bool { return !p.OK && p.Error != "" }},
		// Domain fronting: SNI allowed, Host blocked. The connection follows SNI,
		// so the request lands on the allowed origin, never on blocked's server.
		{"front_sni_allowed_host_blocked", l.ip(10), "front", "allowed.warden.test", "blocked.warden.test", func(p probe) bool { return p.Body != "origin-blocked" }},
		{"block_run_b_no_domains", l.ip(11), "connect", "allowed.warden.test", "", func(p probe) bool { return p.ProxyStatus == 403 }},
		{"block_run_b_sni", l.ip(11), "sni", "allowed.warden.test", "", func(p probe) bool { return !p.OK && p.Error != "" }},
		{"block_unknown_source", l.ip(12), "connect", "allowed.warden.test", "", func(p probe) bool { return !p.OK && p.ProxyStatus == 0 }},
		{"block_direct_bypass", l.ip(10), "direct", "blocked.warden.test", originIP, func(p probe) bool { return !p.OK && p.Resolved == "" }},
	}
	for _, c := range cases {
		args := []string{c.mode, l.proxyIP, c.host, "/ca.pem"}
		if c.extra != "" {
			args = append(args, c.extra)
		}
		if p := l.probe(t, c.key, c.src, args...); !c.check(p) {
			t.Errorf("%s: not blocked: %+v", c.key, p)
		}
	}
}

// TestRuncSandboxEgress repeats the three tests above with real runc
// sandboxes instead of python containers (`make test-egress-runc`). The
// dedicated runc lab container (scripts/runtime_lab_docker.py egress) joins
// the sandbox network at .3 and shares the Envoy config directory; inside it,
// TestRuncEgressAllowlist starts every probe as a runc run in Network
// "allowlist" and drives the grants through EgressPool. Its results land in
// the config directory as runc-result.json.
func TestRuncSandboxEgress(t *testing.T) {
	if os.Getenv("WARDEN_LIVE_EGRESS_RUNC") != "1" {
		t.Skip("live runc egress lab: run `make test-egress-runc`")
	}
	l := liveLab(t)
	proxyDir := filepath.Join(l.dir, "proxy")
	ca, err := os.ReadFile(filepath.Join(l.dir, "certs", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proxyDir, "ca.pem"), ca, 0o644); err != nil {
		t.Fatal(err)
	}
	originIP, err := docker("inspect", "--format", "{{(index .NetworkSettings.Networks \""+l.up+"\").IPAddress}}", l.prefix+"-origin-blocked")
	if err != nil {
		t.Fatal(err)
	}
	// Envoy 256 MiB + two origins at 64 MiB run beside the 4 GB lab.
	start := time.Now()
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/python3", "-B", filepath.Join(repo, "scripts/runtime_lab_docker.py"), "egress",
		"--other-service-memory-bytes", fmt.Sprint(384<<20),
		"--egress-network", l.sbx, "--egress-ip", l.ip(3), "--egress-dir", proxyDir,
		"--egress-prefix", l.subnet, "--egress-proxy", l.proxyIP, "--egress-origin", originIP)
	out, runErr := cmd.CombinedOutput()
	l.record("runc_lab_seconds", time.Since(start).Seconds())
	if path := os.Getenv("EGRESS_OUT"); path != "" {
		_ = os.WriteFile(strings.TrimSuffix(path, ".json")+"-lab.log", out, 0o644)
	}
	var result map[string]any
	if b, err := os.ReadFile(filepath.Join(proxyDir, "runc-result.json")); err == nil {
		_ = json.Unmarshal(b, &result)
	}
	l.record("runc", result)
	b, err := os.ReadFile(filepath.Join(proxyDir, "api-chain-result.json"))
	if err != nil {
		t.Fatal("api chain left no result")
	}
	var chain map[string]any
	if err := json.Unmarshal(b, &chain); err != nil || chain["api_allow"] == nil || chain["api_block"] == nil {
		t.Fatal("api chain result missing the allow and block runs")
	}
	l.record("api_chain", chain)
	tail := string(out)
	if len(tail) > 6000 {
		tail = tail[len(tail)-6000:]
	}
	if runErr != nil || !strings.Contains(string(out), "--- PASS: TestRuncEgressAllowlist") || !strings.Contains(string(out), "--- PASS: TestAPIProcessRuncEgress") {
		t.Fatalf("runc egress lab failed: %v\n%s", runErr, tail)
	}
	if result == nil {
		t.Fatal("runc egress lab left no result")
	}
}

// TestEgressHotReload measures how long a grant and a revocation take to
// reach live traffic through Envoy's watched-directory LDS.
func TestEgressHotReload(t *testing.T) {
	l := liveLab(t)
	l.grant(t, runA, 10, "allowed.warden.test")
	l.waitApplied(t, l.ip(10), "allowed.warden.test")
	measure := func(key string, change func(), until string) {
		args := []string{"poll", l.proxyIP, "blocked.warden.test", "/ca.pem"}
		if until != "" {
			args = append(args, until)
		}
		id, err := docker(l.clientArgs(l.ip(10), true, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = docker("rm", "-f", id) }()
		// Let the poller observe the old state for a moment before the change.
		deadline := time.Now().Add(20 * time.Second)
		for {
			logs, _ := docker("logs", id)
			if strings.Contains(logs, "polling_since") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: poller did not start", key)
			}
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)
		t0 := time.Now()
		change()
		if _, err := docker("wait", id); err != nil {
			t.Fatal(err)
		}
		logs, _ := docker("logs", id)
		lines := strings.Split(logs, "\n")
		var p probe
		_ = json.Unmarshal([]byte(lines[len(lines)-1]), &p)
		want := until == ""
		if p.OK != want || p.SucceededAt == 0 {
			t.Fatalf("%s: change never observed: %s", key, logs)
		}
		latency := p.SucceededAt - float64(t0.UnixNano())/1e9
		l.record(key, map[string]any{"latency_ms": int(latency * 1000), "poll_attempts": p.Attempts, "final": p})
		t.Logf("%s: %.0f ms", key, latency*1000)
	}
	measure("reload_grant_latency", func() { l.grant(t, runA, 10, "allowed.warden.test", "blocked.warden.test") }, "")
	measure("reload_revoke_latency", func() {
		if err := l.ctl.Remove(runA); err != nil {
			t.Fatal(err)
		}
	}, "until-denied")
}
