package gvisor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/attacks/matrix"
	"warden/runtimes"
	"warden/runtimes/conformance"
	"warden/runtimes/gate"
)

// Live tests against the k3s + gVisor lab (scripts/k3s_gvisor_lab.sh, which
// writes the WARDEN_GVISOR_* variables). `make test-gvisor` runs them.

func labEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s not set: run through make test-gvisor (scripts/k3s_gvisor_lab.sh env)", key)
	}
	return v
}

// labKubeconfig reads the one cluster and user k3s writes, with inline
// credentials; the server must be https.
func labKubeconfig(t *testing.T, path string) (server string, ca, cert, key []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	clusters := 0
	fields := map[string]*[]byte{"certificate-authority-data": &ca, "client-certificate-data": &cert, "client-key-data": &key}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "- cluster:" {
			clusters++
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if k == "server" {
			server = v
		} else if dst, ok := fields[k]; ok {
			if *dst, err = base64.StdEncoding.DecodeString(v); err != nil {
				t.Fatalf("kubeconfig %s: %v", k, err)
			}
		}
	}
	if u, err := url.Parse(server); clusters != 1 || err != nil || u.Scheme != "https" || len(ca) == 0 || len(cert) == 0 || len(key) == 0 {
		t.Fatalf("kubeconfig: want one https cluster with inline credentials (clusters=%d server=%q)", clusters, server)
	}
	return server, ca, cert, key
}

// labGate builds the driver from the lab's kubeconfig and binds it, through
// gvisor.Bind, to the identity the lab recorded. The gate directory is
// fresh per test: every run ID is consumed once.
func labGate(t *testing.T) (*Driver, *gate.Gate) {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_GVISOR") != "1" {
		t.Skip("live gVisor lab test: needs WARDEN_LIVE_GVISOR=1 and the lab of scripts/k3s_gvisor_lab.sh (make test-gvisor)")
	}
	server, ca, cert, key := labKubeconfig(t, labEnv(t, "WARDEN_GVISOR_KUBECONFIG"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("kubeconfig CA is not PEM")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	httpc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}}
	id := BackendIdentity{APIServer: server, ClusterUID: labEnv(t, "WARDEN_GVISOR_CLUSTER_UID"), Namespace: "warden-lab",
		NamespaceUID: labEnv(t, "WARDEN_GVISOR_NAMESPACE_UID"), NodeName: labEnv(t, "WARDEN_GVISOR_NODE"),
		NodeUID: labEnv(t, "WARDEN_GVISOR_NODE_UID"), NodeConfigSHA256: labEnv(t, "WARDEN_GVISOR_NODE_CONFIG_SHA256")}
	sum := sha256.Sum256(ca)
	id.CASHA256 = hex.EncodeToString(sum[:])
	d, err := New(Config{Server: server, HTTP: httpc, Namespace: id.Namespace, Repository: "docker.io/warden-lab/probe",
		NodeName: id.NodeName, ExpectClusterUID: id.ClusterUID, ExpectNamespaceUID: id.NamespaceUID, ExpectNodeUID: id.NodeUID, PullPolicy: "Never"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() + "/gate"
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { // the mkdir mode is masked
		t.Fatal(err)
	}
	g, err := Bind(dir, id.NodeName, id, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_LAB_ACK", "dedicated-warden-lab")
	t.Setenv("WARDEN_LAB_IMAGE_DIGEST", labEnv(t, "WARDEN_LAB_IMAGE_DIGEST"))
	return d, g
}

// recorder keeps every handle so the test can check the node afterwards.
type recorder struct {
	rt   runtimes.Runtime
	mu   sync.Mutex
	runs []*Run
}

func (r *recorder) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	h, err := r.rt.Start(ctx, s)
	if run, ok := h.(*Run); ok {
		r.mu.Lock()
		r.runs = append(r.runs, run)
		r.mu.Unlock()
	}
	return h, err
}

// podCgroupGone asks the node container whether the pod's cgroup is still
// there. Outside the driver's view: it backs the claim that a deleted pod
// object means a removed pod cgroup.
func podCgroupGone(t *testing.T, podUID string) bool {
	t.Helper()
	node := labEnv(t, "WARDEN_GVISOR_NODE_CONTAINER")
	out, err := exec.Command("docker", "exec", node, "find", "/sys/fs/cgroup/kubepods", "-maxdepth", "2", "-name", "pod"+podUID).CombinedOutput()
	if err != nil {
		t.Fatalf("node check: %v %s", err, out)
	}
	return strings.TrimSpace(string(out)) == ""
}

func TestGVisorConformance(t *testing.T) {
	_, g := labGate(t)
	rec := &recorder{rt: g}
	conformance.Run(t, rec)
	if len(rec.runs) != 7 {
		t.Fatalf("%d runs started, want 7", len(rec.runs))
	}
	for _, r := range rec.runs {
		tm := r.Timings()
		gone := podCgroupGone(t, tm.PodUID)
		exec := "n/a (no supervisor report)"
		if tm.ExecUnixNano != 0 {
			exec = fmt.Sprintf("%.2f ms", float64(tm.ExecUnixNano-tm.StartUnixNano)/1e6)
		}
		t.Logf("run %s pod %s: pod cgroup on the node gone=%v start->exec=%s", r.spec.Cmd[1], tm.PodUID, gone, exec)
		if !gone {
			t.Errorf("pod %s: cgroup still on the node after the pod object was deleted", tm.PodUID)
		}
	}
	matrix.RunFromEnv(t, g, "gvisor")
}

// quantiles is CompareStarts' method (runtimes/firecracker): the median is
// the mean of the two middle values for an even count, p95 is nearest rank.
func quantiles(in []float64) (p50, p95 float64) {
	a := append([]float64(nil), in...)
	sort.Float64s(a)
	p50 = a[len(a)/2]
	if len(a)%2 == 0 {
		p50 = (a[len(a)/2-1] + p50) / 2
	}
	return p50, a[(95*len(a)+99)/100-1]
}

func TestQuantilesMatchFirecrackerMethod(t *testing.T) {
	v := make([]float64, 20)
	for i := range v {
		v[i] = float64(20 - i)
	}
	if p50, p95 := quantiles(v); p50 != 10.5 || p95 != 19 {
		t.Fatalf("p50=%v p95=%v", p50, p95)
	}
}

func loadavg() string {
	b, _ := os.ReadFile("/proc/loadavg")
	return strings.TrimSpace(string(b))
}

// TestGVisorColdStarts runs WARDEN_GVISOR_COLD_STARTS serial runs of the
// uid probe in the default Firecracker-sized spec (512 MiB payload, 1 CPU),
// each a new Job, Pod and gVisor sandbox with the image already on the node.
// GVISOR_OUT gets one JSON line per run and a summary line.
func TestGVisorColdStarts(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("WARDEN_GVISOR_COLD_STARTS"))
	if n == 0 {
		t.Skip("cold-start series: set WARDEN_GVISOR_COLD_STARTS=<n> (make test-gvisor GVISOR_COLD_STARTS=100)")
	}
	_, g := labGate(t)
	out := io.Discard
	if p := os.Getenv("GVISOR_OUT"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	digest := labEnv(t, "WARDEN_LAB_IMAGE_DIGEST")
	ms := func(a, b int64) float64 { return float64(b-a) / 1e6 }
	var toInit, toExec, toWait []float64
	loadStart := loadavg()
	began := time.Now()
	for i := 1; i <= n; i++ {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		s := runtimes.Spec{RunID: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]), ImageDigest: digest,
			Cmd: []string{"/warden-probe", "uid"}, Limits: runtimes.Limits{CPU: 1, MemoryMiB: 512, Pids: 32, TimeoutS: 30}, Network: "none"}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		h, err := g.Start(ctx, s)
		if err != nil {
			cancel()
			t.Fatalf("run %d start: %v", i, err)
		}
		exit, err := h.Wait(ctx)
		raw, _ := io.ReadAll(h.Logs())
		cancel()
		if err != nil || exit.Code != 0 || !exit.CgroupEmpty || string(raw) != "PASS uid\n" {
			h.Kill()
			t.Fatalf("run %d: %v exit=%+v logs=%q", i, err, exit, raw)
		}
		if err := g.Reap(context.Background(), s.RunID); err != nil {
			t.Fatalf("run %d reap: %v", i, err)
		}
		tm := h.(*Run).Timings()
		if !(tm.StartUnixNano < tm.InitUnixNano && tm.InitUnixNano < tm.ExecUnixNano && tm.ExecUnixNano < tm.WaitUnixNano) {
			t.Fatalf("run %d: timestamps out of order %+v", i, tm)
		}
		toInit = append(toInit, ms(tm.StartUnixNano, tm.InitUnixNano))
		toExec = append(toExec, ms(tm.StartUnixNano, tm.ExecUnixNano))
		toWait = append(toWait, ms(tm.StartUnixNano, tm.WaitUnixNano))
		enc.Encode(map[string]any{"i": i, "run_id": s.RunID, "pod_uid": tm.PodUID, "start_ns": tm.StartUnixNano, "init_ns": tm.InitUnixNano,
			"exec_ns": tm.ExecUnixNano, "wait_ns": tm.WaitUnixNano, "start_to_init_ms": toInit[i-1], "start_to_exec_ms": toExec[i-1],
			"start_to_wait_ms": toWait[i-1], "exit": exit})
	}
	summary := map[string]any{"summary": true, "runs": n, "began": began.Format(time.RFC3339), "ended": time.Now().Format(time.RFC3339),
		"loadavg_start": loadStart, "loadavg_end": loadavg()}
	for name, v := range map[string][]float64{"start_to_init_ms": toInit, "start_to_exec_ms": toExec, "start_to_wait_ms": toWait} {
		p50, p95 := quantiles(v)
		lo, hi := v[0], v[0]
		for _, x := range v {
			lo, hi = min(lo, x), max(hi, x)
		}
		summary[name] = map[string]float64{"p50": p50, "p95": p95, "min": lo, "max": hi}
	}
	enc.Encode(summary)
	b, _ := json.Marshal(summary)
	t.Logf("cold starts: %s", b)
	fmt.Fprintln(os.Stderr, string(b))
}
