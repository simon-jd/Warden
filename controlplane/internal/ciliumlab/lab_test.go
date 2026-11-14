package ciliumlab

// The live harness: the k3s lab of scripts/k3s_gvisor_lab.sh up --cilium,
// driven through kubectl and cilium-dbg in the node container (docker exec)
// and the API server (the respond adapter's requests). Every test creates
// its own pods and policies and removes them when it ends; the egress proxy
// is shared and removed by TestMain.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/controlplane/internal/scheduler"
	"warden/respond/kindlab"
)

const (
	sandboxNS = "warden-lab" // created by the lab
	proxyNS   = "warden-system"
	proxyName = "warden-egress"
	// The sandboxes' proxy address: an absolute name, so the resolver asks
	// for exactly the name policies/cilium/default-deny.yaml allows.
	proxyHost  = "warden-egress.warden-system.svc.cluster.local."
	proxyAddr  = proxyHost + ":3128"
	envoyImage = "docker.io/envoyproxy/envoy:v1.40.2" // imported by the lab (scripts/restore-tools.sh cilium)
	policyDir  = "../../../policies/cilium"
	// The lab's stand-ins (scripts/k3s_gvisor_lab.sh, world.py).
	originAllowed = "warden-k3s-origin-allowed"
	originBlocked = "warden-k3s-origin-blocked"
	streamServer  = "warden-k3s-stream"
	imds          = "warden-k3s-imds"
	dnsSink       = "warden-k3s-dns"
)

type lab struct {
	t       testing.TB
	node    string // the node container
	world   string // the world network's /24 prefix, e.g. 198.18.18
	apiHost string
	digest  string // the probe image
	cluster kindlab.Cluster
}

func env(t testing.TB, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s is not set: run through `scripts/k3s_gvisor_lab.sh env` (make test-cilium)", k)
	}
	return v
}

func liveLab(t testing.TB) *lab {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_CILIUM") != "1" {
		t.Skip("live Cilium test: needs WARDEN_LIVE_CILIUM=1 and scripts/k3s_gvisor_lab.sh up --cilium (make test-cilium)")
	}
	if env(t, "WARDEN_K3S_CNI") != "cilium" {
		t.Fatal("the lab is not in Cilium mode: scripts/k3s_gvisor_lab.sh up --cilium")
	}
	raw, err := os.ReadFile(env(t, "WARDEN_GVISOR_KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := kindlab.ParseKubeconfigFor(raw, env(t, "WARDEN_GVISOR_API_HOST"))
	if err != nil {
		t.Fatal(err)
	}
	return &lab{t: t, node: env(t, "WARDEN_GVISOR_NODE_CONTAINER"), world: env(t, "WARDEN_CILIUM_WORLD_PREFIX"),
		apiHost: env(t, "WARDEN_GVISOR_API_HOST"), digest: env(t, "WARDEN_LAB_IMAGE_DIGEST"), cluster: c}
}

// docker runs docker with stdin and returns stdout; stderr goes into the error.
func docker(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (l *lab) kubectl(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pre := []string{"exec"}
	if stdin != nil {
		pre = append(pre, "-i")
	}
	return docker(ctx, stdin, append(append(pre, l.node, "kubectl"), args...)...)
}

func (l *lab) must(out []byte, err error) []byte {
	l.t.Helper()
	if err != nil {
		l.t.Fatal(err)
	}
	return out
}

func (l *lab) apply(obj any) {
	l.t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		l.t.Fatal(err)
	}
	l.must(l.kubectl(b, "apply", "-f", "-"))
}

func (l *lab) ciliumDbg(args ...string) ([]byte, error) {
	return l.kubectl(nil, append([]string{"-n", "kube-system", "exec", "ds/cilium", "-c", "cilium-agent", "--", "cilium-dbg"}, args...)...)
}

// --- policies ----------------------------------------------------------------

var policyName = regexp.MustCompile(`(?m)^metadata:\n  name: (\S+)$`)

func policyNames(t testing.TB, doc []byte) []string {
	var names []string
	for _, m := range policyName.FindAllSubmatch(doc, -1) {
		names = append(names, string(m[1]))
	}
	if len(names) == 0 {
		t.Fatalf("no policy names in %q", doc)
	}
	return names
}

// realized waits until the agent's repository has (or, with present false,
// no longer has) the named policies and every endpoint has computed its
// policy at that revision. It returns the revision.
func (l *lab) realized(names []string, present bool) int {
	l.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		raw, err := l.ciliumDbg("policy", "get", "-o", "json")
		var got struct {
			Policy   string `json:"policy"`
			Revision int    `json:"revision"`
		}
		if err == nil {
			err = json.Unmarshal(raw, &got)
		}
		var rules []struct {
			Labels []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"Labels"`
		}
		if err == nil {
			err = json.Unmarshal([]byte(got.Policy), &rules)
		}
		if err == nil {
			have := map[string]bool{}
			for _, r := range rules {
				for _, lb := range r.Labels {
					if lb.Key == "io.cilium.k8s.policy.name" {
						have[lb.Value] = true
					}
				}
			}
			all := true
			for _, n := range names {
				all = all && have[n] == present
			}
			if all {
				l.must(l.ciliumDbg("policy", "wait", strconv.Itoa(got.Revision), "--max-wait-time", "60"))
				return got.Revision
			}
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("policies %v present=%v not realized after 60 s (last: %v)", names, present, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// applyPolicy applies one file of policies/cilium and waits until it is in
// force; the test's cleanup removes it again and waits for that too.
func (l *lab) applyPolicy(file string) map[string]any {
	l.t.Helper()
	doc, err := os.ReadFile(filepath.Join(policyDir, file))
	if err != nil {
		l.t.Fatal(err)
	}
	names := policyNames(l.t, doc)
	t0 := time.Now()
	l.must(l.kubectl(doc, "apply", "-f", "-"))
	l.t.Cleanup(func() {
		if _, err := l.kubectl(doc, "delete", "--ignore-not-found", "-f", "-"); err != nil {
			l.t.Errorf("delete %s: %v", file, err)
			return
		}
		l.realized(names, false)
	})
	rev := l.realized(names, true)
	return map[string]any{"file": "policies/cilium/" + file, "names": names, "revision": rev,
		"realized_after_ms": ms(time.Since(t0).Seconds())}
}

func (l *lab) deletePolicy(file string) {
	l.t.Helper()
	doc, err := os.ReadFile(filepath.Join(policyDir, file))
	if err != nil {
		l.t.Fatal(err)
	}
	l.must(l.kubectl(doc, "delete", "--ignore-not-found", "-f", "-"))
	l.realized(policyNames(l.t, doc), false)
}

// --- pods --------------------------------------------------------------------

type podStatus struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		RuntimeClassName string `json:"runtimeClassName"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		PodIP             string `json:"podIP"`
		ContainerStatuses []struct {
			ImageID string `json:"imageID"`
			Ready   bool   `json:"ready"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (l *lab) pod(ns, name string) (podStatus, error) {
	var p podStatus
	raw, err := l.kubectl(nil, "-n", ns, "get", "pod", name, "-o", "json")
	if err == nil {
		err = json.Unmarshal(raw, &p)
	}
	return p, err
}

// waitReady waits for the pod to run (ready, if it has a readiness probe)
// and for Cilium's endpoint for its IP to be ready.
func (l *lab) waitReady(ns, name string) podStatus {
	l.t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		p, err := l.pod(ns, name)
		if err == nil && p.Status.Phase == "Running" && p.Status.PodIP != "" &&
			len(p.Status.ContainerStatuses) > 0 && p.Status.ContainerStatuses[0].Ready && l.endpointReady(p.Status.PodIP) {
			return p
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("pod %s/%s not ready after 120 s: %+v %v", ns, name, p.Status, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type endpoint struct {
	ID     int `json:"id"`
	Status struct {
		State      string `json:"state"`
		Networking struct {
			Addressing []struct {
				IPv4 string `json:"ipv4"`
			} `json:"addressing"`
		} `json:"networking"`
		Identity struct {
			ID     int      `json:"id"`
			Labels []string `json:"labels"`
		} `json:"identity"`
		Policy struct {
			Realized struct {
				Revision      int    `json:"policy-revision"`
				PolicyEnabled string `json:"policy-enabled"`
			} `json:"realized"`
		} `json:"policy"`
	} `json:"status"`
}

func (l *lab) endpoint(ip string) (endpoint, bool) {
	raw, err := l.ciliumDbg("endpoint", "list", "-o", "json")
	if err != nil {
		return endpoint{}, false
	}
	var eps []endpoint
	if json.Unmarshal(raw, &eps) != nil {
		return endpoint{}, false
	}
	for _, e := range eps {
		for _, a := range e.Status.Networking.Addressing {
			if a.IPv4 == ip {
				return e, true
			}
		}
	}
	return endpoint{}, false
}

func (l *lab) endpointReady(ip string) bool {
	e, ok := l.endpoint(ip)
	return ok && e.Status.State == "ready"
}

// sandbox starts a gVisor pod with its own network stack (RuntimeClass
// gvisor-netstack) running the probe, labelled as a Warden sandbox unless
// sandbox is false, and returns its IP once Cilium's endpoint is ready. The
// test's cleanup deletes it.
func (l *lab) sandbox(name string, sandbox bool) string {
	l.t.Helper()
	return l.sandboxRunning(name, sandbox, "hold")
}

// sandboxRunning is sandbox with the probe's arguments, e.g. a stream.
func (l *lab) sandboxRunning(name string, sandbox bool, args ...string) string {
	l.t.Helper()
	labels := map[string]string{"app": name, "warden.dev/test": "cilium"}
	if sandbox {
		labels["warden.dev/sandbox"] = "true"
	}
	l.apply(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": sandboxNS, "labels": labels},
		"spec": map[string]any{
			"runtimeClassName": "gvisor-netstack", "automountServiceAccountToken": false, "enableServiceLinks": false,
			"terminationGracePeriodSeconds": 1, "restartPolicy": "Never",
			"containers": []map[string]any{{
				"name": "probe", "image": "docker.io/warden-lab/probe@" + l.digest, "imagePullPolicy": "Never",
				"args":      args,
				"resources": map[string]any{"limits": map[string]string{"cpu": "200m", "memory": "192Mi"}},
				"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65534, "allowPrivilegeEscalation": false,
					"readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}},
					"seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			}},
		}})
	l.t.Cleanup(func() { l.deletePod(sandboxNS, name) })
	p := l.waitReady(sandboxNS, name)
	if p.Spec.RuntimeClassName != "gvisor-netstack" {
		l.t.Fatalf("pod %s runs with %q", name, p.Spec.RuntimeClassName)
	}
	return p.Status.PodIP
}

func (l *lab) deletePod(ns, name string) {
	if _, err := l.kubectl(nil, "-n", ns, "delete", "pod", name, "--ignore-not-found", "--grace-period=0", "--force", "--wait=true"); err != nil {
		l.t.Errorf("delete pod %s/%s: %v", ns, name, err)
	}
}

// runtimeHandler is what the node's CRI ran the pod's sandbox with.
func (l *lab) runtimeHandler(name string) string {
	raw, err := docker(context.Background(), nil, "exec", l.node, "crictl", "--runtime-endpoint",
		"unix:///run/k3s/containerd/containerd.sock", "pods", "--name", "^"+name+"$", "--namespace", sandboxNS, "-o", "json")
	if err != nil {
		return "error: " + err.Error()
	}
	var pods struct {
		Items []struct {
			RuntimeHandler string `json:"runtimeHandler"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &pods) != nil || len(pods.Items) != 1 {
		return "unknown"
	}
	return pods.Items[0].RuntimeHandler
}

// net runs `warden-probe net` in the pod.
func (l *lab) net(pod string, cases ...string) map[string]NetResult {
	l.t.Helper()
	keys := make([]string, len(cases))
	for i, c := range cases {
		keys[i], _, _ = strings.Cut(c, ",")
	}
	out, err := l.kubectl(nil, append([]string{"-n", sandboxNS, "exec", pod, "--", "/warden-probe", "net"}, cases...)...)
	if err != nil {
		l.t.Fatalf("probe in %s: %v\n%s", pod, err, out)
	}
	got, err := ParseNetResults(out, keys...)
	if err != nil {
		l.t.Fatalf("probe in %s: %v\n%s", pod, err, out)
	}
	return got
}

// podLog returns the log lines of a pod in the sandbox namespace.
func (l *lab) podLog(name string) []Event {
	l.t.Helper()
	return ParseLog(l.must(l.kubectl(nil, "-n", sandboxNS, "logs", name)))
}

// logs returns a stand-in's log lines since t.
func (l *lab) logs(container string, since time.Time) []Event {
	l.t.Helper()
	out := l.must(docker(context.Background(), nil, "logs", "--since", strconv.FormatInt(since.Add(-time.Second).Unix(), 10), container))
	var ev []Event
	for _, e := range ParseLog(out) {
		if e.At >= epoch(since) {
			ev = append(ev, e)
		}
	}
	return ev
}

func epoch(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func nonce() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// runID is a scheduler run ID (26 characters of base32) for a lab grant.
func runID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// --- the egress proxy ----------------------------------------------------------

// proxy is Envoy with the scheduler's bootstrap and listeners, in the pod and
// namespace the policies select. Its configuration directory is an
// emptyDir: grants are written there with an atomic rename, as
// scheduler.EgressController does, and Envoy reloads them.
type proxy struct {
	l       *lab
	mu      sync.Mutex
	version uint64
	grants  map[string]scheduler.EgressGrant // by source IP
	image   string
}

var (
	sharedProxy *proxy
	proxyOnce   sync.Once
	proxyErr    error
)

func (l *lab) proxy() *proxy {
	l.t.Helper()
	proxyOnce.Do(func() { sharedProxy, proxyErr = startProxy(l) })
	if proxyErr != nil {
		l.t.Fatalf("egress proxy: %v", proxyErr)
	}
	sharedProxy.l = l
	return sharedProxy
}

func startProxy(l *lab) (*proxy, error) {
	boot, err := scheduler.RenderEgressBootstrap()
	if err != nil {
		return nil, err
	}
	lds, err := scheduler.RenderEgressLDS(1, nil)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{"app.kubernetes.io/name": proxyName}
	objs := []map[string]any{
		{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": proxyNS}},
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": proxyName + "-boot", "namespace": proxyNS},
			"data": map[string]string{scheduler.BootstrapFile: string(boot), scheduler.LDSFile: string(lds)}},
		{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": proxyName, "namespace": proxyNS},
			"spec": map[string]any{"selector": labels, "ports": []map[string]any{
				{"name": "http", "port": scheduler.HTTPProxyPort, "protocol": "TCP"},
				{"name": "sni", "port": scheduler.SNIProxyPort, "protocol": "TCP"}}}},
		{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": proxyName, "namespace": proxyNS, "labels": labels},
			"spec": map[string]any{
				"automountServiceAccountToken": false, "enableServiceLinks": false, "terminationGracePeriodSeconds": 1,
				"securityContext": map[string]any{"runAsUser": 101, "runAsGroup": 101, "fsGroup": 101, "runAsNonRoot": true,
					"seccompProfile": map[string]string{"type": "RuntimeDefault"}},
				"initContainers": []map[string]any{{
					"name": "config", "image": envoyImage, "imagePullPolicy": "Never",
					"command":         []string{"cp", "/boot/" + scheduler.BootstrapFile, "/boot/" + scheduler.LDSFile, "/etc/warden-egress/"},
					"securityContext": containerSecurity(),
					"volumeMounts": []map[string]any{{"name": "boot", "mountPath": "/boot", "readOnly": true},
						{"name": "config", "mountPath": "/etc/warden-egress"}},
				}},
				"containers": []map[string]any{{
					"name": "envoy", "image": envoyImage, "imagePullPolicy": "Never",
					"command": []string{"envoy", "-c", "/etc/warden-egress/" + scheduler.BootstrapFile, "--log-level", "warn",
						"--disable-hot-restart"},
					"ports": []map[string]any{{"containerPort": scheduler.HTTPProxyPort}, {"containerPort": scheduler.SNIProxyPort}},
					"readinessProbe": map[string]any{"tcpSocket": map[string]any{"port": scheduler.HTTPProxyPort},
						"periodSeconds": 1},
					"resources":       map[string]any{"limits": map[string]string{"cpu": "500m", "memory": "256Mi"}},
					"securityContext": containerSecurity(),
					"volumeMounts": []map[string]any{{"name": "config", "mountPath": "/etc/warden-egress"},
						{"name": "tmp", "mountPath": "/tmp"}},
				}},
				"volumes": []map[string]any{
					{"name": "boot", "configMap": map[string]any{"name": proxyName + "-boot"}},
					{"name": "config", "emptyDir": map[string]any{}},
					{"name": "tmp", "emptyDir": map[string]any{}}},
			}},
	}
	for _, o := range objs {
		b, _ := json.Marshal(o)
		if out, err := l.kubectl(b, "apply", "-f", "-"); err != nil {
			return nil, fmt.Errorf("%v %s", err, out)
		}
	}
	p := l.waitReady(proxyNS, proxyName)
	return &proxy{version: 1, grants: map[string]scheduler.EgressGrant{}, image: p.Status.ContainerStatuses[0].ImageID}, nil
}

func containerSecurity() map[string]any {
	return map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"capabilities": map[string]any{"drop": []string{"ALL"}}}
}

func removeProxy(l *lab) error {
	_, err := l.kubectl(nil, "delete", "namespace", proxyNS, "--ignore-not-found", "--wait=true", "--timeout=120s")
	return err
}

// grant sets the allowlist of one sandbox source address (none: no grant,
// its connections hit the proxy's deny chain) and publishes all grants. A
// new grant is revoked when the test ends.
func (p *proxy) grant(source string, domains ...string) {
	t := p.l.t
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(domains) == 0 {
		delete(p.grants, source)
	} else {
		g, ok := p.grants[source]
		if !ok {
			g = scheduler.EgressGrant{RunID: runID()}
			t.Cleanup(func() { p.grant(source) })
		}
		var err error
		if g.Source, err = netip.ParseAddr(source); err != nil {
			t.Fatal(err)
		}
		g.AllowDomains = domains
		p.grants[source] = g
	}
	var all []scheduler.EgressGrant
	for _, g := range p.grants {
		all = append(all, g)
	}
	lds, err := scheduler.RenderEgressLDS(p.version+1, all)
	if err != nil {
		p.l.t.Fatal(err)
	}
	dir := "/etc/warden-egress/"
	p.l.must(p.l.kubectl(lds, "-n", proxyNS, "exec", "-i", proxyName, "-c", "envoy", "--", "sh", "-c",
		"cat >"+dir+".lds.new && mv -f "+dir+".lds.new "+dir+scheduler.LDSFile))
	p.version++
}

// --- results -----------------------------------------------------------------

func loadavg() string {
	b, _ := os.ReadFile("/proc/loadavg")
	return strings.TrimSpace(string(b))
}

// record writes the test's result to $CILIUM_OUT/<test>.json (when set) and the log.
func record(t testing.TB, result map[string]any) {
	result["nproc"] = runtime.NumCPU()
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("result: %s", out)
	if dir := os.Getenv("CILIUM_OUT"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, t.Name()+".json"), append(out, '\n'), 0o644); err != nil {
			t.Error(err)
		}
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedProxy != nil {
		if err := removeProxy(sharedProxy.l); err != nil {
			fmt.Fprintln(os.Stderr, "remove the egress proxy:", err)
			code = 1
		}
	}
	os.Exit(code)
}
