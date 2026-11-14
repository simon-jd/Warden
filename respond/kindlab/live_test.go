package kindlab

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/respond"
)

const (
	sandboxNS   = "warden-sandbox"
	responderNS = "warden-respond"
	responderSA = "warden-responder"
	podImage    = "python:3.14.4-alpine" // loaded by scripts/kind_lab.sh
	isolateRuns = 10
)

// probeScript runs in every lab pod: it answers "ok" on 8080 and echoes lines
// on 8081 (logging "echo end <client ip>" when a connection closes), exits on
// SIGTERM only if EXIT_ON_TERM is set (as PID 1 it otherwise ignores it), probes each TARGETS entry with a fresh TCP connection every 50 ms,
// and keeps one long-lived connection to PERSIST, writing a line every 100 ms.
// Each log line starts with the attempt's start time (pod clock = host clock).
const probeScript = `
import os, signal, socket, socketserver, threading, time
if os.environ.get("EXIT_ON_TERM"):
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
class H(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"ok\n")
class E(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            for line in self.rfile:
                self.wfile.write(line)
        except OSError:
            pass
        print("%.3f echo end %s" % (time.time(), self.client_address[0]), flush=True)
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
for port, h in ((8080, H), (8081, E)):
    threading.Thread(target=S(("0.0.0.0", port), h).serve_forever, daemon=True).start()
targets = [t.split("=", 1) for t in os.environ.get("TARGETS", "").split(",") if t]
def probe():
    while True:
        for name, addr in targets:
            host, port = addr.rsplit(":", 1)
            t = time.time()
            try:
                with socket.create_connection((host, int(port)), timeout=0.3) as s:
                    s.settimeout(0.3)
                    ok = s.recv(3) == b"ok\n"
            except OSError:
                ok = False
            print("%.3f probe %s %s" % (t, name, "ok" if ok else "fail"), flush=True)
        time.sleep(0.05)
def keep(addr):
    host, port = addr.rsplit(":", 1)
    s = None
    while True:
        t = time.time()
        state = "old" if s is not None else "new"
        try:
            if s is None:
                s = socket.create_connection((host, int(port)), timeout=0.3)
                s.settimeout(0.3)
            s.sendall(b"x\n")
            ok = s.recv(2) == b"x\n"
        except OSError:
            ok = False
        if not ok and s is not None:
            s.close()
            s = None
        print("%.3f persist %s %s" % (t, state, "ok" if ok else "fail"), flush=True)
        time.sleep(0.1)
if os.environ.get("PERSIST"):
    threading.Thread(target=keep, args=(os.environ["PERSIST"],), daemon=True).start()
probe() if targets else threading.Event().wait()
`

type lab struct {
	t        *testing.T
	ctx      context.Context
	admin    API
	cluster  Cluster
	token    string
	tokenTTL time.Duration
	node     string
}

func liveLab(t *testing.T) *lab {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_KIND") != "1" {
		t.Skip("live kind test: run `make test-kind`")
	}
	raw, err := os.ReadFile(os.Getenv("WARDEN_KIND_KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseKubeconfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := c.HTTPClient(true)
	if err != nil {
		t.Fatal(err)
	}
	return &lab{t: t, ctx: context.Background(), admin: API{Server: c.Server, HTTP: hc}, cluster: c}
}

func (l *lab) must(err error, what string) {
	l.t.Helper()
	if err != nil {
		l.t.Fatalf("%s: %v", what, err)
	}
}

func (l *lab) create(path string, obj any) {
	l.t.Helper()
	if err := l.admin.Do(l.ctx, http.MethodPost, path, "", obj, nil); err != nil && !IsStatus(err, http.StatusConflict) {
		l.t.Fatalf("POST %s: %v", path, err)
	}
}

func meta(name, ns string) map[string]any {
	m := map[string]any{"name": name}
	if ns != "" {
		m["namespace"] = ns
	}
	return m
}

// setup creates the namespaces, the quarantine NetworkPolicy and a responder
// ServiceAccount that may only get/patch pods in the sandbox namespace and
// get/patch nodes, then requests a 10-minute token for it.
func (l *lab) setup() {
	for _, ns := range []string{sandboxNS, responderNS} {
		l.create("/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": meta(ns, "")})
	}
	policy, err := os.ReadFile(QuarantinePolicyPath)
	l.must(err, "read policy")
	l.create("/apis/networking.k8s.io/v1/namespaces/"+sandboxNS+"/networkpolicies", policy)
	l.create("/api/v1/namespaces/"+responderNS+"/serviceaccounts",
		map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta(responderSA, responderNS)})
	subject := []map[string]string{{"kind": "ServiceAccount", "name": responderSA, "namespace": responderNS}}
	l.create("/apis/rbac.authorization.k8s.io/v1/namespaces/"+sandboxNS+"/roles", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta("warden-isolate-pod", sandboxNS),
		"rules": []map[string]any{{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get", "patch"}}}})
	l.create("/apis/rbac.authorization.k8s.io/v1/namespaces/"+sandboxNS+"/rolebindings", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta("warden-isolate-pod", sandboxNS),
		"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "warden-isolate-pod"},
		"subjects": subject})
	l.create("/apis/rbac.authorization.k8s.io/v1/clusterroles", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": meta("warden-cordon-node", ""),
		"rules": []map[string]any{{"apiGroups": []string{""}, "resources": []string{"nodes"}, "verbs": []string{"get", "patch"}}}})
	l.create("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": meta("warden-cordon-node", ""),
		"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "warden-cordon-node"},
		"subjects": subject})
	var tr struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	issued := time.Now()
	l.must(l.admin.Do(l.ctx, http.MethodPost, "/api/v1/namespaces/"+responderNS+"/serviceaccounts/"+responderSA+"/token", "",
		map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": map[string]any{"expirationSeconds": 600}},
		&tr), "token request")
	l.token, l.tokenTTL = tr.Status.Token, tr.Status.ExpirationTimestamp.Sub(issued)
	var nodes struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/nodes", "", nil, &nodes), "list nodes")
	if len(nodes.Items) != 1 {
		l.t.Fatalf("want one node, got %d", len(nodes.Items))
	}
	l.node = nodes.Items[0].Metadata.Name
}

func (l *lab) responder() API {
	hc, err := l.cluster.HTTPClient(false)
	l.must(err, "responder client")
	return API{Server: l.cluster.Server, HTTP: hc, Token: l.token}
}

// allowed asks the API server whether the responder token may do verb on resource in ns.
func (l *lab) allowed(verb, resource, ns string) bool {
	var r struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	l.must(l.responder().Do(l.ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": map[string]string{"verb": verb, "resource": resource, "namespace": ns}}}, &r), "access review")
	return r.Status.Allowed
}

// podIP starts a pod and returns its IP once it runs. The lab probes pod IPs
// directly, so the measurements do not go through kube-proxy. In phase 5
// kube-proxy could not start in this kind node (inotify EMFILE on the shared
// host); TestKindServiceAndDNS checks Services and cluster DNS now.
func (l *lab) podIP(name string, env map[string]string) string {
	l.pod(name, env)
	l.waitRunning(name)
	return l.getPod(name).Status.PodIP
}

func (l *lab) pod(name string, env map[string]string) {
	var envs []map[string]string
	for k, v := range env {
		envs = append(envs, map[string]string{"name": k, "value": v})
	}
	l.create("/api/v1/namespaces/"+sandboxNS+"/pods", map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": sandboxNS, "labels": map[string]string{"app": name}},
		"spec": map[string]any{
			"automountServiceAccountToken": false, "terminationGracePeriodSeconds": 1,
			"containers": []map[string]any{{
				"name": "probe", "image": podImage, "imagePullPolicy": "Never",
				"command": []string{"python", "-u", "-c", probeScript}, "env": envs,
				"resources": map[string]any{"limits": map[string]string{"cpu": "200m", "memory": "64Mi"}},
				"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65534, "allowPrivilegeEscalation": false,
					"readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
			}},
		}})
}

type podState struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		PodIP      string `json:"podIP"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"conditions"`
	} `json:"status"`
}

func (l *lab) getPod(name string) podState {
	var p podState
	l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/namespaces/"+sandboxNS+"/pods/"+name, "", nil, &p), "get pod "+name)
	return p
}

func (l *lab) waitRunning(names ...string) {
	deadline := time.Now().Add(120 * time.Second)
	for _, n := range names {
		for l.getPod(n).Status.Phase != "Running" {
			if time.Now().After(deadline) {
				l.t.Fatalf("pod %s not running: %+v", n, l.getPod(n).Status)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

type sample struct {
	at     float64 // epoch seconds, attempt start
	kind   string  // probe | persist
	target string  // probe target, or old/new for persist
	ok     bool
}

// samples returns the pod's log lines from the last `since` seconds.
func (l *lab) samples(pod string, since int) []sample {
	var raw []byte
	l.must(l.admin.Do(l.ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?sinceSeconds=%d", sandboxNS, pod, since),
		"", nil, &raw), "logs "+pod)
	var out []sample
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 {
			continue
		}
		at, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		out = append(out, sample{at: at, kind: f[1], target: f[2], ok: f[3] == "ok"})
	}
	return out
}

func epoch(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// first returns the start time of the first sample at or after from matching
// kind/target with the given result, or 0.
func first(ss []sample, from float64, kind, target string, ok bool) float64 {
	for _, s := range ss {
		if s.at >= from && s.kind == kind && (target == "" || s.target == target) && s.ok == ok {
			return s.at
		}
	}
	return 0
}

func count(ss []sample, from, to float64, kind, target string, ok bool) int {
	n := 0
	for _, s := range ss {
		if s.at >= from && s.at < to && s.kind == kind && (target == "" || s.target == target) && s.ok == ok {
			n++
		}
	}
	return n
}

// healthy waits until a->b, peer->a, peer->c and a's long-lived connection have
// all been ok for one second, and returns when that was first true.
func (l *lab) healthy(timeout time.Duration) time.Duration {
	start := time.Now()
	for time.Since(start) < timeout {
		now := epoch(time.Now())
		a, b := l.samples("a", 5), l.samples("peer", 5)
		if count(a, now-1, now, "probe", "b", false) == 0 && count(a, now-1, now, "probe", "b", true) > 3 &&
			count(b, now-1, now, "probe", "a", false) == 0 && count(b, now-1, now, "probe", "a", true) > 3 &&
			count(b, now-1, now, "probe", "c", false) == 0 && count(b, now-1, now, "probe", "c", true) > 3 &&
			count(a, now-1, now, "persist", "old", true) > 3 {
			return time.Since(start)
		}
		time.Sleep(200 * time.Millisecond)
	}
	l.t.Fatalf("lab pods not healthy within %v: a=%v peer=%v", timeout, tail(l.samples("a", 5)), tail(l.samples("peer", 5)))
	return 0
}

func tail(ss []sample) []sample {
	if len(ss) > 6 {
		return ss[len(ss)-6:]
	}
	return ss
}

func nearestRank(sorted []float64, p float64) float64 {
	i := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	return sorted[max(0, min(i, len(sorted)-1))]
}

func stats(v []float64) map[string]float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s) == 0 {
		return nil
	}
	return map[string]float64{"p50": nearestRank(s, 50), "p95": nearestRank(s, 95), "max": s[len(s)-1], "min": s[0]}
}

func newExecutor(t *testing.T, pb respond.Playbook, k respond.Kubernetes) *respond.Executor {
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e, err := respond.New(respond.Config{Playbook: pb, AllowedTenantIDs: []string{"tenant-a"},
		JournalPath: filepath.Join(dir, "attempts.journal"), Actions: respond.Router{pb.Steps[0].Name: k}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func ms(d float64) float64 { return math.Round(d*1e4) / 10 }

func loadavg() string {
	la, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(la))
}

// TestKindIsolatePodAndCordonNode runs respond's IsolatePod and CordonNode
// through the executor and the real Kubernetes adapter against the kind lab,
// authenticated only by the least-privilege responder token, and measures
// from the alert's arrival at the executor to the first failed connection in
// each direction (IsolatePod) and to the node refusing new pods (CordonNode).
func TestKindIsolatePodAndCordonNode(t *testing.T) {
	l := liveLab(t)
	loadStart := loadavg()
	l.setup()
	result := map[string]any{"token_ttl_s": l.tokenTTL.Seconds(), "node": l.node, "isolate_runs": isolateRuns}
	var version map[string]any
	l.must(l.admin.Do(l.ctx, http.MethodGet, "/version", "", nil, &version), "version")
	result["server_version"] = version["gitVersion"]
	if l.tokenTTL <= 0 || l.tokenTTL > time.Hour {
		t.Fatalf("responder token TTL %v, want (0, 1h]", l.tokenTTL)
	}

	rbac := map[string]bool{
		"patch pods warden-sandbox":  l.allowed("patch", "pods", sandboxNS),
		"patch nodes":                l.allowed("patch", "nodes", ""),
		"delete pods warden-sandbox": l.allowed("delete", "pods", sandboxNS),
		"patch pods kube-system":     l.allowed("patch", "pods", "kube-system"),
		"get secrets warden-sandbox": l.allowed("get", "secrets", sandboxNS),
		"create pods/exec":           l.allowed("create", "pods/exec", sandboxNS),
		"delete nodes":               l.allowed("delete", "nodes", ""),
	}
	result["responder_rbac"] = rbac
	for k, v := range rbac {
		if want := strings.HasPrefix(k, "patch pods warden") || k == "patch nodes"; v != want {
			t.Errorf("responder may %s = %v, want %v", k, v, want)
		}
	}

	// a (the target) probes b (egress) and keeps a connection to b open;
	// peer probes a (ingress) and c (control path, must stay up).
	ipB, ipC := l.podIP("b", nil), l.podIP("c", nil)
	ipA := l.podIP("a", map[string]string{"TARGETS": "b=" + ipB + ":8080", "PERSIST": ipB + ":8081"})
	l.podIP("peer", map[string]string{"TARGETS": "a=" + ipA + ":8080,c=" + ipC + ":8080"})
	l.healthy(90 * time.Second)

	k := respond.Kubernetes{Server: l.cluster.Server, Token: l.token}
	hc, err := l.cluster.HTTPClient(false)
	l.must(err, "adapter client")
	k.HTTP = hc
	iso := newExecutor(t, respond.Playbook{ID: "isolate-sandbox-pod", Trigger: "warden-sandbox-reverse-shell",
		Steps: []respond.Action{{Name: respond.IsolatePod, Resource: respond.Resource{Type: "pod"}}}}, k)

	var handleMS, egressMS, ingressMS, bothMS, releaseMS []float64
	var controlFails, persistOldOK, noOps int
	var runs []map[string]any
	for i := range isolateRuns {
		alert := respond.Alert{ID: fmt.Sprintf("kind-isolate-%02d", i), RuleID: "warden-sandbox-reverse-shell", TenantID: "tenant-a",
			Resource: respond.Resource{Type: "pod", ID: sandboxNS + "/a"}}
		if i == 0 {
			d0 := epoch(time.Now())
			if r, err := iso.Handle(alert, true); err != nil || r.Status != respond.Preview {
				t.Fatalf("dry run = %+v, %v", r, err)
			}
			time.Sleep(1500 * time.Millisecond)
			if _, set := l.getPod("a").Metadata.Labels[respond.QuarantineLabel]; set {
				t.Fatal("dry run labelled the pod")
			}
			if n := count(l.samples("a", 5), d0, epoch(time.Now()), "probe", "b", false); n != 0 {
				t.Fatalf("dry run: %d failed probes", n)
			}
		}
		t0 := time.Now()
		r, err := iso.Handle(alert, false)
		handled := time.Since(t0)
		if err != nil || r.Status != respond.Completed {
			t.Fatalf("run %d: %+v, %v", i, r, err)
		}
		e0 := epoch(t0)
		var egress, ingress float64
		for time.Since(t0) < 30*time.Second && (egress == 0 || ingress == 0) {
			time.Sleep(100 * time.Millisecond)
			egress = first(l.samples("a", 40), e0, "probe", "b", false)
			ingress = first(l.samples("peer", 40), e0, "probe", "a", false)
		}
		if egress == 0 || ingress == 0 {
			t.Fatalf("run %d: not isolated after 30 s (egress fail at %v, ingress fail at %v)", i, egress, ingress)
		}
		// Watch three more seconds: the control path peer->c must stay up,
		// and a's already-open connection to b shows whether the policy cuts
		// established flows or only new ones.
		// The first run watches ten seconds, to show the open connection is
		// not just a short grace period.
		both := math.Max(egress, ingress)
		watch := 3.0
		if i == 0 {
			watch = 10
		}
		time.Sleep(time.Duration(watch * float64(time.Second)))
		a, b := l.samples("a", 40), l.samples("peer", 40)
		cf := count(b, e0, both+3, "probe", "c", false)
		po := count(a, both+1, both+3, "persist", "old", true)
		if i == 0 {
			result["persist_old_ok_samples_1to10s_run0"] = count(a, both+1, both+10, "persist", "old", true)
			result["persist_fail_samples_1to10s_run0"] = count(a, both+1, both+10, "persist", "", false)
		}
		okAfter := count(a, both+0.5, both+3, "probe", "b", true) + count(b, both+0.5, both+3, "probe", "a", true)
		if okAfter != 0 {
			t.Errorf("run %d: %d new connections succeeded after isolation", i, okAfter)
		}
		controlFails += cf
		persistOldOK += po
		if _, set := l.getPod("a").Metadata.Labels[respond.QuarantineLabel]; !set {
			t.Fatalf("run %d: pod not labelled", i)
		}
		if r2, err := iso.Handle(alert, false); err != nil || !r2.NoOp {
			t.Fatalf("run %d: replay = %+v, %v", i, r2, err)
		}
		noOps++
		handleMS = append(handleMS, ms(handled.Seconds()))
		egressMS = append(egressMS, ms(egress-e0))
		ingressMS = append(ingressMS, ms(ingress-e0))
		bothMS = append(bothMS, ms(both-e0))
		// Release (an operator action, not part of the measurement) and wait for recovery.
		r0 := time.Now()
		l.must(l.admin.Do(l.ctx, http.MethodPatch, "/api/v1/namespaces/"+sandboxNS+"/pods/a", "application/merge-patch+json",
			map[string]any{"metadata": map[string]any{"labels": map[string]any{respond.QuarantineLabel: nil}}}, nil), "release")
		l.healthy(60 * time.Second)
		releaseMS = append(releaseMS, ms(time.Since(r0).Seconds()))
		runs = append(runs, map[string]any{"alert": alert.ID, "handle_ms": handleMS[i], "egress_blocked_ms": egressMS[i],
			"ingress_blocked_ms": ingressMS[i], "control_fail_probes": cf, "persist_old_ok_after_isolation": po})
	}
	result["isolate"] = map[string]any{
		"runs": runs, "handle_ms": stats(handleMS), "alert_to_egress_blocked_ms": stats(egressMS),
		"alert_to_ingress_blocked_ms": stats(ingressMS), "alert_to_both_blocked_ms": stats(bothMS),
		"release_to_healthy_ms": stats(releaseMS), "control_fail_probes": controlFails, "replays_noop": noOps,
		"persist_old_ok_samples_1to3s_after_isolation": persistOldOK,
		"probe": "fresh TCP connect every 50 ms (0.3 s timeout) to pod IPs (not through kube-proxy, see podIP); time = attempt start of the first failed probe",
	}
	if controlFails != 0 {
		t.Errorf("control path peer->c failed %d probes", controlFails)
	}

	// CordonNode.
	cord := newExecutor(t, respond.Playbook{ID: "cordon-node", Trigger: "warden-node-escape",
		Steps: []respond.Action{{Name: respond.CordonNode, Resource: respond.Resource{Type: "node"}}}}, k)
	alert := respond.Alert{ID: "kind-cordon-00", RuleID: "warden-node-escape", TenantID: "tenant-a",
		Resource: respond.Resource{Type: "node", ID: l.node}}
	unschedulable := func() bool {
		var n struct {
			Spec struct {
				Unschedulable bool `json:"unschedulable"`
			} `json:"spec"`
		}
		l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/nodes/"+l.node, "", nil, &n), "get node")
		return n.Spec.Unschedulable
	}
	if r, err := cord.Handle(alert, true); err != nil || r.Status != respond.Preview || unschedulable() {
		t.Fatalf("cordon dry run = %+v, %v, unschedulable=%v", r, err, unschedulable())
	}
	t0 := time.Now()
	r, err := cord.Handle(alert, false)
	handled := time.Since(t0)
	if err != nil || r.Status != respond.Completed || !unschedulable() {
		t.Fatalf("cordon = %+v, %v, unschedulable=%v", r, err, unschedulable())
	}
	l.pod("d", nil)
	var refused time.Duration
	for time.Since(t0) < 30*time.Second && refused == 0 {
		for _, c := range l.getPod("d").Status.Conditions {
			if c.Type == "PodScheduled" && c.Status == "False" && c.Reason == "Unschedulable" {
				refused = time.Since(t0)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if refused == 0 || l.getPod("d").Spec.NodeName != "" {
		t.Fatalf("new pod was not refused by the cordoned node: %+v", l.getPod("d"))
	}
	if r2, err := cord.Handle(alert, false); err != nil || !r2.NoOp {
		t.Fatalf("cordon replay = %+v, %v", r2, err)
	}
	l.must(l.admin.Do(l.ctx, http.MethodPatch, "/api/v1/nodes/"+l.node, "application/merge-patch+json",
		map[string]any{"spec": map[string]any{"unschedulable": false}}, nil), "uncordon")
	l.waitRunning("d")
	result["cordon"] = map[string]any{"handle_ms": ms(handled.Seconds()), "alert_to_new_pod_unschedulable_ms": ms(refused.Seconds()),
		"replay_noop": true, "pod_scheduled_after_uncordon": true}

	result["load"] = map[string]any{"nproc": runtime.NumCPU(), "loadavg_start": loadStart, "loadavg_end": loadavg()}
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("%s", out)
	if p := os.Getenv("KIND_OUT"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
