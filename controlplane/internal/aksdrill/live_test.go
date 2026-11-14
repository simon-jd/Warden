package aksdrill

// The live harness: the AKS drill's cluster through kubectl (the
// kubeconfig scripts/aks_drill.py wrote), and cilium-dbg in the AKS Cilium
// agent to see when a policy is in force. Every test creates its own pods
// and removes them when it ends.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/controlplane/internal/ciliumlab"
)

const (
	sandboxNS = "warden-lab"    // created by scripts/aks_drill.py up
	proxyNS   = "warden-system" // where policies/cilium expects the egress proxy
	policyDir = "../../../policies/cilium"
)

type drill struct {
	t                                 *testing.T
	kubectl, kubeconfig, image, probe string
}

func live(t *testing.T) *drill {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_AKS") != "1" {
		t.Skip("live AKS test: needs WARDEN_LIVE_AKS=1 and the AKS drill (scripts/aks_drill.py up; make test-aks)")
	}
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is not set: run through `scripts/aks_drill.py env`", k)
		}
		return v
	}
	stop, err := time.Parse(time.RFC3339, env("WARDEN_AKS_HARD_STOP"))
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(stop); left < 15*time.Minute {
		t.Fatalf("the AKS drill's hard stop is %s away: too close to start a test", left.Round(time.Second))
	}
	return &drill{t: t, kubectl: env("WARDEN_KUBECTL"), kubeconfig: env("WARDEN_AKS_KUBECONFIG"),
		image: env("WARDEN_AKS_CARRIER_IMAGE"), probe: env("WARDEN_AKS_PROBE")}
}

func (d *drill) k(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.kubectl, append([]string{"--kubeconfig", d.kubeconfig}, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (d *drill) must(out []byte, err error) []byte {
	d.t.Helper()
	if err != nil {
		d.t.Fatal(err)
	}
	return out
}

func (d *drill) apply(obj any) {
	d.t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		d.t.Fatal(err)
	}
	d.must(d.k(b, "apply", "-f", "-"))
}

// namespace makes sure ns exists; one the test created is deleted again.
func (d *drill) namespace(ns string) {
	d.t.Helper()
	if _, err := d.k(nil, "get", "namespace", ns); err == nil {
		return
	}
	d.must(d.k(nil, "create", "namespace", ns))
	d.t.Cleanup(func() {
		if _, err := d.k(nil, "delete", "namespace", ns, "--wait=true", "--timeout=120s"); err != nil {
			d.t.Errorf("delete namespace %s: %v", ns, err)
		}
	})
}

// pod starts ProbePod, waits until it is ready and returns its IP; the
// test's cleanup deletes it. With copyProbe the probe binary is copied
// into /work.
func (d *drill) pod(ns, name string, labels map[string]string, copyProbe bool, command ...string) string {
	d.t.Helper()
	obj := ProbePod(name, ns, d.image, labels, command...)
	if len(command) > 0 {
		c := obj["spec"].(map[string]any)["containers"].([]map[string]any)[0]
		c["readinessProbe"] = map[string]any{"tcpSocket": map[string]any{"port": 8080}, "periodSeconds": 1}
	}
	d.apply(obj)
	d.t.Cleanup(func() {
		if _, err := d.k(nil, "-n", ns, "delete", "pod", name, "--ignore-not-found", "--grace-period=0", "--force", "--wait=true"); err != nil {
			d.t.Errorf("delete pod %s/%s: %v", ns, name, err)
		}
	})
	d.must(d.k(nil, "-n", ns, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=180s"))
	if copyProbe {
		bin, err := os.ReadFile(d.probe)
		if err != nil {
			d.t.Fatal(err)
		}
		d.must(d.k(bin, "-n", ns, "exec", "-i", name, "--", "sh", "-c", "cat >/work/warden-probe && chmod 0555 /work/warden-probe"))
	}
	return strings.TrimSpace(string(d.must(d.k(nil, "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.podIP}"))))
}

func (d *drill) net(ns, pod string, cases ...string) map[string]ciliumlab.NetResult {
	d.t.Helper()
	keys := make([]string, len(cases))
	for i, c := range cases {
		keys[i], _, _ = strings.Cut(c, ",")
	}
	out, err := d.k(nil, append([]string{"-n", ns, "exec", pod, "--", "/work/warden-probe", "net"}, cases...)...)
	if err != nil {
		d.t.Fatalf("probe in %s/%s: %v\n%s", ns, pod, err, out)
	}
	got, err := ciliumlab.ParseNetResults(out, keys...)
	if err != nil {
		d.t.Fatalf("probe in %s/%s: %v\n%s", ns, pod, err, out)
	}
	return got
}

func (d *drill) ciliumDbg(args ...string) ([]byte, error) {
	return d.k(nil, append([]string{"-n", "kube-system", "exec", "ds/cilium", "-c", "cilium-agent", "--", "cilium-dbg"}, args...)...)
}

var policyName = regexp.MustCompile(`(?m)^metadata:\n  name: (\S+)$`)

// realized waits until the Cilium agent has (or, with present false, no
// longer has) the named policies and every endpoint computed its policy at
// that revision, as on the k3s lab. If cilium-dbg cannot be run in the
// AKS-managed agent, it waits 20 s instead and says so in the result.
func (d *drill) realized(names []string, present bool) map[string]any {
	d.t.Helper()
	t0 := time.Now()
	deadline := t0.Add(90 * time.Second)
	for attempt := 0; ; attempt++ {
		raw, err := d.ciliumDbg("policy", "get", "-o", "json")
		if err != nil && attempt == 0 {
			time.Sleep(20 * time.Second)
			return map[string]any{"realized": "not observed: cilium-dbg failed, waited 20 s", "error": err.Error()}
		}
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
				d.must(d.ciliumDbg("policy", "wait", strconv.Itoa(got.Revision), "--max-wait-time", "60"))
				return map[string]any{"realized": "agent revision " + strconv.Itoa(got.Revision),
					"after_ms": time.Since(t0).Milliseconds()}
			}
		}
		if time.Now().After(deadline) {
			d.t.Fatalf("policies %v present=%v not realized after 90 s (last: %v)", names, present, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (d *drill) policyFile(file string) ([]byte, []string) {
	d.t.Helper()
	doc, err := os.ReadFile(filepath.Join(policyDir, file))
	if err != nil {
		d.t.Fatal(err)
	}
	var names []string
	for _, m := range policyName.FindAllSubmatch(doc, -1) {
		names = append(names, string(m[1]))
	}
	if len(names) == 0 {
		d.t.Fatalf("no policy names in %s", file)
	}
	return doc, names
}

// applyPolicy applies a file of policies/cilium and waits until it is in
// force. It returns how the API server stored each policy's default-deny
// switch. The test's cleanup removes the policies.
func (d *drill) applyPolicy(file string) map[string]any {
	d.t.Helper()
	doc, names := d.policyFile(file)
	d.must(d.k(doc, "apply", "-f", "-"))
	d.t.Cleanup(func() {
		if _, err := d.k(doc, "delete", "--ignore-not-found", "-f", "-"); err != nil {
			d.t.Errorf("delete %s: %v", file, err)
		}
	})
	out := map[string]any{"file": "policies/cilium/" + file, "names": names}
	stored := map[string]bool{}
	for _, n := range names {
		raw := d.must(d.k(nil, "get", "ciliumclusterwidenetworkpolicy", n, "-o", "json"))
		off, err := DefaultDenyOff(raw)
		if err != nil {
			d.t.Fatal(err)
		}
		stored[n] = off
	}
	out["stored_default_deny_off"] = stored
	out["realization"] = d.realized(names, true)
	return out
}

func (d *drill) deletePolicy(file string) map[string]any {
	d.t.Helper()
	doc, names := d.policyFile(file)
	d.must(d.k(doc, "delete", "--ignore-not-found", "-f", "-"))
	return d.realized(names, false)
}

// environment is what the drill ran on: versions, the node, Cilium.
func (d *drill) environment() map[string]any {
	d.t.Helper()
	env := map[string]any{"nproc_test_host": runtime.NumCPU()}
	var version struct {
		Server struct {
			GitVersion string `json:"gitVersion"`
		} `json:"serverVersion"`
	}
	if err := json.Unmarshal(d.must(d.k(nil, "version", "-o", "json")), &version); err == nil {
		env["kubernetes"] = version.Server.GitVersion
	}
	var nodes struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				NodeInfo map[string]string `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(d.must(d.k(nil, "get", "nodes", "-o", "json")), &nodes); err == nil {
		var list []map[string]any
		for _, n := range nodes.Items {
			info := n.Status.NodeInfo
			list = append(list, map[string]any{"name": n.Metadata.Name, "instance_type": n.Metadata.Labels["node.kubernetes.io/instance-type"],
				"os_image": info["osImage"], "kernel": info["kernelVersion"], "container_runtime": info["containerRuntimeVersion"],
				"kubelet": info["kubeletVersion"]})
		}
		env["nodes"] = list
	}
	if img, err := d.k(nil, "-n", "kube-system", "get", "ds", "cilium", "-o", "jsonpath={.spec.template.spec.containers[0].image}"); err == nil {
		env["cilium_image"] = strings.TrimSpace(string(img))
	}
	if v, err := d.ciliumDbg("version"); err == nil {
		env["cilium_version"] = strings.TrimSpace(string(v))
	} else {
		env["cilium_version"] = "error: " + err.Error()
	}
	return env
}

type check struct {
	Name string `json:"name"`
	Want string `json:"want"`
	Got  string `json:"got"`
	Pass bool   `json:"pass"`
}

type checks struct {
	t   *testing.T
	all []check
}

func (c *checks) add(name, want, got string, pass bool) {
	c.t.Helper()
	c.all = append(c.all, check{name, want, got, pass})
	if !pass {
		c.t.Errorf("%s: want %s, got %s", name, want, got)
	}
}

func brief(r ciliumlab.NetResult) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// record writes the result to $AKS_OUT/<test>.json (when set) and the log.
func record(t *testing.T, result map[string]any) {
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("result: %s", out)
	if dir := os.Getenv("AKS_OUT"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, t.Name()+".json"), append(out, '\n'), 0o644); err != nil {
			t.Error(err)
		}
	}
}
