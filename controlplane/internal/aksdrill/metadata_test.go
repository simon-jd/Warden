package aksdrill

import (
	"strings"
	"time"

	"testing"

	"warden/controlplane/internal/ciliumlab"
)

// TestSandboxCannotReachMetadata (Task 7) on AKS with Azure CNI powered by
// Cilium: policies/cilium/deny-metadata.yaml keeps a sandbox, and the pods
// the egress proxy runs in, off the real Azure instance metadata service.
//
// Three probe pods: md-a, a sandbox (warden.dev/sandbox=true) in warden-lab;
// md-proxy, a stand-in with the egress proxy's labels in warden-system (the
// policy's second document; AKS runs no Envoy here); md-ctl, without the
// sandbox label. And an in-cluster origin (busybox httpd). Each probe run
// reads the instance's region from IMDS (the only metadata request the
// probe can make), asks Azure DNS at 168.63.129.16 (the WireServer address,
// also in the deny list) directly, and checks other traffic: cluster DNS,
// the API server, the origin and an internet host.
//
//  1. Without the policy, all three reach IMDS and get the region (positive
//     control), and md-a and md-proxy get answers from 168.63.129.16.
//  2. With only deny-metadata.yaml, md-a and md-proxy cannot connect to
//     IMDS or get an answer from 168.63.129.16, while all their other
//     traffic flows (the policy only denies). md-ctl still reaches IMDS:
//     the policy selects sandboxes and the proxy only.
//  3. With the policy deleted, md-a and md-proxy reach IMDS again.
//
// Unlike the k3s lab, default-deny.yaml and egress-proxy.yaml are not
// applied: their DNS rules need Cilium's L7 DNS proxy, which AKS offers only
// with Advanced Container Networking Services, a paid add-on.
func TestSandboxCannotReachMetadata(t *testing.T) {
	d := live(t)
	result := map[string]any{"started": time.Now().UTC().Format(time.RFC3339), "environment": d.environment(),
		"image": d.image}
	d.namespace(proxyNS)
	originIP := d.pod(sandboxNS, "aks-origin", nil, false, "sh", "-c",
		"mkdir -p /work/www && echo warden-aks-origin >/work/www/index.html && exec httpd -f -v -p 8080 -h /work/www")
	pods := []struct{ ns, name, role string }{
		{sandboxNS, "md-a", "sandbox"}, {proxyNS, "md-proxy", "egress proxy stand-in"}, {sandboxNS, "md-ctl", "control (no sandbox label)"},
	}
	labels := map[string]map[string]string{
		"md-a":     {"warden.dev/sandbox": "true"},
		"md-proxy": {"app.kubernetes.io/name": "warden-egress"},
		"md-ctl":   nil,
	}
	ips := map[string]string{"aks-origin": originIP}
	for _, p := range pods {
		ips[p.name] = d.pod(p.ns, p.name, labels[p.name], true)
	}
	result["pods"] = map[string]any{"ips": ips, "labels": labels}
	cases := []string{
		"imds,imds," + IMDSLocationURL,
		"wire-dns,dns,A,mcr.microsoft.com.,168.63.129.16",
		"dns,dns,A,kubernetes.default.svc.cluster.local.",
		"api,tcp,kubernetes.default.svc.cluster.local.:443",
		"origin,get,http://" + originIP + ":8080/index.html",
		"internet,tcp,mcr.microsoft.com.:443",
	}
	controls := []string{"dns", "api", "origin", "internet"}
	c := &checks{t: t}
	reachesIMDS := func(r ciliumlab.NetResult) bool {
		return r.OK && r.Status == 200 && IsRegion(r.Body)
	}
	noIMDS := func(r ciliumlab.NetResult) bool {
		return !r.OK && r.Status == 0 && r.ConnectError != "" && !IsRegion(r.Body)
	}
	run := func(phase string) map[string]map[string]ciliumlab.NetResult {
		got := map[string]map[string]ciliumlab.NetResult{}
		for _, p := range pods {
			got[p.name] = d.net(p.ns, p.name, cases...)
			for _, k := range controls {
				r := got[p.name][k]
				ok := r.OK && (k != "origin" || strings.TrimSpace(r.Body) == "warden-aks-origin")
				c.add(phase+": "+p.name+" "+k+" (other traffic)", "reached", brief(r), ok)
			}
		}
		result[phase] = got
		return got
	}

	phase := "without the policy"
	r := run(phase)
	for _, p := range pods {
		c.add(phase+": "+p.name+" imds (positive control)", "the region "+Region, brief(r[p.name]["imds"]), reachesIMDS(r[p.name]["imds"]))
	}
	for _, name := range []string{"md-a", "md-proxy"} {
		c.add(phase+": "+name+" wire-dns (positive control)", "an answer from 168.63.129.16", brief(r[name]["wire-dns"]), r[name]["wire-dns"].OK)
	}

	policy := d.applyPolicy("deny-metadata.yaml")
	result["policy"] = policy
	for name, off := range policy["stored_default_deny_off"].(map[string]bool) {
		c.add("stored policy "+name, "enableDefaultDeny egress and ingress false", map[bool]string{true: "false/false", false: "missing or true"}[off], off)
	}
	phase = "with deny-metadata.yaml"
	r = run(phase)
	for _, name := range []string{"md-a", "md-proxy"} {
		c.add(phase+": "+name+" imds", "no connection", brief(r[name]["imds"]), noIMDS(r[name]["imds"]))
		w := r[name]["wire-dns"]
		c.add(phase+": "+name+" wire-dns", "no answer", brief(w), !w.OK && w.Rcode == nil)
	}
	c.add(phase+": md-ctl imds (not selected)", "the region "+Region, brief(r["md-ctl"]["imds"]), reachesIMDS(r["md-ctl"]["imds"]))

	result["policy_deleted"] = d.deletePolicy("deny-metadata.yaml")
	phase = "after deleting the policy"
	r = run(phase)
	for _, p := range pods {
		c.add(phase+": "+p.name+" imds", "the region "+Region, brief(r[p.name]["imds"]), reachesIMDS(r[p.name]["imds"]))
	}
	for _, name := range []string{"md-a", "md-proxy"} {
		c.add(phase+": "+name+" wire-dns", "an answer from 168.63.129.16", brief(r[name]["wire-dns"]), r[name]["wire-dns"].OK)
	}
	result["checks"] = c.all
	pass := 0
	for _, x := range c.all {
		if x.Pass {
			pass++
		}
	}
	result["summary"] = map[string]int{"pass": pass, "total": len(c.all)}
	result["finished"] = time.Now().UTC().Format(time.RFC3339)
	record(t, result)
}
