package ciliumlab

import (
	"strings"
	"testing"
	"time"
)

const imdsBody = "warden-lab-imds" // what the lab's metadata stand-in answers

// TestSandboxCannotReachMetadata (Task 7): policies/cilium/deny-metadata.yaml
// keeps a gVisor sandbox off the cloud metadata endpoint, by its address and
// by its name, and keeps the egress proxy from reaching it on the sandbox's
// behalf, whatever the proxy's allowlist says. The lab's stand-in for the
// endpoint is at 169.254.169.254 (routed inside the node only), and the
// lab's resolver maps metadata.google.internal to it.
//
// Only deny-metadata.yaml is applied, so nothing else can be what blocks: a
// sandbox reaches the endpoint (three ways) before the policy, cannot while
// it is in force, and can again once it is deleted. Its other egress (an
// origin, DNS, an allowed domain through the proxy) works throughout: the
// policy only denies. Last, with default-deny.yaml and egress-proxy.yaml
// added, the sandbox is still in default deny (deny-metadata.yaml turns
// default deny off for itself only) and the endpoint stays out of reach.
func TestSandboxCannotReachMetadata(t *testing.T) {
	l := liveLab(t)
	result := map[string]any{"loadavg_start": loadavg(), "started": time.Now().UTC().Format(time.RFC3339)}
	p := l.proxy()
	result["proxy_image"] = p.image
	ip := l.sandbox("md-a", true)
	// The proxy's allowlist names the metadata host: only the policy stands
	// between the sandbox's request and the endpoint.
	p.grant(ip, "metadata.google.internal", "allowed.warden.test")
	proxyPod, err := l.pod(proxyNS, proxyName)
	if err != nil {
		t.Fatal(err)
	}
	result["pods"] = map[string]any{
		"md-a":    map[string]string{"ip": ip, "sandbox": "true", "grant": "metadata.google.internal allowed.warden.test", "runtime_handler": l.runtimeHandler("md-a")},
		proxyName: map[string]string{"ip": proxyPod.Status.PodIP},
	}
	w := l.world
	cases := func(n string) []string {
		return []string{
			"imds-ip,get,http://169.254.169.254/i-" + n,
			"imds-name,get,http://metadata.google.internal/h-" + n,
			"imds-proxy,proxy," + proxyAddr + ",http://metadata.google.internal/p-" + n,
			"origin,get,http://" + w + ".20/o-" + n,
			"dns,dns,A,allowed.warden.test",
			"proxy-allowed,proxy," + proxyAddr + ",http://allowed.warden.test/a-" + n,
		}
	}
	imdsCases := []string{"imds-ip", "imds-name", "imds-proxy"}
	controls := []string{"origin", "dns", "proxy-allowed"}
	c := &checks{t: t}

	deadline := time.Now().Add(60 * time.Second)
	for !l.net("md-a", "warm,proxy,"+proxyAddr+",http://allowed.warden.test/warm")["warm"].OK {
		if time.Now().After(deadline) {
			t.Fatal("md-a's grant did not reach the proxy within 60 s")
		}
		time.Sleep(time.Second)
	}

	// probe runs the cases and returns them with the requests that reached
	// the metadata stand-in and the origin.
	probe := func(phase string) map[string]NetResult {
		n := nonce()
		t0 := time.Now()
		r := l.net("md-a", cases(n)...)
		time.Sleep(time.Second) // the stand-ins' logs
		imdsGot, originGot := containing(paths(l.logs(imds, t0)), n), containing(paths(l.logs(originAllowed, t0)), n)
		result[phase] = map[string]any{"nonce": n, "md-a": r, "imds_paths": imdsGot, "origin_allowed_paths": originGot}
		c.add(phase+": origin log", "the /o- and /a- requests", strings.Join(originGot, " "),
			len(containing(originGot, "/o-"+n)) == 1 && len(containing(originGot, "/a-"+n)) == 1)
		for _, k := range controls {
			c.add(phase+": md-a "+k+" (control)", "reached", brief(r[k]), r[k].OK)
		}
		if phase == "with deny-metadata.yaml" {
			c.add(phase+": metadata log", "no request", strings.Join(imdsGot, " "), len(imdsGot) == 0)
			return r
		}
		for _, k := range imdsCases {
			c.add(phase+": md-a "+k+" (positive control)", "the metadata answer", brief(r[k]), r[k].OK && strings.TrimSpace(r[k].Body) == imdsBody)
		}
		c.add(phase+": metadata log", "the /i-, /h- and /p- requests", strings.Join(imdsGot, " "),
			len(containing(imdsGot, "/i-"+n)) == 1 && len(containing(imdsGot, "/h-"+n)) == 1 && len(containing(imdsGot, "/p-"+n)) == 1)
		return r
	}

	probe("without the policy")

	result["policy"] = l.applyPolicy("deny-metadata.yaml")
	for name, addr := range map[string]string{"md-a": ip, proxyName: proxyPod.Status.PodIP} {
		e, _ := l.endpoint(addr)
		result["endpoint_"+name] = map[string]any{"id": e.ID, "identity": e.Status.Identity.ID,
			"policy_enabled": e.Status.Policy.Realized.PolicyEnabled, "policy_revision": e.Status.Policy.Realized.Revision}
	}
	phase := "with deny-metadata.yaml"
	r := probe(phase)
	for _, k := range []string{"imds-ip", "imds-name"} {
		c.add(phase+": md-a "+k, "no connection", brief(r[k]), !r[k].OK && r[k].Status == 0 && r[k].ConnectError != "")
	}
	c.add(phase+": md-a imds-name resolves", "169.254.169.254 (the address is what is denied)", r["imds-name"].Resolved+" "+r["imds-name"].ResolveError,
		r["imds-name"].Resolved == "169.254.169.254")
	c.add(phase+": md-a imds-proxy", "the proxy cannot connect (no metadata answer)", brief(r["imds-proxy"]),
		!r["imds-proxy"].OK && r["imds-proxy"].Status != 200 && !strings.Contains(r["imds-proxy"].Body, imdsBody))

	l.deletePolicy("deny-metadata.yaml")
	probe("after deleting the policy")

	// The deployed set: default deny is still on.
	phase = "with default-deny.yaml, egress-proxy.yaml and deny-metadata.yaml"
	result["policies_all"] = []any{l.applyPolicy("default-deny.yaml"), l.applyPolicy("egress-proxy.yaml"), l.applyPolicy("deny-metadata.yaml")}
	n := nonce()
	t0 := time.Now()
	r = l.net("md-a", cases(n)...)
	time.Sleep(time.Second)
	imdsGot, originGot := containing(paths(l.logs(imds, t0)), n), containing(paths(l.logs(originAllowed, t0)), n)
	result[phase] = map[string]any{"nonce": n, "md-a": r, "imds_paths": imdsGot, "origin_allowed_paths": originGot}
	for _, k := range []string{"imds-ip", "origin"} {
		c.add(phase+": md-a "+k, "no connection", brief(r[k]), !r[k].OK && r[k].Status == 0 && r[k].ConnectError != "")
	}
	c.add(phase+": md-a imds-name", "name not resolved (only the proxy's name is)", brief(r["imds-name"]), !r["imds-name"].OK && r["imds-name"].ResolveError != "")
	c.add(phase+": md-a dns", "refused", brief(r["dns"]), !r["dns"].OK)
	c.add(phase+": md-a imds-proxy", "the proxy cannot connect (no metadata answer)", brief(r["imds-proxy"]),
		!r["imds-proxy"].OK && r["imds-proxy"].Status != 200 && !strings.Contains(r["imds-proxy"].Body, imdsBody))
	c.add(phase+": md-a proxy-allowed (control)", "reached through the proxy", brief(r["proxy-allowed"]), r["proxy-allowed"].OK)
	c.add(phase+": metadata log", "no request", strings.Join(imdsGot, " "), len(imdsGot) == 0)
	c.add(phase+": origin log", "only the proxied /a- request", strings.Join(originGot, " "),
		len(originGot) == 1 && strings.HasSuffix(originGot[0], "/a-"+n))

	result["checks"] = c.all
	result["loadavg_end"] = loadavg()
	record(t, result)
}
