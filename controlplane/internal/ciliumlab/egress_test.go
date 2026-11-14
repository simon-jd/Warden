package ciliumlab

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// check is one expectation on a probe result or a stand-in's log.
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

func brief(r NetResult) string {
	var b []string
	if r.OK {
		b = append(b, "ok")
	}
	for _, kv := range [][2]string{{"status", itoa(r.Status)}, {"proxy_status", itoa(r.ProxyStatus)},
		{"body", strings.TrimSpace(r.Body)}, {"resolve_error", r.ResolveError}, {"connect_error", r.ConnectError},
		{"error", r.Error}, {"answers", strings.Join(r.Answers, ",")}} {
		if kv[1] != "" && kv[1] != "0" {
			b = append(b, kv[0]+"="+kv[1])
		}
	}
	if r.Rcode != nil {
		b = append(b, "rcode="+strconv.Itoa(*r.Rcode))
	}
	return strings.Join(b, " ")
}

func itoa(i int) string {
	if i == 0 {
		return ""
	}
	return strconv.Itoa(i)
}

// paths returns the paths a stand-in logged for HTTP requests.
func paths(ev []Event) []string {
	var out []string
	for _, e := range ev {
		if e.Kind == "http" && len(e.Fields) >= 3 {
			out = append(out, e.Fields[1]+e.Fields[2])
		}
	}
	return out
}

// dnsNames returns the names a resolver stand-in was asked for.
func dnsNames(ev []Event) []string {
	var out []string
	for _, e := range ev {
		if e.Kind == "dns" && len(e.Fields) >= 3 {
			out = append(out, e.Fields[1]+" "+e.Fields[2])
		}
	}
	return out
}

func containing(list []string, sub string) []string {
	var out []string
	for _, s := range list {
		if strings.Contains(s, sub) {
			out = append(out, s)
		}
	}
	return out
}

// exfilLabel is a DNS label carrying data, as a TXT exfiltration would.
func exfilLabel(tag string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "-" + tag // 48 + 1 + 12 characters, under 63
}

// TestSandboxReachesOnlyTheEgressProxy (Task 10): with
// policies/cilium/default-deny.yaml and egress-proxy.yaml applied, a gVisor
// sandbox reaches the world only through the egress proxy, and the proxy's
// allowlist (controlplane/internal/scheduler's Envoy listeners, granted by
// the sandbox's source address) decides what leaves. The same probes run
// first without the policies: every path that is blocked afterwards is open
// before, so a blocked result is the policy's doing. A pod without the
// sandbox label runs the direct probes under the policies as a control.
func TestSandboxReachesOnlyTheEgressProxy(t *testing.T) {
	l := liveLab(t)
	result := map[string]any{"loadavg_start": loadavg(), "started": time.Now().UTC().Format(time.RFC3339)}
	p := l.proxy()
	result["proxy_image"] = p.image
	ipA := l.sandbox("egr-a", true)
	ipB := l.sandbox("egr-b", true)
	ipCtl := l.sandbox("egr-ctl", false)
	p.grant(ipA, "allowed.warden.test")
	result["pods"] = map[string]any{
		"egr-a":   map[string]string{"ip": ipA, "sandbox": "true", "grant": "allowed.warden.test", "runtime_handler": l.runtimeHandler("egr-a")},
		"egr-b":   map[string]string{"ip": ipB, "sandbox": "true", "grant": "none", "runtime_handler": l.runtimeHandler("egr-b")},
		"egr-ctl": map[string]string{"ip": ipCtl, "sandbox": "false (control)", "runtime_handler": l.runtimeHandler("egr-ctl")},
	}
	w := l.world
	cases := func(n string) []string {
		return []string{
			"proxy-connect-allowed,tunnel," + proxyAddr + ",allowed.warden.test:443",
			"proxy-http-allowed,proxy," + proxyAddr + ",http://allowed.warden.test/p-" + n,
			"proxy-connect-blocked,tunnel," + proxyAddr + ",blocked.warden.test:443",
			"proxy-http-blocked,proxy," + proxyAddr + ",http://blocked.warden.test/b-" + n,
			"dns-proxy-name,dns,A,warden-egress.warden-system.svc.cluster.local",
			"direct-allowed,get,http://" + w + ".20/d-" + n,
			"direct-blocked,get,http://" + w + ".21/d-" + n,
			"direct-name,get,http://blocked.warden.test/n-" + n,
			"direct-stream,tcp," + w + ".22:443",
			"dns-exfil,dns,TXT," + exfilLabel(n) + ".exfil.warden.test",
			"dns-exfil-direct,dns,TXT," + exfilLabel(n) + ".exfil.warden.test," + w + ".40",
			"apiserver,tcp,10.43.0.1:443",
			"node,tcp," + l.apiHost + ":6443",
			"metadata,get,http://169.254.169.254/m-" + n,
		}
	}
	noGrant := []string{"nogrant-tcp,tcp," + proxyAddr, "nogrant-connect,tunnel," + proxyAddr + ",allowed.warden.test:443"}
	c := &checks{t: t}

	// The proxy has to have the grant before anything is measured.
	deadline := time.Now().Add(60 * time.Second)
	for !l.net("egr-a", "warm,tunnel,"+proxyAddr+",allowed.warden.test:443")["warm"].OK {
		if time.Now().After(deadline) {
			t.Fatal("egr-a's grant did not reach the proxy within 60 s")
		}
		time.Sleep(time.Second)
	}

	// Without the policies.
	open := nonce()
	t0 := time.Now()
	ra, rb := l.net("egr-a", cases(open)...), l.net("egr-b", noGrant...)
	time.Sleep(time.Second) // the stand-ins' logs
	blockedLog, allowedLog, sinkLog := l.logs(originBlocked, t0), l.logs(originAllowed, t0), l.logs(dnsSink, t0)
	result["without_policies"] = map[string]any{"nonce": open, "egr-a": ra, "egr-b": rb,
		"origin_blocked_paths": paths(blockedLog), "origin_allowed_paths": paths(allowedLog), "dns_sink": dnsNames(sinkLog)}
	for _, k := range []string{"proxy-connect-allowed", "proxy-http-allowed", "dns-proxy-name", "direct-allowed", "direct-blocked",
		"direct-name", "direct-stream", "dns-exfil", "dns-exfil-direct", "apiserver", "node", "metadata"} {
		c.add("without policies: egr-a "+k, "reached (positive control)", brief(ra[k]), ra[k].OK)
	}
	c.add("without policies: egr-a proxy-connect-blocked", "proxy answers 403", brief(ra["proxy-connect-blocked"]), ra["proxy-connect-blocked"].ProxyStatus == 403)
	c.add("without policies: egr-a proxy-http-blocked", "proxy answers 403", brief(ra["proxy-http-blocked"]), ra["proxy-http-blocked"].Status == 403)
	c.add("without policies: egr-a dns-exfil answer", "the sink's TXT", brief(ra["dns-exfil"]), strings.Join(ra["dns-exfil"].Answers, "") == "warden-lab-exfil-received")
	c.add("without policies: egr-b nogrant-tcp", "proxy reachable", brief(rb["nogrant-tcp"]), rb["nogrant-tcp"].OK)
	c.add("without policies: egr-b nogrant-connect", "proxy closes the connection (no grant)", brief(rb["nogrant-connect"]),
		!rb["nogrant-connect"].OK && strings.Contains(rb["nogrant-connect"].ConnectError+rb["nogrant-connect"].Error, "proxy closed"))
	c.add("without policies: origin-blocked log", "direct requests /d- and /n- arrived",
		strings.Join(containing(paths(blockedLog), open), " "),
		len(containing(paths(blockedLog), "/d-"+open)) == 1 && len(containing(paths(blockedLog), "/n-"+open)) == 1)
	c.add("without policies: DNS sink log", "both exfil queries arrived", strings.Join(containing(dnsNames(sinkLog), open), " "),
		len(containing(dnsNames(sinkLog), open)) == 2)

	// With the policies.
	result["policies"] = []any{l.applyPolicy("default-deny.yaml"), l.applyPolicy("egress-proxy.yaml")}
	for name, ip := range map[string]string{"egr-a": ipA, "egr-b": ipB, "egr-ctl": ipCtl} {
		e, _ := l.endpoint(ip)
		result["endpoint_"+name] = map[string]any{"id": e.ID, "identity": e.Status.Identity.ID, "labels": e.Status.Identity.Labels,
			"policy_enabled": e.Status.Policy.Realized.PolicyEnabled, "policy_revision": e.Status.Policy.Realized.Revision}
	}
	closed := nonce()
	t1 := time.Now()
	ra, rb = l.net("egr-a", cases(closed)...), l.net("egr-b", noGrant...)
	t2 := time.Now()
	rc := l.net("egr-ctl", "ctl-direct-blocked,get,http://"+w+".21/c-"+closed, "ctl-dns-exfil,dns,TXT,ctl-"+closed+".exfil.warden.test")
	time.Sleep(time.Second)
	blockedLog, allowedLog, sinkLog = l.logs(originBlocked, t1), l.logs(originAllowed, t1), l.logs(dnsSink, t1)
	result["with_policies"] = map[string]any{"nonce": closed, "egr-a": ra, "egr-b": rb, "egr-ctl": rc,
		"sandbox_probes_ms":    ms(t2.Sub(t1).Seconds()),
		"origin_blocked_paths": paths(blockedLog), "origin_allowed_paths": paths(allowedLog), "dns_sink": dnsNames(sinkLog)}
	for _, k := range []string{"proxy-connect-allowed", "proxy-http-allowed"} {
		c.add("with policies: egr-a "+k, "reached through the proxy", brief(ra[k]), ra[k].OK && strings.Contains(ra[k].Body, "origin-allowed"))
	}
	c.add("with policies: egr-a proxy-connect-blocked", "proxy answers 403", brief(ra["proxy-connect-blocked"]), ra["proxy-connect-blocked"].ProxyStatus == 403)
	c.add("with policies: egr-a proxy-http-blocked", "proxy answers 403", brief(ra["proxy-http-blocked"]), ra["proxy-http-blocked"].Status == 403)
	c.add("with policies: egr-a dns-proxy-name", "resolves (the one name allowed)", brief(ra["dns-proxy-name"]), ra["dns-proxy-name"].OK)
	for _, k := range []string{"direct-allowed", "direct-blocked", "direct-stream", "apiserver", "node", "metadata"} {
		r := ra[k]
		c.add("with policies: egr-a "+k, "no connection", brief(r), !r.OK && r.Status == 0 && (r.ConnectError != "" || r.Error != ""))
	}
	c.add("with policies: egr-a direct-name", "name not resolved", brief(ra["direct-name"]), !ra["direct-name"].OK && ra["direct-name"].ResolveError != "")
	c.add("with policies: egr-a dns-exfil", "no answer from the sink", brief(ra["dns-exfil"]), !ra["dns-exfil"].OK && len(ra["dns-exfil"].Answers) == 0)
	c.add("with policies: egr-a dns-exfil-direct", "no answer", brief(ra["dns-exfil-direct"]), !ra["dns-exfil-direct"].OK && len(ra["dns-exfil-direct"].Answers) == 0)
	c.add("with policies: egr-b nogrant-tcp", "proxy reachable", brief(rb["nogrant-tcp"]), rb["nogrant-tcp"].OK)
	c.add("with policies: egr-b nogrant-connect", "proxy closes the connection (no grant)", brief(rb["nogrant-connect"]),
		!rb["nogrant-connect"].OK && strings.Contains(rb["nogrant-connect"].ConnectError+rb["nogrant-connect"].Error, "proxy closed"))
	c.add("with policies: egr-ctl ctl-direct-blocked (control, no sandbox label)", "reached", brief(rc["ctl-direct-blocked"]), rc["ctl-direct-blocked"].OK)
	c.add("with policies: egr-ctl ctl-dns-exfil (control)", "the sink's TXT", brief(rc["ctl-dns-exfil"]), rc["ctl-dns-exfil"].OK)
	got := containing(paths(blockedLog), closed)
	c.add("with policies: origin-blocked log", "only the control's /c- request", strings.Join(got, " "),
		len(got) == 1 && strings.Contains(got[0], "/c-"+closed))
	got = containing(paths(allowedLog), closed)
	c.add("with policies: origin-allowed log", "only the proxied /p- request, Host allowed.warden.test", strings.Join(got, " "),
		len(got) == 1 && got[0] == "allowed.warden.test/p-"+closed)
	got = containing(dnsNames(sinkLog), closed)
	c.add("with policies: DNS sink log", "only the control's query", strings.Join(got, " "),
		len(got) == 1 && strings.Contains(got[0], "ctl-"+closed))
	result["checks"] = c.all
	result["loadavg_end"] = loadavg()
	record(t, result)
}
