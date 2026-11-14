package ciliumlab

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/respond"
)

const (
	streamTarget = "stream.warden.test:443" // the lab's stream stand-in, through the proxy
	streamEvery  = "20"                     // ms between two lines, each way
	// A stream counts as cut once no line went either way for this long
	// (each way carries 50 lines a second while it is up).
	quietS = 5.0
	// How long a rep waits for the cut, from the alert.
	maxWatch    = 60 * time.Second
	responderNS = "warden-respond"
	responderSA = "warden-responder"
	// What the quarantined endpoint's identity carries once Cilium has
	// taken the label in.
	quarantinedLabel = "k8s:" + respond.QuarantineLabel + "=true"
)

func quarantineReps(t *testing.T) int {
	n := 12
	if v := os.Getenv("WARDEN_CILIUM_REPS"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			t.Fatalf("WARDEN_CILIUM_REPS=%q", v)
		}
	}
	return n
}

// responder creates a service account that may only get and patch pods in
// the sandbox namespace and returns a 10-minute token for it, with what the
// API server says it may do. The test's cleanup removes it.
func (l *lab) responder() (string, map[string]bool) {
	l.t.Helper()
	l.apply(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": responderNS}})
	l.t.Cleanup(func() {
		for _, args := range [][]string{{"-n", sandboxNS, "delete", "rolebinding,role", "warden-isolate-pod", "--ignore-not-found"},
			{"delete", "namespace", responderNS, "--ignore-not-found", "--wait=true", "--timeout=120s"}} {
			if _, err := l.kubectl(nil, args...); err != nil {
				l.t.Errorf("remove the responder: %v", err)
			}
		}
	})
	l.apply(map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": responderSA, "namespace": responderNS},
		"automountServiceAccountToken": false})
	l.apply(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
		"metadata": map[string]any{"name": "warden-isolate-pod", "namespace": sandboxNS},
		"rules":    []map[string]any{{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get", "patch"}}}})
	l.apply(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "warden-isolate-pod", "namespace": sandboxNS},
		"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "warden-isolate-pod"},
		"subjects": []map[string]string{{"kind": "ServiceAccount", "name": responderSA, "namespace": responderNS}}})
	token := strings.TrimSpace(string(l.must(l.kubectl(nil, "-n", responderNS, "create", "token", responderSA, "--duration=600s"))))
	as := "--as=system:serviceaccount:" + responderNS + ":" + responderSA
	rbac := map[string]bool{}
	for _, c := range [][3]string{{"patch", "pods", sandboxNS}, {"get", "pods", sandboxNS}, {"delete", "pods", sandboxNS},
		{"create", "pods/exec", sandboxNS}, {"patch", "pods", "kube-system"}, {"get", "secrets", sandboxNS},
		{"delete", "ciliumclusterwidenetworkpolicies", ""}} {
		args := []string{"auth", "can-i", as, c[0], c[1]}
		if c[2] != "" {
			args = append(args, "-n", c[2])
		}
		out, _ := l.kubectl(nil, args...) // "no" exits 1
		rbac[strings.TrimSpace(strings.Join(c[:], " "))] = strings.TrimSpace(string(out)) == "yes"
	}
	return token, rbac
}

// identityPoll follows the endpoint of ip until its identity carries the
// quarantine label: lastWithout is the start of the last poll that did not
// show it, firstWith the start of the first that did (each 0 if no such poll).
type identityPoll struct {
	lastWithout, firstWith float64
	before, after          int // the identity numbers
	polls                  int
}

// record returns a rep's identity fields, in ms after the alert at e0. A
// field no poll observed is null: when the first poll already shows the
// label there is no identity and no time from before it.
func (p identityPoll) record(e0 float64) map[string]any {
	r := map[string]any{"polls": p.polls, "before": nil, "last_poll_without_label_ms": nil,
		"after": nil, "first_poll_with_label_ms": nil}
	if p.lastWithout != 0 {
		r["before"], r["last_poll_without_label_ms"] = p.before, ms(p.lastWithout-e0)
	}
	if p.firstWith != 0 {
		r["after"], r["first_poll_with_label_ms"] = p.after, ms(p.firstWith-e0)
	}
	return r
}

// bracketed reports whether a poll without the label came before the first
// poll with it, so that the identity switch lies between two observed polls.
func (p identityPoll) bracketed() bool { return p.lastWithout != 0 && p.firstWith != 0 }

func (l *lab) pollIdentity(ip string, stop <-chan struct{}) <-chan identityPoll {
	done := make(chan identityPoll, 1)
	go func() {
		var p identityPoll
		defer func() { done <- p }()
		for {
			t := epoch(time.Now())
			e, ok := l.endpoint(ip)
			p.polls++
			if ok {
				if slices.Contains(e.Status.Identity.Labels, quarantinedLabel) {
					p.firstWith, p.after = t, e.Status.Identity.ID
					return
				}
				p.lastWithout, p.before = t, e.Status.Identity.ID
			}
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return done
}

// TestQuarantineCutsEstablishedConnections (Task 14): respond's IsolatePod
// labels a pod warden.dev/quarantine=true through the executor and the real
// Kubernetes adapter, with a token that may only get and patch pods; the
// lab has policies/cilium/quarantine.yaml in force, next to default-deny.yaml
// and egress-proxy.yaml. Each rep starts a fresh gVisor sandbox whose one
// long-lived connection, established before the alert, goes through the
// egress proxy to the lab's stream server, a line every 20 ms each way. The
// rep measures from the alert (the call to the executor) to the last line
// that got through either way, and calls the connection cut once nothing
// went either way for 5 s; the plan requires the cut within 1 s. Positive
// controls: the stream is up before the alert, a new request from the
// target gets through before it, and a control sandbox's own stream through
// the same proxy must keep flowing (no gap over 1 s either way) through
// every rep. A new request from the target after the cut must fail.
func TestQuarantineCutsEstablishedConnections(t *testing.T) {
	l := liveLab(t)
	n := quarantineReps(t)
	result := map[string]any{"loadavg_start": loadavg(), "started": time.Now().UTC().Format(time.RFC3339), "reps": n,
		"quiet_s": quietS, "max_watch_s": maxWatch.Seconds(), "stream_every_ms": streamEvery,
		"requirement": "every rep: the established connection carries nothing either way from 1000 ms after the alert on"}
	p := l.proxy()
	result["proxy_image"] = p.image
	result["policies"] = []any{l.applyPolicy("default-deny.yaml"), l.applyPolicy("egress-proxy.yaml"), l.applyPolicy("quarantine.yaml")}
	token, rbac := l.responder()
	result["responder_rbac"] = rbac
	c := &checks{t: t}
	for k, v := range rbac {
		want := k == "patch pods "+sandboxNS || k == "get pods "+sandboxNS
		c.add("responder may "+k, strconv.FormatBool(want), strconv.FormatBool(v), v == want)
	}
	hc, err := l.cluster.HTTPClient(false)
	if err != nil {
		t.Fatal(err)
	}
	pb := respond.Playbook{ID: "isolate-sandbox-pod", Trigger: "warden-sandbox-reverse-shell",
		Steps: []respond.Action{{Name: respond.IsolatePod, Resource: respond.Resource{Type: "pod"}}}}
	journal := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	ex, err := respond.New(respond.Config{Playbook: pb, AllowedTenantIDs: []string{"tenant-a"},
		JournalPath: filepath.Join(journal, "attempts.journal"),
		Actions:     respond.Router{respond.IsolatePod: respond.Kubernetes{Server: l.cluster.Server, Token: token, HTTP: hc}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Close()

	run := nonce()
	stream := func(name string) []string {
		return []string{"stream", proxyAddr, streamTarget, name, streamEvery}
	}
	// up waits until a stream has carried lines both ways for a second.
	up := func(pod, name string) StreamLines {
		t.Helper()
		since := time.Now()
		for {
			now := epoch(time.Now())
			s := Stream(l.logs(streamServer, since.Add(-time.Minute)), l.podLog(pod), name)
			if Count(s.Up, now-1, now) >= 10 && Count(s.Down, now-1, now) >= 10 {
				return s
			}
			if time.Since(since) > 90*time.Second {
				t.Fatalf("stream %s of %s not up after 90 s (up %d, down %d lines)", name, pod, len(s.Up), len(s.Down))
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	ctlName := "ctl-" + run
	ctlIP := l.sandboxRunning("q-ctl", true, stream(ctlName)...)
	p.grant(ctlIP, "stream.warden.test")
	up("q-ctl", ctlName)
	result["control"] = map[string]any{"pod": "q-ctl", "ip": ctlIP, "stream": ctlName, "runtime_handler": l.runtimeHandler("q-ctl")}

	var cutMS, handleMS, switchMS, lastUpMS, lastDownMS []float64
	var reps []map[string]any
	labelledFirst := 0 // reps whose first poll already showed the label
	for i := range n {
		pod, name := fmt.Sprintf("q-%02d", i), fmt.Sprintf("q%02d-%s", i, run)
		phase := fmt.Sprintf("rep %02d", i)
		ip := l.sandboxRunning(pod, true, stream(name)...)
		p.grant(ip, "stream.warden.test", "allowed.warden.test")
		repStart := time.Now()
		up(pod, name)
		rep := map[string]any{"pod": pod, "ip": ip, "stream": name, "runtime_handler": l.runtimeHandler(pod), "loadavg": loadavg()}
		before := l.net(pod, "new-before,proxy,"+proxyAddr+",http://allowed.warden.test/qb-"+name)["new-before"]
		c.add(phase+": new request before the alert (positive control)", "reached", brief(before), before.OK)
		alert := respond.Alert{ID: "cilium-isolate-" + name, RuleID: "warden-sandbox-reverse-shell", TenantID: "tenant-a",
			Resource: respond.Resource{Type: "pod", ID: sandboxNS + "/" + pod}}
		if i == 0 {
			d0 := time.Now()
			r, err := ex.Handle(alert, true)
			c.add(phase+": dry run", "Preview", fmt.Sprintf("%+v %v", r, err), err == nil && r.Status == respond.Preview)
			time.Sleep(1500 * time.Millisecond)
			pd, _ := l.pod(sandboxNS, pod)
			s := Stream(l.logs(streamServer, repStart.Add(-time.Minute)), l.podLog(pod), name)
			e := epoch(d0)
			c.add(phase+": dry run leaves the pod and its stream alone", "no label, lines both ways",
				fmt.Sprintf("label %q, up %d, down %d", pd.Metadata.Labels[respond.QuarantineLabel], Count(s.Up, e+0.5, e+1.5), Count(s.Down, e+0.5, e+1.5)),
				pd.Metadata.Labels[respond.QuarantineLabel] == "" && Count(s.Up, e+0.5, e+1.5) >= 10 && Count(s.Down, e+0.5, e+1.5) >= 10)
		}

		stop := make(chan struct{})
		ident := l.pollIdentity(ip, stop)
		t0 := time.Now()
		r, err := ex.Handle(alert, false)
		handled := time.Since(t0)
		e0 := epoch(t0)
		c.add(phase+": IsolatePod", "Completed", fmt.Sprintf("%+v %v", r, err), err == nil && r.Status == respond.Completed)

		// Watch until the stream is cut or the watch is over.
		var s, ctl StreamLines
		var cut Cut
		var end float64
		for {
			time.Sleep(500 * time.Millisecond)
			srv := l.logs(streamServer, repStart.Add(-time.Minute))
			s, ctl = Stream(srv, l.podLog(pod), name), Stream(srv, l.podLog("q-ctl"), ctlName)
			end = epoch(time.Now())
			if cut = Measure(s, e0, end, quietS); cut.Stopped || time.Since(t0) > maxWatch {
				break
			}
		}
		close(stop)
		id := <-ident
		pd, _ := l.pod(sandboxNS, pod)
		rep["handle_ms"], rep["cut"], rep["watch_ms"] = ms(handled.Seconds()), cut, ms(end-e0)
		rep["identity"] = id.record(e0)
		rep["lines_after_alert"] = map[string]int{"up": Count(s.Up, e0, end+1), "down": Count(s.Down, e0, end+1)}
		rep["probe_saw_close_ms"] = 0.0
		if s.Closed != 0 {
			rep["probe_saw_close_ms"] = ms(s.Closed - e0)
		}
		c.add(phase+": stream up before the alert", "lines both ways in the second before it",
			fmt.Sprintf("up %d, down %d", Count(s.Up, e0-1, e0), Count(s.Down, e0-1, e0)), Count(s.Up, e0-1, e0) >= 10 && Count(s.Down, e0-1, e0) >= 10)
		c.add(phase+": pod labelled", "true", pd.Metadata.Labels[respond.QuarantineLabel], pd.Metadata.Labels[respond.QuarantineLabel] == "true")
		c.add(phase+": established connection cut", fmt.Sprintf("nothing either way for %.0f s within %.0f s of the alert", quietS, maxWatch.Seconds()),
			fmt.Sprintf("%+v", cut), cut.Stopped)
		c.add(phase+": cut within 1 s (requirement)", "last line <= 1000 ms after the alert",
			fmt.Sprintf("%.1f ms (up %.1f, down %.1f)", cut.CutMS, cut.LastUpMS, cut.LastDownMS), cut.Stopped && cut.CutMS <= 1000)
		upGap, downGap := MaxGap(ctl.Up, e0, end), MaxGap(ctl.Down, e0, end)
		rep["control_max_gap_ms"] = map[string]float64{"up": ms(upGap), "down": ms(downGap)}
		c.add(phase+": control stream kept flowing", "no gap over 1000 ms either way, not closed",
			fmt.Sprintf("gaps up %.1f ms, down %.1f ms, closed %v", ms(upGap), ms(downGap), ctl.Closed != 0),
			upGap <= 1 && downGap <= 1 && ctl.Closed == 0)
		after := l.net(pod, "new-after,proxy,"+proxyAddr+",http://allowed.warden.test/qa-"+name)["new-after"]
		c.add(phase+": new request after the cut", "fails", brief(after), !after.OK && after.Status == 0)
		r2, err := ex.Handle(alert, false)
		c.add(phase+": replay", "no-op", fmt.Sprintf("%+v %v", r2, err), err == nil && r2.NoOp)
		rep["new_before"], rep["new_after"] = before, after
		reps = append(reps, rep)
		handleMS = append(handleMS, ms(handled.Seconds()))
		lastUpMS, lastDownMS = append(lastUpMS, cut.LastUpMS), append(lastDownMS, cut.LastDownMS)
		if cut.Stopped {
			cutMS = append(cutMS, cut.CutMS)
		}
		if id.bracketed() {
			switchMS = append(switchMS, ms(id.firstWith-e0))
		} else if id.firstWith != 0 {
			labelledFirst++
		}
		l.deletePod(sandboxNS, pod)
		p.grant(ip)
	}
	within := 0
	for _, v := range cutMS {
		if v <= 1000 {
			within++
		}
	}
	allowed := l.logs(originAllowed, time.Now().Add(-2*time.Hour))
	result["origin_allowed_paths"] = containing(paths(allowed), run)
	c.add("origin log", "only the new-before requests", strings.Join(containing(paths(allowed), "/qa-"), " "),
		len(containing(containing(paths(allowed), run), "/qa-")) == 0 && len(containing(containing(paths(allowed), run), "/qb-")) == n)
	result["reps_detail"] = reps
	result["summary"] = map[string]any{
		"percentiles":                     "nearest rank",
		"alert_to_cut_ms":                 Summary(cutMS),
		"alert_to_identity_with_label_ms": Summary(switchMS), // only reps with a poll before the switch
		"identity_labelled_on_first_poll": fmt.Sprintf("%d/%d", labelledFirst, n),
		"handle_ms":                       Summary(handleMS),
		"alert_to_last_up_line_ms":        Summary(lastUpMS),
		"alert_to_last_down_line_ms":      Summary(lastDownMS),
		"cut":                             fmt.Sprintf("%d/%d", len(cutMS), n),
		"cut_within_1s":                   fmt.Sprintf("%d/%d", within, n),
	}
	result["checks"] = c.all
	result["loadavg_end"] = loadavg()
	record(t, result)
}
