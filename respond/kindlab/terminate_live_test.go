package kindlab

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/respond"
)

const (
	terminatorSA  = "warden-terminator"
	terminateRuns = 5
)

// fixtureAuthority stands in for the real approval service: it returns a
// second, distinct approver for the requested binding. It is test wiring, not
// identity proof; the executor's own checks (binding, roles, distinct
// principals, expiry) still run on what it returns.
type fixtureAuthority struct{}

func (fixtureAuthority) Verify(_ context.Context, req respond.ApprovalRequest) (respond.Approval, error) {
	if req.RequesterCredential != "kind-lab-requester" || req.ApprovalProof != "kind-lab-approval" {
		return respond.Approval{}, fmt.Errorf("fixture authority: unknown credentials")
	}
	now := time.Now()
	return respond.Approval{
		Requester: respond.Principal{Issuer: "kind-lab", Subject: "operator", CanonicalID: "kind-lab-operator", Roles: []string{"respond:execute"}},
		Approver:  respond.Principal{Issuer: "kind-lab", Subject: "approver", CanonicalID: "kind-lab-approver", Roles: []string{"respond:approve"}},
		Binding:   req.Binding, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(2 * time.Minute),
	}, nil
}

// terminator creates a ServiceAccount that may only get and delete pods in the
// sandbox namespace, and returns a 10-minute token for it.
func (l *lab) terminator() string {
	l.create("/api/v1/namespaces/"+responderNS+"/serviceaccounts",
		map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta(terminatorSA, responderNS)})
	l.create("/apis/rbac.authorization.k8s.io/v1/namespaces/"+sandboxNS+"/roles", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta("warden-terminate-pod", sandboxNS),
		"rules": []map[string]any{{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get", "delete"}}}})
	l.create("/apis/rbac.authorization.k8s.io/v1/namespaces/"+sandboxNS+"/rolebindings", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta("warden-terminate-pod", sandboxNS),
		"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "warden-terminate-pod"},
		"subjects": []map[string]string{{"kind": "ServiceAccount", "name": terminatorSA, "namespace": responderNS}}})
	var tr struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	l.must(l.admin.Do(l.ctx, http.MethodPost, "/api/v1/namespaces/"+responderNS+"/serviceaccounts/"+terminatorSA+"/token", "",
		map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": map[string]any{"expirationSeconds": 600}},
		&tr), "terminator token")
	return tr.Status.Token
}

func (l *lab) allowedFor(token, verb, resource, ns string) bool {
	hc, err := l.cluster.HTTPClient(false)
	l.must(err, "client")
	var r struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	l.must(API{Server: l.cluster.Server, HTTP: hc, Token: token}.Do(l.ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": map[string]string{"verb": verb, "resource": resource, "namespace": ns}}}, &r), "access review")
	return r.Status.Allowed
}

// echoEnds returns when b's echo server saw a connection from client close.
func (l *lab) echoEnds(pod, client string, since int) []float64 {
	var raw []byte
	l.must(l.admin.Do(l.ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?sinceSeconds=%d", sandboxNS, pod, since),
		"", nil, &raw), "logs "+pod)
	var out []float64
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 4 && f[1] == "echo" && f[2] == "end" && f[3] == client {
			if at, err := strconv.ParseFloat(f[0], 64); err == nil {
				out = append(out, at)
			}
		}
	}
	return out
}

func (l *lab) podGone(name string) bool {
	err := l.admin.Do(l.ctx, http.MethodGet, "/api/v1/namespaces/"+sandboxNS+"/pods/"+name, "", nil, nil)
	return IsStatus(err, http.StatusNotFound)
}

// TestKindTerminateClosesEstablishedConnections measures the step after
// IsolatePod: the quarantine label leaves an already-open connection working
// (TestKindIsolatePodAndCordonNode), so TerminatePod, approved by a second
// person, deletes the pod. The open connection's peer must see it close
// within one second of the alert reaching the executor.
func TestKindTerminateClosesEstablishedConnections(t *testing.T) {
	l := liveLab(t)
	loadStart := loadavg()
	l.setup()
	token := l.terminator()
	result := map[string]any{"terminate_runs": terminateRuns, "approval": "fixture authority (test wiring, not a real approver identity)"}
	rbac := map[string]bool{
		"delete pods warden-sandbox": l.allowedFor(token, "delete", "pods", sandboxNS),
		"patch pods warden-sandbox":  l.allowedFor(token, "patch", "pods", sandboxNS),
		"delete pods kube-system":    l.allowedFor(token, "delete", "pods", "kube-system"),
		"create pods/exec":           l.allowedFor(token, "create", "pods/exec", sandboxNS),
		"get secrets warden-sandbox": l.allowedFor(token, "get", "secrets", sandboxNS),
	}
	result["terminator_rbac"] = rbac
	for k, v := range rbac {
		if want := k == "delete pods warden-sandbox"; v != want {
			t.Errorf("terminator may %s = %v, want %v", k, v, want)
		}
	}

	hc, err := l.cluster.HTTPClient(false)
	l.must(err, "adapter client")
	iso := newExecutor(t, respond.Playbook{ID: "isolate-sandbox-pod", Trigger: "warden-sandbox-reverse-shell",
		Steps: []respond.Action{{Name: respond.IsolatePod, Resource: respond.Resource{Type: "pod"}}}},
		respond.Kubernetes{Server: l.cluster.Server, Token: l.token, HTTP: hc})
	dir := filepath.Join(t.TempDir(), "journal")
	l.must(os.Mkdir(dir, 0o700), "journal dir")
	term, err := respond.New(respond.Config{
		Playbook: respond.Playbook{ID: "terminate-quarantined-pod", Trigger: "warden-sandbox-reverse-shell", RequiresApproval: true,
			Steps: []respond.Action{{Name: respond.TerminatePod, Resource: respond.Resource{Type: "pod"}}}},
		AllowedTenantIDs: []string{"tenant-a"}, JournalPath: filepath.Join(dir, "attempts.journal"), Authority: fixtureAuthority{},
		Actions: respond.Router{respond.TerminatePod: respond.Kubernetes{Server: l.cluster.Server, Token: token, HTTP: hc}}})
	l.must(err, "terminate executor")
	t.Cleanup(func() { term.Close() })

	ipB := l.podIP("echo", nil)
	closeMS, goneMS, handleMS := map[string][]float64{}, map[string][]float64{}, map[string][]float64{}
	var runs []map[string]any
	// "ignores-sigterm" is the measured case: the target runs as PID 1 with the
	// default SIGTERM disposition, like a process that will not exit when asked.
	// "exits-on-sigterm" is a diagnostic for where the time goes.
	type variant struct{ name, kind string }
	var variants []variant
	for i := range terminateRuns {
		variants = append(variants, variant{fmt.Sprintf("t%d", i), "ignores-sigterm"})
	}
	for i := range 3 {
		variants = append(variants, variant{fmt.Sprintf("c%d", i), "exits-on-sigterm"})
	}
	for _, v := range variants {
		name := v.name
		env := map[string]string{"PERSIST": ipB + ":8081"}
		if v.kind == "exits-on-sigterm" {
			env["EXIT_ON_TERM"] = "1"
		}
		ip := l.podIP(name, env)
		deadline := time.Now().Add(60 * time.Second)
		for count(l.samples(name, 5), epoch(time.Now())-1, epoch(time.Now()), "persist", "old", true) < 3 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: long-lived connection never up: %v", name, tail(l.samples(name, 5)))
			}
			time.Sleep(200 * time.Millisecond)
		}
		target := respond.Resource{Type: "pod", ID: sandboxNS + "/" + name}
		if r, err := iso.Handle(respond.Alert{ID: "kind-term-iso-" + name, RuleID: "warden-sandbox-reverse-shell", TenantID: "tenant-a", Resource: target}, false); err != nil || r.Status != respond.Completed {
			t.Fatalf("%s: isolate = %+v, %v", name, r, err)
		}
		i0 := epoch(time.Now())
		time.Sleep(2 * time.Second)
		// Reproduces the phase-5 finding before the new step runs.
		stillOpen := count(l.samples(name, 5), i0+1, i0+2, "persist", "old", true)

		alert := respond.Alert{ID: "kind-term-" + name, RuleID: "warden-sandbox-reverse-shell", TenantID: "tenant-a", Resource: target}
		if _, err := term.Handle(alert, false); err == nil {
			t.Fatalf("%s: terminate ran without approval credentials", name)
		}
		alert.RequesterCredential, alert.ApprovalProof = "kind-lab-requester", "kind-lab-approval"
		if r, err := term.Handle(alert, true); err != nil || r.Status != respond.Preview || l.podGone(name) {
			t.Fatalf("%s: dry run = %+v, %v, gone=%v", name, r, err, l.podGone(name))
		}
		t0 := time.Now()
		r, err := term.Handle(alert, false)
		handled := time.Since(t0)
		if err != nil || r.Status != respond.Completed {
			t.Fatalf("%s: terminate = %+v, %v", name, r, err)
		}
		e0 := epoch(t0)
		var closed, gone float64
		for time.Since(t0) < 30*time.Second && (closed == 0 || gone == 0) {
			if gone == 0 && l.podGone(name) {
				gone = epoch(time.Now())
			}
			if closed == 0 {
				for _, at := range l.echoEnds("echo", ip, 60) {
					if at >= e0 {
						closed = at
						break
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if r2, err := term.Handle(alert, false); err != nil || !r2.NoOp {
			t.Fatalf("%s: replay = %+v, %v", name, r2, err)
		}
		run := map[string]any{"pod": name, "variant": v.kind, "pod_ip": ip, "persist_old_ok_1to2s_after_isolate": stillOpen, "handle_ms": ms(handled.Seconds())}
		if closed == 0 {
			run["alert_to_peer_saw_close_ms"] = nil
			runs = append(runs, run)
			t.Errorf("%s: established connection not closed within 30 s", name)
			continue
		}
		run["alert_to_peer_saw_close_ms"] = ms(closed - e0)
		run["alert_to_pod_object_gone_ms"] = ms(gone - e0)
		runs = append(runs, run)
		closeMS[v.kind] = append(closeMS[v.kind], ms(closed-e0))
		goneMS[v.kind] = append(goneMS[v.kind], ms(gone-e0))
		handleMS[v.kind] = append(handleMS[v.kind], ms(handled.Seconds()))
		if stillOpen == 0 {
			t.Logf("%s: open connection already failed after isolation (phase-5 finding not reproduced)", name)
		}
		if v.kind == "ignores-sigterm" && closed-e0 > 1 {
			t.Errorf("%s: established connection closed %.0f ms after the alert, want <= 1000 ms", name, (closed-e0)*1000)
		}
	}
	result["runs"] = runs
	for _, kind := range []string{"ignores-sigterm", "exits-on-sigterm"} {
		result[kind] = map[string]any{"alert_to_peer_saw_close_ms": stats(closeMS[kind]),
			"alert_to_pod_object_gone_ms": stats(goneMS[kind]), "handle_ms": stats(handleMS[kind])}
	}
	result["measure"] = "peer (echo pod) logs when its read of the open connection returns EOF or an error; time from Handle start"
	result["load"] = map[string]any{"nproc": runtime.NumCPU(), "loadavg_start": loadStart, "loadavg_end": loadavg()}
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("%s", out)
	if p := os.Getenv("TERMINATE_OUT"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
