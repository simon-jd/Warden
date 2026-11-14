package respond

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TerminatePod ends every process of a quarantined pod, which is what closes
// connections the quarantine label leaves open. It is destructive, so a
// playbook for it must require a second approver.
func TestTerminatePodNeedsSecondApprover(t *testing.T) {
	step := []Action{{Name: TerminatePod, Resource: Resource{Type: "pod"}}}
	if err := validatePlaybook(Playbook{ID: "terminate", Trigger: "rule-t", Steps: step}); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("TerminatePod playbook without approval: %v", err)
	}
	if err := validatePlaybook(Playbook{ID: "terminate", Trigger: "rule-t", Steps: []Action{{Name: TerminatePod, Resource: Resource{Type: "pod", ID: "ns/p"}}}, RequiresApproval: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TerminatePod target fixed in the playbook: %v", err)
	}
	raw := []byte(`{"id":"terminate-pod","trigger":"rule-t","steps":[{"name":"TerminatePod","resource":{"type":"pod","id":""}}],"requires_approval":true}`)
	if _, err := ParsePlaybook(raw); err != nil {
		t.Fatalf("parse: %v", err)
	}

	e, actions, _ := containmentExecutor(t, TerminatePod, "pod", true)
	alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: "pod", ID: "tenant-a-sandbox/run-1"}}
	if _, err := e.Handle(alert, false); !errors.Is(err, ErrApprovalDenied) || len(actions.calls) != 0 {
		t.Fatalf("terminate without approval: %v, calls %d", err, len(actions.calls))
	}
	alert.RequesterCredential, alert.ApprovalProof = "test-requester-credential", "test-approval-proof"
	if r, err := e.Handle(alert, true); err != nil || r.Status != Preview || !r.ApprovalNeeded || len(actions.calls) != 0 {
		t.Fatalf("dry run = %+v, %v, calls %d", r, err, len(actions.calls))
	}
	if r, err := e.Handle(alert, false); err != nil || r.Status != Completed || len(actions.calls) != 1 || actions.calls[0].Name != TerminatePod {
		t.Fatalf("approved terminate = %+v, %v, calls %+v", r, err, actions.calls)
	}

	// Self-approval: requester and approver are the same principal.
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	self := &recordingAuthority{now: now, mutate: func(a *Approval) { a.Approver = a.Requester; a.Approver.Roles = []string{"respond:approve"} }}
	e2, err := New(Config{Playbook: Playbook{ID: "terminate", Trigger: "rule-c", Steps: step, RequiresApproval: true},
		AllowedTenantIDs: []string{"tenant-a"}, JournalPath: filepath.Join(dir, "attempts.journal"),
		Authority: self, Actions: actions, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	alert.ID = "alert-2"
	if _, err := e2.Handle(alert, false); !errors.Is(err, ErrApprovalDenied) || len(actions.calls) != 1 {
		t.Fatalf("self-approved terminate: %v, calls %d", err, len(actions.calls))
	}
}

func TestKubernetesTerminatePodDeletesImmediately(t *testing.T) {
	srv, got := recorder(t, http.StatusOK)
	k := Kubernetes{Server: srv.URL, Token: "sa-token"}
	a := Action{Name: TerminatePod, Resource: Resource{Type: "pod", ID: "tenant-a-sandbox/run-1"}}
	if err := k.Contain(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("requests %+v", *got)
	}
	r := (*got)[0]
	if r.Method != http.MethodDelete || r.Path != "/api/v1/namespaces/tenant-a-sandbox/pods/run-1" || r.Auth != "Bearer sa-token" ||
		r.Body["kind"] != "DeleteOptions" || r.Body["gracePeriodSeconds"] != float64(0) {
		t.Fatalf("terminate request %+v", r)
	}
	// Already gone is contained; any other refusal is an error.
	gone, _ := recorder(t, http.StatusNotFound)
	if err := (Kubernetes{Server: gone.URL, Token: "t"}).Contain(context.Background(), a); err != nil {
		t.Fatalf("404 on terminate: %v", err)
	}
	denied, _ := recorder(t, http.StatusForbidden)
	if err := (Kubernetes{Server: denied.URL, Token: "t"}).Contain(context.Background(), a); err == nil {
		t.Fatal("403 on terminate accepted")
	}
	isolateGone, _ := recorder(t, http.StatusNotFound)
	if err := (Kubernetes{Server: isolateGone.URL, Token: "t"}).Contain(context.Background(), Action{Name: IsolatePod, Resource: a.Resource}); err == nil {
		t.Fatal("404 on isolate accepted: a missing pod was never labelled")
	}
}
