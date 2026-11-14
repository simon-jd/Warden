package respond

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordingActions struct {
	mu    sync.Mutex
	calls []Action
	err   error
}

func (r *recordingActions) Contain(ctx context.Context, a Action) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, a)
	return r.err
}

// One valid alert target per containment action. The playbook names only the
// resource type; the concrete target comes from the alert.
var containmentCases = []struct {
	action  ActionName
	typ     string
	valid   string
	invalid []string
}{
	{RevokeVaultLease, "vault_lease", "database/creds/warden-app/Xy3kP9qL2mN8",
		[]string{"", "../sys/leases", "database//x", "database/creds/x/..", "/database/creds/x", "database creds"}},
	{DisableAzureServicePrincipalCredential, "azure_app_credential",
		"3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
		[]string{"", "3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f", "not-a-guid/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "3F2B8C1E-4D5A-4B6C-9E7F-0A1B2C3D4E5F/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"}},
	{IsolatePod, "pod", "tenant-a-sandbox/run-7q4kx",
		[]string{"", "run-7q4kx", "Tenant/run", "tenant-a/run/x", "-bad/run", "tenant-a/"}},
	{CordonNode, "node", "aks-sandbox-12345678-vmss000001",
		[]string{"", "Node_A", "node/a", "-node", "a..b"}},
}

func containmentExecutor(t *testing.T, action ActionName, typ string, approval bool) (*Executor, *recordingActions, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	actions := &recordingActions{}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	e, err := New(Config{
		Playbook:         Playbook{ID: "contain", Trigger: "rule-c", Steps: []Action{{Name: action, Resource: Resource{Type: typ}}}, RequiresApproval: approval},
		AllowedTenantIDs: []string{"tenant-a"},
		JournalPath:      filepath.Join(dir, "attempts.journal"),
		Authority:        &recordingAuthority{now: now},
		Actions:          actions,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, actions, dir
}

func TestContainmentPlaybookParses(t *testing.T) {
	raw := []byte(`{"id": "revoke-lease", "trigger": "rule-c", "steps": [{"name": "RevokeVaultLease", "resource": {"type": "vault_lease", "id": ""}}], "requires_approval": false}`)
	p, err := ParsePlaybook(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Name != RevokeVaultLease || p.RequiresApproval {
		t.Fatalf("parsed %+v", p)
	}
	// A containment step with a fixed target or the wrong type is rejected.
	for _, bad := range []string{
		`{"id": "x", "trigger": "rule-c", "steps": [{"name": "RevokeVaultLease", "resource": {"type": "vault_lease", "id": "database/creds/a/b"}}], "requires_approval": false}`,
		`{"id": "x", "trigger": "rule-c", "steps": [{"name": "IsolatePod", "resource": {"type": "node", "id": ""}}], "requires_approval": false}`,
		`{"id": "x", "trigger": "rule-c", "steps": [{"name": "SuspendTenant", "resource": {"type": "tenant", "id": "tenant-a"}}], "requires_approval": false}`,
	} {
		if _, err := ParsePlaybook([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestContainmentIdempotentPerAlert(t *testing.T) {
	for _, c := range containmentCases {
		t.Run(string(c.action), func(t *testing.T) {
			e, actions, _ := containmentExecutor(t, c.action, c.typ, false)
			alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: c.typ, ID: c.valid}}
			first, err := e.Handle(alert, false)
			if err != nil || first.Status != Completed || first.NoOp {
				t.Fatalf("first = %+v, %v", first, err)
			}
			second, err := e.Handle(alert, false)
			if err != nil || !second.NoOp || second.Status != Completed {
				t.Fatalf("second = %+v, %v", second, err)
			}
			want := Action{Name: c.action, Resource: alert.Resource}
			if len(actions.calls) != 1 || actions.calls[0] != want {
				t.Fatalf("calls %+v, want exactly [%+v]", actions.calls, want)
			}
			// Same alert ID with another target is a conflict, not a new action.
			other := alert
			other.Resource.ID = c.valid + "0"
			if c.action == DisableAzureServicePrincipalCredential {
				other.Resource.ID = "00000000-0000-4000-8000-000000000000/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
			}
			if _, err := e.Handle(other, false); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed target under same alert: %v", err)
			}
		})
	}
}

func TestContainmentDryRunMakesNoChanges(t *testing.T) {
	for _, c := range containmentCases {
		t.Run(string(c.action), func(t *testing.T) {
			e, actions, dir := containmentExecutor(t, c.action, c.typ, false)
			alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: c.typ, ID: c.valid}}
			r, err := e.Handle(alert, true)
			if err != nil || r.Status != Preview || r.ApprovalNeeded || r.Resource != alert.Resource {
				t.Fatalf("dry run = %+v, %v", r, err)
			}
			if len(actions.calls) != 0 {
				t.Fatalf("dry run called client: %+v", actions.calls)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("dry run touched the journal dir: %v", entries)
			}
		})
	}
}

func TestContainmentRejectsInvalidTargets(t *testing.T) {
	for _, c := range containmentCases {
		t.Run(string(c.action), func(t *testing.T) {
			e, actions, _ := containmentExecutor(t, c.action, c.typ, false)
			for _, id := range c.invalid {
				alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: c.typ, ID: id}}
				if _, err := e.Handle(alert, true); !errors.Is(err, ErrInvalid) {
					t.Errorf("target %q: %v", id, err)
				}
			}
			wrongType := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: "tenant", ID: "tenant-a"}}
			wrongTenant := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-b", Resource: Resource{Type: c.typ, ID: c.valid}}
			wrongRule := Alert{ID: "alert-1", RuleID: "rule-x", TenantID: "tenant-a", Resource: Resource{Type: c.typ, ID: c.valid}}
			for _, a := range []Alert{wrongType, wrongTenant, wrongRule} {
				if _, err := e.Handle(a, false); !errors.Is(err, ErrInvalid) {
					t.Errorf("%+v: %v", a, err)
				}
			}
			if len(actions.calls) != 0 {
				t.Fatalf("invalid alerts reached the client: %+v", actions.calls)
			}
		})
	}
}

func TestContainmentApprovalIsOptIn(t *testing.T) {
	e, actions, _ := containmentExecutor(t, IsolatePod, "pod", true)
	alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: "pod", ID: "tenant-a-sandbox/run-1"}}
	if _, err := e.Handle(alert, false); !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("approval-requiring containment without proof: %v", err)
	}
	alert.RequesterCredential, alert.ApprovalProof = "test-requester-credential", "test-approval-proof"
	if r, err := e.Handle(alert, false); err != nil || r.Status != Completed || len(actions.calls) != 1 {
		t.Fatalf("approved containment = %+v, %v, calls %d", r, err, len(actions.calls))
	}
}

func TestContainmentClientErrorIsUnknownAndNotRetried(t *testing.T) {
	e, actions, _ := containmentExecutor(t, CordonNode, "node", false)
	actions.err = errors.New("apiserver timeout")
	alert := Alert{ID: "alert-1", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: "node", ID: "node-1"}}
	if r, err := e.Handle(alert, false); !errors.Is(err, ErrOutcomeUnknown) || r.Status != Unknown {
		t.Fatalf("failed action = %+v, %v", r, err)
	}
	if _, err := e.Handle(alert, false); !errors.Is(err, ErrOutcomeUnknown) || len(actions.calls) != 1 {
		t.Fatalf("unknown outcome retried: %v, calls %d", err, len(actions.calls))
	}
}

func TestContainmentWithoutClientFailsClosed(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	_, err := New(Config{
		Playbook:         Playbook{ID: "contain", Trigger: "rule-c", Steps: []Action{{Name: CordonNode, Resource: Resource{Type: "node"}}}},
		AllowedTenantIDs: []string{"tenant-a"}, JournalPath: filepath.Join(dir, "j"),
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("containment playbook without an action client: %v", err)
	}
}

type deadlineActions struct{ left time.Duration }

func (d *deadlineActions) Contain(ctx context.Context, _ Action) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("action context unbounded")
	}
	d.left = time.Until(deadline)
	return nil
}

// One az process took up to 1.71 s in the live Entra drill (Handle,
// docs/evidence/time-to-contain.md), and a key Graph does not know as a
// password needs up to three. An az that takes 2.5 s must not be killed: Graph
// may already have deleted the secret, and the outcome would be Unknown.
func TestAzureActionBudgetFitsTheCLI(t *testing.T) {
	az := filepath.Join(t.TempDir(), "az")
	if err := os.WriteFile(az, []byte("#!/bin/sh\nsleep 2.5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	e, _, _ := containmentExecutor(t, DisableAzureServicePrincipalCredential, "azure_app_credential", false)
	e.config.Actions = AzureCLI{Az: az}
	alert := Alert{ID: "alert-slow-az", RuleID: "rule-c", TenantID: "tenant-a",
		Resource: Resource{Type: "azure_app_credential", ID: testApp + "/" + testKey}}
	if r, err := e.Handle(alert, false); err != nil || r.Status != Completed {
		t.Fatalf("2.5 s az = %+v, %v", r, err)
	}
}

// Every action context stays bounded: 30 s for the Azure CLI action, 2 s for
// the others.
func TestActionBudgetPerAction(t *testing.T) {
	for _, c := range []struct {
		action   ActionName
		typ, id  string
		min, max time.Duration
	}{
		{DisableAzureServicePrincipalCredential, "azure_app_credential", testApp + "/" + testKey, 29 * time.Second, 30 * time.Second},
		{CordonNode, "node", "node-1", time.Second, 2 * time.Second},
		{IsolatePod, "pod", "tenant-a-sandbox/run-1", time.Second, 2 * time.Second},
	} {
		e, _, _ := containmentExecutor(t, c.action, c.typ, false)
		d := &deadlineActions{}
		e.config.Actions = d
		alert := Alert{ID: "alert-budget", RuleID: "rule-c", TenantID: "tenant-a", Resource: Resource{Type: c.typ, ID: c.id}}
		if r, err := e.Handle(alert, false); err != nil || r.Status != Completed {
			t.Fatalf("%s = %+v, %v", c.action, r, err)
		}
		if d.left < c.min || d.left > c.max {
			t.Fatalf("%s action budget %v, want %v..%v", c.action, d.left, c.min, c.max)
		}
	}
}
