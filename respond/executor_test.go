package respond

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingTenantClient struct {
	mu      sync.Mutex
	tenants []string
	run     func(context.Context, string) error
}

func (c *recordingTenantClient) SuspendTenant(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.tenants = append(c.tenants, tenantID)
	c.mu.Unlock()
	if c.run != nil {
		return c.run(ctx, tenantID)
	}
	return nil
}

type recordingAuthority struct {
	mu     sync.Mutex
	calls  int
	now    time.Time
	mutate func(*Approval)
	run    func(context.Context, ApprovalRequest) (Approval, error)
}

func (a *recordingAuthority) Verify(ctx context.Context, req ApprovalRequest) (Approval, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	if a.run != nil {
		return a.run(ctx, req)
	}
	if err := ctx.Err(); err != nil {
		return Approval{}, err
	}
	if req.RequesterCredential != "test-requester-credential" || req.ApprovalProof != "test-approval-proof" {
		return Approval{}, errors.New("test authority denied")
	}
	approval := Approval{
		Requester: Principal{Issuer: "test-issuer", Subject: "operator", CanonicalID: "test-operator", Roles: []string{"respond:execute"}},
		Approver:  Principal{Issuer: "test-issuer", Subject: "approver", CanonicalID: "test-approver", Roles: []string{"respond:approve"}},
		Binding:   req.Binding,
		IssuedAt:  a.now.Add(-time.Second),
		ExpiresAt: a.now.Add(time.Minute),
	}
	if a.mutate != nil {
		a.mutate(&approval)
	}
	return approval, nil
}

func executorFixture(t *testing.T) (*Executor, Alert, *recordingTenantClient, *recordingAuthority, string) {
	t.Helper()
	dir := t.TempDir()
	// The future ledger requires a private, owned directory.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	client := &recordingTenantClient{}
	authority := &recordingAuthority{now: now}
	resource := Resource{Type: "tenant", ID: "tenant-a"}
	executor, err := New(Config{
		Playbook:         Playbook{ID: "suspend-tenant", Trigger: "rule-a", Steps: []Action{{Name: SuspendTenant, Resource: resource}}, RequiresApproval: true},
		AllowedTenantIDs: []string{"tenant-a"},
		JournalPath:      filepath.Join(dir, "attempts.journal"),
		Authority:        authority,
		Client:           client,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("fixture configuration failed: %v", err)
	}
	t.Cleanup(func() {
		if err := executor.Close(); err != nil {
			t.Errorf("close executor: %v", err)
		}
	})
	alert := Alert{ID: "alert-a", RuleID: "rule-a", TenantID: "tenant-a", Resource: resource, RequesterCredential: "test-requester-credential", ApprovalProof: "test-approval-proof"}
	return executor, alert, client, authority, dir
}

func TestPlaybookIdempotentPerAlert(t *testing.T) {
	executor, alert, client, _, _ := executorFixture(t)
	first, err := executor.Handle(alert, false)
	if err != nil {
		t.Fatalf("RED_REQUIRED authorized first execution must complete: %v", err)
	}
	if first.Status != Completed || first.NoOp {
		t.Fatalf("first result = %+v; want Completed mutation", first)
	}
	second, err := executor.Handle(alert, false)
	if err != nil {
		t.Fatalf("duplicate execution: %v", err)
	}
	if !second.NoOp || second.Status != Completed {
		t.Fatalf("duplicate result = %+v; want Completed no-op", second)
	}
	if len(client.tenants) != 1 || client.tenants[0] != alert.TenantID {
		t.Fatalf("client targets = %v; want exactly [%s]", client.tenants, alert.TenantID)
	}
}

func TestDestructiveRequiresApproval(t *testing.T) {
	executor, alert, client, _, _ := executorFixture(t)
	withoutProof := alert
	withoutProof.ApprovalProof = ""
	if _, err := executor.Handle(withoutProof, false); err == nil {
		t.Fatal("missing authenticated approval must fail")
	}
	if len(client.tenants) != 0 {
		t.Fatalf("unapproved mutation targets = %v; want none", client.tenants)
	}
	result, err := executor.Handle(alert, false)
	if err != nil {
		t.Fatalf("RED_REQUIRED distinct authenticated approval must execute: %v", err)
	}
	if result.Status != Completed || result.NoOp || len(client.tenants) != 1 || client.tenants[0] != alert.TenantID {
		t.Fatalf("approved result = %+v, targets = %v; want one Completed mutation", result, client.tenants)
	}
}

func TestDryRunMakesNoChanges(t *testing.T) {
	executor, alert, client, authority, dir := executorFixture(t)
	for i := 0; i < 2; i++ {
		result, err := executor.Handle(alert, true)
		if err != nil {
			t.Fatalf("RED_REQUIRED dry-run must return a preview: %v", err)
		}
		if result.Status != Preview || !result.ApprovalNeeded || result.Resource != alert.Resource {
			t.Fatalf("dry-run result = %+v; want concrete approval-needed Preview", result)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || len(client.tenants) != 0 || authority.calls != 0 {
		t.Fatalf("preview changed state: files=%d mutations=%d authority=%d", len(entries), len(client.tenants), authority.calls)
	}
	result, err := executor.Handle(alert, false)
	if err != nil {
		t.Fatalf("actual execution after preview: %v", err)
	}
	if result.Status != Completed || result.NoOp || len(client.tenants) != 1 {
		t.Fatalf("preview consumed real execution: result=%+v targets=%v", result, client.tenants)
	}
}

func (c *recordingTenantClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.tenants)
}

func requireNoFiles(t *testing.T, dir string) {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("unexpected files: %v, %v", files, err)
	}
}

func TestConcurrentDuplicateAndCloseRetainsLock(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	client.run = func(ctx context.Context, tenant string) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, err := e.Handle(alert, false); done <- err }()
	<-entered
	result, err := e.Handle(alert, false)
	if err != nil || result.Status != InProgress || !result.NoOp || client.count() != 1 {
		t.Fatalf("pending duplicate: %+v %v calls=%d", result, err, client.count())
	}
	if !errors.Is(e.Close(), ErrBusy) {
		t.Fatal("Close must refuse in-flight work")
	}
	other, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Handle(alert, false); !errors.Is(err, ErrStorage) {
		t.Fatalf("second owner acquired active lock: %v", err)
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err = reopened.Handle(alert, false)
	if err != nil || !result.NoOp || result.Status != Completed || client.count() != 1 {
		t.Fatalf("reopen duplicate: %+v %v calls=%d", result, err, client.count())
	}
}

func TestApprovalBindingAndIdentityFailuresDoNotReserve(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Approval)
	}{
		{"tenant", func(a *Approval) { a.Binding.TenantID = "other" }},
		{"alert", func(a *Approval) { a.Binding.AlertID = "other" }},
		{"rule", func(a *Approval) { a.Binding.RuleID = "other" }},
		{"playbook", func(a *Approval) { a.Binding.PlaybookID = "other" }},
		{"steps", func(a *Approval) { a.Binding.StepsHash = "other" }},
		{"action", func(a *Approval) { a.Binding.Action = CordonNode }},
		{"resource-type", func(a *Approval) { a.Binding.Resource.Type = "pod" }},
		{"resource-id", func(a *Approval) { a.Binding.Resource.ID = "other" }},
		{"same-subject", func(a *Approval) { a.Approver.Issuer = a.Requester.Issuer; a.Approver.Subject = a.Requester.Subject }},
		{"alias", func(a *Approval) { a.Approver.CanonicalID = a.Requester.CanonicalID }},
		{"empty-principal", func(a *Approval) { a.Approver.Subject = "" }},
		{"control-principal", func(a *Approval) { a.Approver.Subject = "x\n" }},
		{"requester-role", func(a *Approval) { a.Requester.Roles = []string{"respond:approve"} }},
		{"approver-role", func(a *Approval) { a.Approver.Roles = []string{"respond:execute"} }},
		{"future", func(a *Approval) { a.IssuedAt = a.ExpiresAt }},
		{"expired", func(a *Approval) { a.ExpiresAt = a.IssuedAt }},
		{"too-long", func(a *Approval) { a.ExpiresAt = a.IssuedAt.Add(6 * time.Minute) }},
		{"zero-time", func(a *Approval) { a.IssuedAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, alert, client, authority, dir := executorFixture(t)
			authority.mutate = tc.change
			if _, err := e.Handle(alert, false); !errors.Is(err, ErrApprovalDenied) {
				t.Fatalf("approval accepted: %v", err)
			}
			if client.count() != 0 || e.ledger != nil {
				t.Fatal("denied approval reserved or mutated")
			}
			requireNoFiles(t, dir)
			authority.mutate = nil
			if _, err := e.Handle(alert, false); err != nil || client.count() != 1 {
				t.Fatalf("denial consumed alert: %v", err)
			}
		})
	}
}

func TestMissingPortsAndAuthorityErrorsFailClosed(t *testing.T) {
	for _, kind := range []string{"nil-authority", "nil-client", "error", "panic", "cancel", "empty-proof", "large-proof", "large-requester"} {
		t.Run(kind, func(t *testing.T) {
			e, alert, client, authority, dir := executorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "nil-authority":
				e.config.Authority = nil
			case "nil-client":
				e.config.Client = nil
			case "error":
				authority.run = func(context.Context, ApprovalRequest) (Approval, error) {
					return Approval{}, errors.New("secret-approval")
				}
			case "panic":
				authority.run = func(context.Context, ApprovalRequest) (Approval, error) { panic("secret-approval") }
			case "cancel":
				authority.run = func(authCtx context.Context, _ ApprovalRequest) (Approval, error) {
					deadline, ok := authCtx.Deadline()
					if !ok || time.Until(deadline) > time.Second {
						t.Error("authority context unbounded")
					}
					cancel()
					return Approval{}, nil
				}
			case "empty-proof":
				alert.ApprovalProof = ""
			case "large-proof":
				alert.ApprovalProof = string(make([]byte, 8193))
			case "large-requester":
				alert.RequesterCredential = string(make([]byte, 8193))
			}
			if _, err := e.HandleContext(ctx, alert, false); !errors.Is(err, ErrApprovalDenied) {
				t.Fatalf("not denied: %v", err)
			}
			if client.count() != 0 || e.ledger != nil {
				t.Fatal("failed authority reserved/mutated")
			}
			requireNoFiles(t, dir)
		})
	}
}

func TestTenantResourceAndTriggerIsolation(t *testing.T) {
	for _, field := range []string{"tenant", "resource", "type", "rule", "alert"} {
		t.Run(field, func(t *testing.T) {
			e, alert, client, authority, dir := executorFixture(t)
			switch field {
			case "tenant":
				alert.TenantID = "tenant-b"
			case "resource":
				alert.Resource.ID = "tenant-b"
			case "type":
				alert.Resource.Type = "pod"
			case "rule":
				alert.RuleID = "rule-b"
			case "alert":
				alert.ID = "../escape"
			}
			if _, err := e.Handle(alert, false); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid alert accepted: %v", err)
			}
			if client.count() != 0 || authority.calls != 0 {
				t.Fatal("invalid target reached ports")
			}
			requireNoFiles(t, dir)
		})
	}
}

func TestConfigurationCopiedAndPreviewUnwired(t *testing.T) {
	old, alert, client, _, dir := executorFixture(t)
	cfg := old.config
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cfg.Playbook.Steps[0].Resource.ID = "changed"
	cfg.AllowedTenantIDs[0] = "changed"
	if _, err = e.Handle(alert, false); err != nil || client.count() != 1 {
		t.Fatalf("input configuration alias: %v", err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	cfg = e.config
	cfg.Authority = nil
	cfg.Client = nil
	cfg.JournalPath = filepath.Join(dir, "unused.journal")
	preview, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer preview.Close()
	if result, err := preview.Handle(alert, true); err != nil || result.Status != Preview || preview.ledger != nil {
		t.Fatalf("unwired preview: %+v %v", result, err)
	}
	if _, err := os.Stat(cfg.JournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created journal: %v", err)
	}
}

func TestClientErrorPanicAndCooperativeCancellationStayUnknown(t *testing.T) {
	for _, kind := range []string{"error", "panic", "cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			e, alert, client, _, _ := executorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline" {
				var end context.CancelFunc
				ctx, end = context.WithTimeout(ctx, time.Second)
				defer end()
			}
			client.run = func(actionCtx context.Context, tenant string) error {
				deadline, ok := actionCtx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second {
					t.Error("action context unbounded")
				}
				switch kind {
				case "panic":
					panic("secret-client")
				case "error":
					return errors.New("secret-client")
				case "cancel":
					cancel()
				}
				<-actionCtx.Done()
				return actionCtx.Err()
			}
			result, err := e.HandleContext(ctx, alert, false)
			if !errors.Is(err, ErrOutcomeUnknown) || result.Status != Unknown || client.count() != 1 {
				t.Fatalf("ambiguous attempt: %+v %v calls=%d", result, err, client.count())
			}
			result, err = e.Handle(alert, false)
			if !errors.Is(err, ErrOutcomeUnknown) || !result.NoOp || client.count() != 1 {
				t.Fatalf("unknown retried: %+v %v calls=%d", result, err, client.count())
			}
		})
	}
}

func TestCancelledBeforeReservationAndAfterIntent(t *testing.T) {
	e, alert, client, _, dir := executorFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.HandleContext(ctx, alert, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel: %v", err)
	}
	requireNoFiles(t, dir)
	l, err := openLedger(e.config.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	e.ledger = l
	ctx, cancel = context.WithCancel(context.Background())
	syncFile := l.sync
	first := true
	l.sync = func() error {
		err := syncFile()
		if first {
			first = false
			cancel()
		}
		return err
	}
	result, err := e.HandleContext(ctx, alert, false)
	if !errors.Is(err, context.Canceled) || result.Status != Cancelled || client.count() != 0 {
		t.Fatalf("post-intent cancel: %+v %v", result, err)
	}
	result, err = e.Handle(alert, false)
	if err != nil || !result.NoOp || result.Status != Cancelled || client.count() != 0 {
		t.Fatalf("cancelled retry: %+v %v", result, err)
	}
}

func TestApprovalExpiresAfterIntentDoesNotMutate(t *testing.T) {
	e, alert, client, authority, _ := executorFixture(t)
	now := authority.now
	e.config.Now = func() time.Time { return now }
	l, err := openLedger(e.config.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	e.ledger = l
	syncFile := l.sync
	l.sync = func() error { err := syncFile(); now = authority.now.Add(time.Minute); return err }
	result, err := e.Handle(alert, false)
	if !errors.Is(err, ErrApprovalDenied) || result.Status != Cancelled || client.count() != 0 {
		t.Fatalf("expired before action: %+v %v", result, err)
	}
}

func TestStrictPlaybookParserAndKnownActionSubset(t *testing.T) {
	raw, err := os.ReadFile("playbooks/suspend-tenant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePlaybook(raw); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		"", "id: suspend-tenant", "null", "[]", "{}",
		string(raw) + "{}", string(raw) + " trailing",
		strings.Replace(string(raw), "\"id\": \"suspend-tenant\"", "\"id\": \"suspend-tenant\", \"id\": \"other\"", 1),
		strings.Replace(string(raw), "\"id\": \"suspend-tenant\"", "\"ID\": \"suspend-tenant\"", 1),
		strings.Replace(string(raw), "\"id\": \"suspend-tenant\"", "\"id\": \"suspend-tenant\", \"ID\": \"other\"", 1),
		strings.Replace(string(raw), "\"requires_approval\": true", "\"requires_approval\": false", 1),
		strings.Replace(string(raw), "\"requires_approval\": true", "\"requires_approval\": null", 1),
		strings.Replace(string(raw), "\"requires_approval\": true", "\"requires_approval\": true, \"extra\": 1", 1),
		strings.Replace(string(raw), "\"trigger\": \"rule-a\"", "\"trigger\": null", 1),
		strings.Replace(string(raw), "\"trigger\": \"rule-a\"", "\"trigger\": 42", 1),
		strings.Replace(string(raw), "\"type\": \"tenant\"", "\"type\": \"pod\"", 1),
		strings.Replace(string(raw), "\"id\": \"tenant-a\"", "\"id\": \"tenant-a\", \"id\": \"tenant-b\"", 1),
		strings.Replace(string(raw), "\"name\": \"SuspendTenant\"", "\"name\": \"SuspendTenant\", \"extra\": true", 1),
		strings.Replace(string(raw), "\"id\": \"tenant-a\"", "\"id\": \"../escape\"", 1),
		strings.Replace(string(raw), "SuspendTenant", "DisableAWSAccessKey", 1),
		strings.Replace(string(raw), "SuspendTenant", "DisableGCPServiceAccountKey", 1),
		strings.Repeat(" ", 16*1024+1),
		string([]byte{0xff}),
	}
	for i, text := range invalid {
		if _, err := ParsePlaybook([]byte(text)); err == nil {
			t.Fatalf("invalid parser case %d accepted", i)
		}
	}
	// Containment actions exist now, but never on a fixed tenant resource.
	for _, action := range []ActionName{RevokeVaultLease, DisableAzureServicePrincipalCredential, IsolatePod, CordonNode} {
		if _, err := ParsePlaybook([]byte(strings.Replace(string(raw), "SuspendTenant", string(action), 1))); !errors.Is(err, ErrInvalid) {
			t.Fatalf("action %s: %v", action, err)
		}
	}
	p, _ := ParsePlaybook(raw)
	p.Steps = append(p.Steps, p.Steps[0])
	if err := validatePlaybook(p); !errors.Is(err, ErrInvalid) {
		t.Fatal("multiple steps accepted")
	}
}

func TestPoisonedJournalRetainsInFlightLock(t *testing.T) {
	e, alert, client, _, _ := executorFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	client.run = func(ctx context.Context, _ string) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { _, err := e.Handle(alert, false); done <- err }()
	<-entered
	e.mu.Lock()
	write := e.ledger.write
	e.ledger.write = func(raw []byte) (int, error) { n, _ := write(raw[:7]); return n, errors.New("partial-intent") }
	e.mu.Unlock()
	second := alert
	second.ID = "second-alert"
	if _, err := e.Handle(second, false); !errors.Is(err, ErrStorage) {
		t.Fatalf("expected poison: %v", err)
	}
	if !errors.Is(e.Close(), ErrBusy) {
		t.Fatal("poison released in-flight lock")
	}
	other, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Handle(alert, false); !errors.Is(err, ErrStorage) {
		t.Fatal("poisoned in-flight owner lost lock")
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err = <-done; !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("in-flight uncertain completion: %v", err)
	}
	if client.count() != 1 {
		t.Fatal("second alert mutated")
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
}
