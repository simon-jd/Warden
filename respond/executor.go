package respond

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sync"
	"time"
)

type Status string

const (
	Preview    Status = "Preview"
	Completed  Status = "Completed"
	InProgress Status = "InProgress"
	Unknown    Status = "Unknown"
	Cancelled  Status = "Cancelled"
)

type Result struct {
	Status         Status
	NoOp           bool
	ApprovalNeeded bool
	Resource       Resource
}

type Config struct {
	Playbook         Playbook
	AllowedTenantIDs []string
	JournalPath      string
	Authority        ApprovalAuthority
	Client           TenantClient // SuspendTenant
	Actions          ActionClient // every other action
	Now              func() time.Time
}

// Executor is local and Linux-only. The mutex never surrounds authority/client
// calls. A poisoned journal retains its lock until Close can safely release it.
type Executor struct {
	mu       sync.Mutex
	config   Config
	ledger   *ledger
	initial  ledgerInit
	closed   bool
	poisoned bool
	active   int
}

func New(config Config) (*Executor, error) {
	if err := validatePlaybook(config.Playbook); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.JournalPath) || filepath.Clean(config.JournalPath) != config.JournalPath || len(config.JournalPath) > 4096 {
		return nil, ErrInvalid
	}
	if len(config.AllowedTenantIDs) == 0 || len(config.AllowedTenantIDs) > 128 {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool)
	for _, id := range config.AllowedTenantIDs {
		if !identifier(id) || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
	}
	step := config.Playbook.Steps[0]
	if step.Name == SuspendTenant && !seen[step.Resource.ID] {
		return nil, ErrInvalid
	}
	if step.Name != SuspendTenant && config.Actions == nil {
		return nil, ErrInvalid
	}
	config.Playbook.Steps = append([]Action(nil), config.Playbook.Steps...)
	config.AllowedTenantIDs = append([]string(nil), config.AllowedTenantIDs...)
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Executor{config: config}, nil
}

func digest(v any) string {
	// Fixed structs/slices of scalar validated values cannot fail JSON marshaling.
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (e *Executor) binding(a Alert) (Binding, error) {
	p := e.config.Playbook
	step := p.Steps[0]
	if !identifier(a.ID) || !identifier(a.RuleID) || !identifier(a.TenantID) || a.RuleID != p.Trigger {
		return Binding{}, ErrInvalid
	}
	if step.Name == SuspendTenant {
		if a.Resource != step.Resource || a.Resource.ID != a.TenantID {
			return Binding{}, ErrInvalid
		}
	} else if a.Resource.Type != step.Resource.Type || !validTarget(a.Resource.Type, a.Resource.ID) {
		return Binding{}, ErrInvalid
	}
	allowed := false
	for _, tenant := range e.config.AllowedTenantIDs {
		allowed = allowed || tenant == a.TenantID
	}
	if !allowed {
		return Binding{}, ErrInvalid
	}
	return Binding{TenantID: a.TenantID, AlertID: a.ID, RuleID: a.RuleID,
		PlaybookID: p.ID, StepsHash: digest(p.Steps), Action: p.Steps[0].Name, Resource: a.Resource}, nil
}

func (e *Executor) Handle(alert Alert, dryRun bool) (Result, error) {
	return e.HandleContext(context.Background(), alert, dryRun)
}

// actionBudget bounds one call of an action's adapter. Vault and Kubernetes
// calls are single API requests: 2 s. DisableAzureServicePrincipalCredential
// runs the Azure CLI: one az process took up to 1.71 s in the live Entra drill
// (Handle, docs/evidence/time-to-contain.md), and a keyId Graph does not know
// as a password costs up to two more (app show, then delete --cert or
// federated-credential list). Killing az after Graph has already deleted the
// credential would leave the outcome Unknown, so it gets 30 s.
func actionBudget(name ActionName) time.Duration {
	if name == DisableAzureServicePrincipalCredential {
		return 30 * time.Second
	}
	return 2 * time.Second
}

func (e *Executor) HandleContext(parent context.Context, alert Alert, dryRun bool) (Result, error) {
	// The whole call: one second for the authority, the action's budget, and
	// two seconds for the journal.
	ctx, cancel := context.WithTimeout(parent, actionBudget(e.config.Playbook.Steps[0].Name)+3*time.Second)
	defer cancel()
	b, err := e.binding(alert)
	if err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{Status: Cancelled}, ctx.Err()
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return Result{}, ErrClosed
	}
	if dryRun {
		return Result{Status: Preview, ApprovalNeeded: e.config.Playbook.RequiresApproval, Resource: b.Resource}, nil
	}
	if (b.Action == SuspendTenant && e.config.Client == nil) || (b.Action != SuspendTenant && e.config.Actions == nil) {
		return Result{}, ErrApprovalDenied
	}
	// deadline bounds the action: the approval's expiry, or one minute for
	// containment that needs no second approver.
	deadline := e.config.Now().Add(time.Minute)
	if e.config.Playbook.RequiresApproval {
		if e.config.Authority == nil || len(alert.RequesterCredential) == 0 || len(alert.RequesterCredential) > 8192 || len(alert.ApprovalProof) == 0 || len(alert.ApprovalProof) > 8192 {
			return Result{}, ErrApprovalDenied
		}
		authCtx, authCancel := context.WithTimeout(ctx, time.Second)
		approval, authErr := callAuthority(authCtx, e.config.Authority, ApprovalRequest{RequesterCredential: alert.RequesterCredential, ApprovalProof: alert.ApprovalProof, Binding: b})
		authContextErr := authCtx.Err()
		authCancel()
		if authErr != nil || authContextErr != nil || !validApproval(approval, b, e.config.Now()) {
			return Result{}, ErrApprovalDenied
		}
		deadline = approval.ExpiresAt
	}
	key := digest(struct{ TenantID, AlertID string }{b.TenantID, b.AlertID})
	fingerprint := digest(b)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return Result{}, ErrClosed
	}
	if e.poisoned {
		e.mu.Unlock()
		return Result{}, ErrStorage
	}
	if ctx.Err() != nil || !deadline.After(e.config.Now()) {
		e.mu.Unlock()
		return Result{Status: Cancelled}, ErrApprovalDenied
	}
	if e.ledger == nil {
		e.ledger, err = openLedgerWithInit(e.config.JournalPath, e.initial)
		if err != nil {
			e.poisoned = true
			e.mu.Unlock()
			return Result{}, ErrStorage
		}
	}
	if prior, ok := e.ledger.entries[key]; ok {
		e.mu.Unlock()
		if prior.fingerprint != fingerprint {
			return Result{}, ErrConflict
		}
		result := Result{Status: prior.status, NoOp: true, Resource: b.Resource}
		if prior.status == Unknown {
			return result, ErrOutcomeUnknown
		}
		return result, nil
	}
	if err = e.ledger.intent(key, fingerprint); err != nil {
		if err != ErrCapacity {
			e.poisoned = true
		}
		e.mu.Unlock()
		return Result{}, err
	}
	e.active++
	e.mu.Unlock()
	status := Cancelled
	var callErr error
	if ctx.Err() != nil {
		callErr = ctx.Err()
	} else if !deadline.After(e.config.Now()) {
		callErr = ErrApprovalDenied
	} else {
		budget := actionBudget(b.Action)
		if remaining := deadline.Sub(e.config.Now()); remaining < budget {
			budget = remaining
		}
		actionCtx, actionCancel := context.WithTimeout(ctx, budget)
		if actionCtx.Err() != nil {
			callErr = actionCtx.Err()
		} else {
			callErr = e.callAction(actionCtx, b)
			if callErr == nil {
				callErr = actionCtx.Err()
			}
			if callErr == nil && !deadline.After(e.config.Now()) {
				callErr = ErrApprovalDenied
			}
			status = Completed
			if callErr != nil {
				status = Unknown
				callErr = ErrOutcomeUnknown
			}
		}
		actionCancel()
	}
	e.mu.Lock()
	e.active--
	if e.poisoned || e.ledger.complete(key, fingerprint, status) != nil {
		e.poisoned = true
		status = Unknown
		callErr = ErrOutcomeUnknown
		e.ledger.entries[key] = ledgerEntry{fingerprint: fingerprint, status: Unknown}
	}
	e.mu.Unlock()
	return Result{Status: status, Resource: b.Resource}, callErr
}

func principalValid(p Principal, role string) bool {
	for _, s := range []string{p.Issuer, p.Subject, p.CanonicalID} {
		if len(s) == 0 || len(s) > 256 {
			return false
		}
		for _, c := range s {
			if c < 33 || c > 126 {
				return false
			}
		}
	}
	if len(p.Roles) > 32 {
		return false
	}
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func validApproval(a Approval, expected Binding, now time.Time) bool {
	return a.Binding == expected && principalValid(a.Requester, "respond:execute") && principalValid(a.Approver, "respond:approve") &&
		a.Requester.CanonicalID != a.Approver.CanonicalID && (a.Requester.Issuer != a.Approver.Issuer || a.Requester.Subject != a.Approver.Subject) &&
		!a.IssuedAt.IsZero() && !a.ExpiresAt.IsZero() && !a.IssuedAt.After(now) && a.ExpiresAt.After(now) &&
		a.ExpiresAt.Sub(a.IssuedAt) > 0 && a.ExpiresAt.Sub(a.IssuedAt) <= 5*time.Minute
}

func callAuthority(ctx context.Context, authority ApprovalAuthority, request ApprovalRequest) (approval Approval, err error) {
	defer func() {
		if recover() != nil {
			err = ErrApprovalDenied
		}
	}()
	return authority.Verify(ctx, request)
}

func (e *Executor) callAction(ctx context.Context, b Binding) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrOutcomeUnknown
		}
	}()
	if b.Action == SuspendTenant {
		return e.config.Client.SuspendTenant(ctx, b.TenantID)
	}
	return e.config.Actions.Contain(ctx, Action{Name: b.Action, Resource: b.Resource})
}

// Close refuses in-flight work and keeps its FD/lock available for completion.
// No path unlocks a journal and then writes a completion to its old descriptor.
func (e *Executor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active != 0 {
		return ErrBusy
	}
	if e.closed {
		return nil
	}
	e.closed = true
	if e.ledger != nil && e.ledger.file.Close() != nil {
		return ErrStorage
	}
	return nil
}
