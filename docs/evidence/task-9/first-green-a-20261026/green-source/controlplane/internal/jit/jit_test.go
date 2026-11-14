package jit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/testutil"
)

// This explicit fixture does not represent authenticated production identity.
type callerFixture struct { user string }
func (c callerFixture) Authorize(_ context.Context, tenant, user, role, action string) error {
	if tenant == "tenant-a" && action == "expire" && user == "" && role == "" { return nil }
	if tenant != "tenant-a" || user != c.user || role != "operator" || (action != "request" && action != "approve") { return errors.New("fixture authorization denied") }
	return nil
}

func (c callerFixture) AuthorizeGrant(_ context.Context, tenant, requester, approver, role string) error {
	if tenant != "tenant-a" || requester != "alice" || approver != c.user || role != "operator" { return errors.New("fixture grant authorization denied") }
	return nil
}

type bindingFixture struct {
	active map[string]Target
	removed []string
	activations int
	reservations map[string]Receipt
}
func (b *bindingFixture) Reserve(_ context.Context, target Target) (Receipt, error) {
	if b.reservations == nil { b.reservations = make(map[string]Receipt) }
	if _, exists := b.reservations[target.RequestID]; exists { return Receipt{}, ErrBindingConflict }
	r := Receipt{UID: target.RequestID, ResourceVersion: "1"}
	b.reservations[target.RequestID] = r
	return r, nil
}
func (b *bindingFixture) Activate(_ context.Context, target Target, receipt Receipt) error {
	if receipt.UID != target.RequestID || receipt.ResourceVersion != "1" || b.reservations[target.RequestID] != receipt { return errors.New("fixture fence mismatch") }
	b.active[target.RequestID] = target
	b.activations++
	return nil
}
func (b *bindingFixture) Remove(_ context.Context, target Target, receipt Receipt) error {
	delete(b.active, target.RequestID)
	delete(b.reservations, target.RequestID)
	b.removed = append(b.removed, target.RequestID)
	return nil
}

func fixture(t *testing.T) (*pgxpool.Pool, *Service, *Service, *bindingFixture, *time.Time) {
	t.Helper()
	pool := testutil.Database(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	b := &bindingFixture{active: make(map[string]Target)}
	config := Config{Roles: map[string]Role{"operator": {Namespace: "tenant-a", Name: "limited-operator"}}}
	requester, err := New(pool, "tenant-a", config, callerFixture{user: "alice"}, b, func() time.Time { return now })
	if err != nil { t.Fatal(err) }
	approver, err := New(pool, "tenant-a", config, callerFixture{user: "bob"}, b, func() time.Time { return now })
	if err != nil { t.Fatal(err) }
	return pool, requester, approver, b, &now
}

func request(t *testing.T, s *Service) string {
	t.Helper()
	id, err := s.Request("alice", "operator", time.Hour, "investigate incident")
	if err != nil { t.Fatalf("durable Request prerequisite failed: %v", err) }
	return id
}

// Break caught: the applicant can approve their own grant, or generic failure
// is incorrectly presented as the required self-approval policy decision.
func TestSelfApprovalRejected(t *testing.T) {
	pool, alice, _, bindings, _ := fixture(t)
	id := request(t, alice)
	err := alice.Approve(id, "alice")
	if !errors.Is(err, ErrSelfApproval) { t.Errorf("self-approval policy: want ErrSelfApproval, got %v", err) }
	var state string
	if err := pool.QueryRow(context.Background(), `SELECT state FROM jit_requests WHERE id=$1 AND tenant_id='tenant-a'`, id).Scan(&state); err != nil { t.Fatal(err) }
	if state != "requested" || bindings.activations != 0 { t.Errorf("self-approval changed state/access: %s, %d", state, bindings.activations) }
}

// Break caught: expiry at equality leaves external access, or only an in-memory
// grant disappears while its external binding remains.
func TestGrantExpiresAndBindingRemoved(t *testing.T) {
	_, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	if err := bob.Approve(id, "bob"); err != nil { t.Logf("approval outcome: %v", err) }
	grant, exists := bindings.active[id]
	if !exists || bindings.activations != 1 { t.Error("approved request has no external grant") }
	wantExpiry := now.Add(time.Hour)
	if exists && !grant.ExpiresAt.Equal(wantExpiry) { t.Errorf("deadline: got %v want %v", grant.ExpiresAt, wantExpiry) }
	*now = wantExpiry.Add(-time.Nanosecond)
	if err := bob.Expire(); err != nil { t.Logf("pre-expiry outcome: %v", err) }
	if _, exists := bindings.active[id]; !exists { t.Error("grant missing before expiry") }
	*now = wantExpiry
	if err := bob.Expire(); err != nil { t.Logf("expiry outcome: %v", err) }
	if _, exists := bindings.active[id]; exists { t.Error("external binding survives expiry equality") }
	if len(bindings.removed) != 1 || bindings.removed[0] != id { t.Errorf("expiry did not remove owned binding: %v", bindings.removed) }
}

// Break caught: successful grant/removal lacks real Task1 transaction/chain
// entries; checking a fixture event slice would miss this integration failure.
func TestAuditRecordedForGrantAndExpiry(t *testing.T) {
	pool, alice, bob, _, now := fixture(t)
	id := request(t, alice)
	if err := bob.Approve(id, "bob"); err != nil { t.Logf("approval outcome: %v", err) }
	*now = now.Add(time.Hour)
	if err := bob.Expire(); err != nil { t.Logf("expiry outcome: %v", err) }
	rows, err := pool.Query(context.Background(), `SELECT canonical_event FROM audit_entries ORDER BY seq`)
	if err != nil { t.Fatal(err) }
	counts := make(map[string]int)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil { t.Fatal(err) }
		var event audit.Event
		if err := json.Unmarshal(raw, &event); err != nil { t.Fatal(err) }
		if event.Type != "jit.granted" && event.Type != "jit.expired" { continue }
		var payload struct { RequestID string `json:"request_id"`; Requester string `json:"requester"`; Approver string `json:"approver"` }
		if err := json.Unmarshal(event.Payload, &payload); err != nil { t.Fatal(err) }
		if event.TenantID != "tenant-a" || payload.RequestID != id || payload.Requester != "alice" || payload.Approver != "bob" { t.Errorf("wrong event identity: %s", raw) }
		counts[event.Type]++
	}
	rows.Close()
	if err := rows.Err(); err != nil { t.Fatal(err) }
	if counts["jit.granted"] != 1 || counts["jit.expired"] != 1 { t.Errorf("real audit chain lacks grant/expiry events: %v", counts) }
	var head uint64
	if err := pool.QueryRow(context.Background(), `SELECT last_seq FROM audit_head WHERE singleton`).Scan(&head); err != nil { t.Fatal(err) }
	if head == 0 { t.Fatal("real Request audit transaction missing") }
	if err := (&audit.Log{Pool: pool}).Verify(1, head); err != nil { t.Fatal(err) }
	t.Log("Task1 PostgreSQL audit Verify completed")
}

// Fault wrapper models ambiguous external outcomes, not real Kubernetes RBAC.
type faultBindings struct {
	base *bindingFixture
	reserve func(Target, Receipt) error
	activate func(Target) error
	removeError error
}
func (f *faultBindings) Reserve(ctx context.Context, target Target) (Receipt, error) {
	r, err := f.base.Reserve(ctx, target)
	if err == nil && f.reserve != nil { err = f.reserve(target, r) }
	return r, err
}
func (f *faultBindings) Activate(ctx context.Context, target Target, r Receipt) error {
	if err := f.base.Activate(ctx, target, r); err != nil { return err }
	if f.activate != nil { return f.activate(target) }
	return nil
}
func (f *faultBindings) Remove(ctx context.Context, target Target, r Receipt) error {
	if f.removeError != nil { return f.removeError }
	return f.base.Remove(ctx, target, r)
}

func stateOf(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(context.Background(), `SELECT state FROM jit_requests WHERE id=$1`, id).Scan(&state); err != nil { t.Fatal(err) }
	return state
}

func failAudit(t *testing.T, pool *pgxpool.Pool, event string) {
	t.Helper()
	// Fixed event values below, never user input. This fails the real Task1
	// AppendTx INSERT, exposing state/event rollback and external cleanup.
	if event != "jit.requested" && event != "jit.approval_intent" && event != "jit.granted" && event != "jit.expired" { t.Fatal("invalid test fault") }
	ddl := `CREATE FUNCTION jit_test_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF convert_from(NEW.canonical_event,'UTF8')::jsonb->>'type' = '`+event+`' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER jit_test_audit_fault BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION jit_test_reject_audit()`
	if _, err := pool.Exec(context.Background(), ddl); err != nil { t.Fatal(err) }
}
func clearAuditFault(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DROP TRIGGER jit_test_audit_fault ON audit_entries; DROP FUNCTION jit_test_reject_audit()`); err != nil { t.Fatal(err) }
}
func auditCount(t *testing.T, pool *pgxpool.Pool, event string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_entries WHERE convert_from(canonical_event,'UTF8')::jsonb->>'type'=$1`, event).Scan(&count); err != nil { t.Fatal(err) }
	var head uint64
	if err := pool.QueryRow(context.Background(), `SELECT last_seq FROM audit_head WHERE singleton`).Scan(&head); err != nil { t.Fatal(err) }
	if head > 0 { if err := (&audit.Log{Pool: pool}).Verify(1, head); err != nil { t.Fatal(err) } }
	return count
}

func TestRequestBoundariesAndTenantIsolation(t *testing.T) {
	pool, alice, bob, bindings, now := fixture(t)
	for _, d := range []time.Duration{0, -1, 2*time.Hour+1} {
		if _, err := alice.Request("alice", "operator", d, "reason"); !errors.Is(err, ErrInvalid) { t.Fatalf("duration %v: %v", d, err) }
	}
	if _, err := alice.Request("bob", "operator", time.Hour, "reason"); err == nil { t.Fatal("unauthenticated user accepted") }
	if _, err := alice.Request("alice", "admin", time.Hour, "reason"); !errors.Is(err, ErrInvalid) { t.Fatal("unconfigured role accepted") }
	if _, err := alice.Request("alice", "operator", time.Hour, " "); !errors.Is(err, ErrInvalid) { t.Fatal("blank reason accepted") }
	id, err := alice.Request("alice", "operator", 2*time.Hour, "maximum")
	if err != nil { t.Fatal(err) }
	if err = bob.Approve(id, "alice"); err == nil { t.Fatal("unbound approver string accepted") }
	other, err := New(pool, "tenant-b", bob.config, bob.caller, bindings, func() time.Time { return *now })
	if err != nil { t.Fatal(err) }
	if err = other.Approve(id, "bob"); !errors.Is(err, ErrNotFound) { t.Fatalf("cross-tenant lookup: %v", err) }
	if bindings.activations != 0 || stateOf(t, pool, id) != "requested" { t.Fatal("denial changed access") }
	if err = bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	if !bindings.active[id].ExpiresAt.Equal(now.Add(2*time.Hour)) { t.Fatal("maximum duration not preserved") }
}

func TestApprovalClockRetryAndExpiryFence(t *testing.T) {
	pool, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	*now = now.Add(30*time.Minute)
	if err := bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	expires := now.Add(time.Hour)
	*now = now.Add(10*time.Minute)
	if err := bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	if bindings.activations != 1 || !bindings.active[id].ExpiresAt.Equal(expires) { t.Fatal("retry extended or duplicated grant") }
	*now = expires
	if err := bob.Approve(id, "bob"); !errors.Is(err, ErrExpired) { t.Fatalf("deadline retry: %v", err) }
	if stateOf(t, pool, id) != "expired" || len(bindings.active) != 0 { t.Fatal("deadline retry left access") }
	if err := bob.Approve(id, "bob"); !errors.Is(err, ErrExpired) { t.Fatal("terminal tombstone regranted") }
	if auditCount(t, pool, "jit.granted") != 1 || auditCount(t, pool, "jit.expired") != 1 { t.Fatal("retry duplicated audit") }
}

func TestAuditFailuresRollbackAndRemoveAccess(t *testing.T) {
	for _, event := range []string{"jit.requested", "jit.approval_intent", "jit.granted"} {
		t.Run(event, func(t *testing.T) {
			pool, alice, bob, bindings, _ := fixture(t)
			if event == "jit.requested" {
				failAudit(t, pool, event)
				if _, err := alice.Request("alice", "operator", time.Hour, "reason"); err == nil { t.Fatal("request accepted audit failure") }
				var count int
				if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM jit_requests`).Scan(&count); err != nil || count != 0 { t.Fatalf("request rollback: %d %v", count, err) }
				return
			}
			id := request(t, alice)
			failAudit(t, pool, event)
			if err := bob.Approve(id, "bob"); err == nil { t.Fatal("approval accepted audit failure") }
			if len(bindings.active) != 0 || len(bindings.reservations) != 0 { t.Fatal("audit failure left external access/reservation") }
			want := "requested"
			if event == "jit.granted" { want = "expired"; if bindings.activations != 1 { t.Fatal("fault did not reach post-activation audit") } }
			if stateOf(t, pool, id) != want { t.Fatalf("state after %s: %s", event, stateOf(t, pool, id)) }
			if auditCount(t, pool, "jit.granted") != 0 { t.Fatal("failed audit committed grant event") }
		})
	}
}

func TestRestartRevokesAmbiguousOperations(t *testing.T) {
	for _, phase := range []string{"reserve", "activate"} {
		t.Run(phase, func(t *testing.T) {
			pool, alice, bob, bindings, now := fixture(t)
			id := request(t, alice)
			fault := &faultBindings{base: bindings, removeError: errors.New("external API unavailable")}
			if phase == "reserve" { fault.reserve = func(Target, Receipt) error { return errors.New("reservation reply lost") } } else { fault.activate = func(Target) error { return errors.New("activation reply lost") } }
			bob.bindings = fault
			if err := bob.Approve(id, "bob"); err == nil { t.Fatal("ambiguous outcome accepted") }
			if stateOf(t, pool, id) != "revoke_pending" { t.Fatal("missing durable recovery state") }
			fault.removeError = nil
			restarted, err := New(pool, "tenant-a", bob.config, bob.caller, fault, func() time.Time { return *now })
			if err != nil { t.Fatal(err) }
			if err = restarted.Expire(); err != nil { t.Fatal(err) }
			if len(bindings.active) != 0 || len(bindings.reservations) != 0 || stateOf(t, pool, id) != "expired" { t.Fatal("restart failed to revoke") }
			wantActivations := 0
			if phase == "activate" { wantActivations = 1 }
			if bindings.activations != wantActivations || auditCount(t, pool, "jit.granted") != 0 || auditCount(t, pool, "jit.expired") != 1 { t.Fatal("recovery resumed activation or lost audit") }
		})
	}
}

func TestExpiryAuditRetryAfterExternalDeletion(t *testing.T) {
	pool, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	if err := bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	failAudit(t, pool, "jit.expired")
	*now = now.Add(time.Hour)
	if err := bob.Expire(); err == nil { t.Fatal("expiry hid audit failure") }
	if len(bindings.active) != 0 || stateOf(t, pool, id) != "revoke_pending" { t.Fatal("expiry lost retryable state or retained access") }
	clearAuditFault(t, pool)
	if err := bob.Expire(); err != nil { t.Fatal(err) }
	if err := bob.Expire(); err != nil { t.Fatal(err) }
	if stateOf(t, pool, id) != "expired" || auditCount(t, pool, "jit.expired") != 1 { t.Fatal("expiry audit retry missing or duplicated") }
}

func TestDeadlineDuringReservationPreventsActivation(t *testing.T) {
	_, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	bob.bindings = &faultBindings{base: bindings, reserve: func(target Target, _ Receipt) error { *now = target.ExpiresAt; return nil }}
	if err := bob.Approve(id, "bob"); !errors.Is(err, ErrExpired) { t.Fatalf("expired reservation: %v", err) }
	if bindings.activations != 0 || len(bindings.reservations) != 0 { t.Fatal("late activation or unfenced reservation") }
}

func TestConcurrentReconciliationCannotActivateTwice(t *testing.T) {
	_, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	entered, unblock := make(chan struct{}), make(chan struct{})
	bob.bindings = &faultBindings{base: bindings, reserve: func(Target, Receipt) error { close(entered); <-unblock; return nil }}
	done := make(chan error, 1)
	go func() { done <- bob.Approve(id, "bob") }()
	select { case <-entered: case <-time.After(time.Second): close(unblock); t.Fatal("reservation not reached") }
	approveErr := bob.Approve(id, "bob")
	expireErr := bob.Expire()
	close(unblock)
	select { case err := <-done: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("approval did not finish") }
	if !errors.Is(approveErr, ErrBusy) || !errors.Is(expireErr, ErrBusy) || bindings.activations != 1 { t.Fatalf("request lock failed: %v %v", approveErr, expireErr) }
	*now = now.Add(time.Hour)
	if err := bob.Expire(); err != nil { t.Fatal(err) }
	if len(bindings.active) != 0 { t.Fatal("reconciliation after lock release left access") }
}

type deniedMaintenance struct { callerFixture }
func (c deniedMaintenance) Authorize(ctx context.Context, tenant, user, role, action string) error {
	if action == "expire" { return errors.New("maintenance denied") }
	return c.callerFixture.Authorize(ctx, tenant, user, role, action)
}
func TestMaintenanceRequiresTrustedAuthorization(t *testing.T) {
	pool, alice, bob, bindings, now := fixture(t)
	id := request(t, alice)
	if err := bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	*now = now.Add(time.Hour)
	bob.caller = deniedMaintenance{callerFixture{user: "bob"}}
	if err := bob.Expire(); err == nil { t.Fatal("untrusted maintenance accepted") }
	if len(bindings.active) != 1 || stateOf(t, pool, id) != "active" { t.Fatal("unauthorized maintenance changed access") }
}


type revokedRequester struct {
	callerFixture
	checks int
}
func (c *revokedRequester) AuthorizeGrant(ctx context.Context, tenant, requester, approver, role string) error {
	c.checks++
	if c.checks > 1 { return errors.New("requester membership revoked") }
	return c.callerFixture.AuthorizeGrant(ctx, tenant, requester, approver, role)
}
func TestRequesterMembershipRecheckedBeforeActivation(t *testing.T) {
	pool, alice, bob, bindings, _ := fixture(t)
	id := request(t, alice)
	bob.caller = &revokedRequester{callerFixture: callerFixture{user: "bob"}}
	if err := bob.Approve(id, "bob"); err == nil { t.Fatal("revoked requester was granted access") }
	if bindings.activations != 0 || len(bindings.reservations) != 0 || stateOf(t, pool, id) != "expired" { t.Fatal("authorization loss left access or an activatable reservation") }
}


type failingBatchBindings struct { *bindingFixture; removable string }
func (b failingBatchBindings) Remove(ctx context.Context, target Target, r Receipt) error {
	if target.RequestID != b.removable { return errors.New("this binding cannot yet be removed") }
	return b.bindingFixture.Remove(ctx, target, r)
}
func TestExpiryBatchFailureDoesNotStarveLaterGrants(t *testing.T) {
	pool, alice, bob, bindings, now := fixture(t)
	for range 65 {
		id := request(t, alice)
		if err := bob.Approve(id, "bob"); err != nil { t.Fatal(err) }
	}
	// Equal fake deadlines intentionally exercise durable ordering, not a
	// lucky change in the wall clock or in-memory scheduler cursor.
	var last string
	if err := pool.QueryRow(context.Background(), `SELECT id FROM jit_requests ORDER BY id DESC LIMIT 1`).Scan(&last); err != nil { t.Fatal(err) }
	bob.bindings = failingBatchBindings{bindingFixture: bindings, removable: last}
	*now = now.Add(time.Hour)
	if err := bob.Expire(); err == nil { t.Fatal("first failed batch hidden") }
	if _, exists := bindings.active[last]; !exists { t.Fatal("first batch exceeded 64 rows") }
	if err := bob.Expire(); err == nil { t.Fatal("remaining failures hidden") }
	if _, exists := bindings.active[last]; exists || stateOf(t, pool, last) != "expired" { t.Fatal("permanent failures starved later expired grant") }
}
