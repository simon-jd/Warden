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
	if tenant != "tenant-a" || user != c.user || role != "operator" || (action != "request" && action != "approve") { return errors.New("fixture authorization denied") }
	return nil
}

type bindingFixture struct {
	active map[string]Target
	removed []string
	activations int
}
func (b *bindingFixture) Reserve(_ context.Context, target Target) (Receipt, error) { return Receipt{UID: target.RequestID, ResourceVersion: "1"}, nil }
func (b *bindingFixture) Activate(_ context.Context, target Target, receipt Receipt) error {
	if receipt.UID != target.RequestID || receipt.ResourceVersion != "1" { return errors.New("fixture fence mismatch") }
	b.active[target.RequestID] = target
	b.activations++
	return nil
}
func (b *bindingFixture) Remove(_ context.Context, target Target, receipt Receipt) error {
	delete(b.active, target.RequestID)
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
