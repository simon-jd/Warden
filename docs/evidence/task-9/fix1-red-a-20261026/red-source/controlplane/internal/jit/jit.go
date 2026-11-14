// Package jit manages tenant-bound, approved operator access. Its caller port
// must authenticate and authorize identities; user strings are not credentials.
package jit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"warden/controlplane/internal/audit"
)

var (
	ErrInvalid = errors.New("invalid JIT request")
	ErrSelfApproval = errors.New("JIT self-approval forbidden")
	ErrUnavailable = errors.New("JIT operation unavailable")
	ErrNotFound = errors.New("JIT request not found")
	ErrExpired = errors.New("JIT approval is expired or revoked")
	ErrBusy = errors.New("JIT request is being reconciled")
)

type Role struct { Namespace, Name string }
type Config struct { Roles map[string]Role }

// Authorizer is trusted wiring, never populated from request JSON. For request
// and approve it must require an active tenant member whose canonical identity
// equals user, and authorize the configured role alias/action. Aliases for one
// person must not pass as distinct identities. For expire, user and role are
// empty: require a separately authorized tenant maintenance principal.
// AuthorizeGrant must recheck the requester's active tenant membership and the
// approver's permission to grant that configured alias to that requester.
// Every call must honor ctx. No production identity integration is implied.
type Authorizer interface {
	Authorize(context.Context, string, string, string, string) error
	AuthorizeGrant(context.Context, string, string, string, string) error
}

type Target struct {
	TenantID string
	RequestID string
	Name string
	Namespace string
	Role string
	User string
	ExpiresAt time.Time
}

type Receipt struct { UID, ResourceVersion string }

// Bindings is a security boundary. Reserve creates ONLY an empty binding.
// Activate conditionally updates the exact UID/version and MUST NOT create on
// missing objects. Remove clears subjects with a fresh version fence, deletes
// with UID/version preconditions and confirms absence. An empty Receipt means
// discover by the complete owned Target after an ambiguous reservation. All
// methods must honor ctx; errors may mean the external mutation happened.
type Bindings interface {
	Reserve(context.Context, Target) (Receipt, error)
	Activate(context.Context, Target, Receipt) error
	Remove(context.Context, Target, Receipt) error
}

type Service struct {
	pool *pgxpool.Pool
	tenant string
	config Config
	caller Authorizer
	bindings Bindings
	now func() time.Time
}

func textID(s string, max int) bool {
	return s != "" && s == strings.TrimSpace(s) && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func New(pool *pgxpool.Pool, tenant string, config Config, caller Authorizer, bindings Bindings, now func() time.Time) (*Service, error) {
	if pool == nil || !textID(tenant, 256) || caller == nil || bindings == nil || now == nil || len(config.Roles) == 0 { return nil, ErrInvalid }
	roles := make(map[string]Role, len(config.Roles))
	for alias, role := range config.Roles {
		if !textID(alias, 128) || !dnsName(role.Namespace, 63) || strings.Contains(role.Namespace, ".") || !dnsName(role.Name, 253) { return nil, ErrInvalid }
		roles[alias] = role
	}
	return &Service{pool: pool, tenant: tenant, config: Config{Roles: roles}, caller: caller, bindings: bindings, now: now}, nil
}

func (s *Service) Request(user, role string, d time.Duration, reason string) (string, error) {
	if s == nil || !textID(user, 256) || !textID(reason, 2048) || d <= 0 || d > 2*time.Hour { return "", ErrInvalid }
	if _, ok := s.config.Roles[role]; !ok { return "", ErrInvalid }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.caller.Authorize(ctx, s.tenant, user, role, "request"); err != nil { return "", err }
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil { return "", err }
	id := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	tx, err := s.pool.Begin(ctx)
	if err != nil { return "", err }
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO jit_requests(id,tenant_id,requester,role_alias,reason,duration_ns,created_at,binding_name,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'requested')`, id, s.tenant, user, role, reason, int64(d), s.now().UTC(), "jit-"+strings.ToLower(id))
	if err != nil { return "", err }
	payload, err := json.Marshal(map[string]any{"request_id": id, "requester": user, "role": role, "reason": reason, "duration_ns": int64(d)})
	if err != nil { return "", err }
	if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: s.tenant, Type: "jit.requested", Payload: payload}); err != nil { return "", err }
	if err = tx.Commit(ctx); err != nil { return "", err }
	return id, nil
}

type requestRow struct {
	id, requester, alias, reason, state, approver string
	duration int64
	approved, expires *time.Time
	target Target
	receipt Receipt
	granted bool
}

func (s *Service) load(ctx context.Context, conn *pgxpool.Conn, id string) (requestRow, error) {
	r := requestRow{id: id}
	err := conn.QueryRow(ctx, `SELECT requester,role_alias,reason,duration_ns,state,COALESCE(approver,''),approved_at,expires_at,binding_name,COALESCE(namespace,''),COALESCE(role_name,''),COALESCE(subject,''),COALESCE(binding_uid,''),COALESCE(binding_version,''),grant_confirmed FROM jit_requests WHERE tenant_id=$1 AND id=$2`, s.tenant, id).Scan(&r.requester, &r.alias, &r.reason, &r.duration, &r.state, &r.approver, &r.approved, &r.expires, &r.target.Name, &r.target.Namespace, &r.target.Role, &r.target.User, &r.receipt.UID, &r.receipt.ResourceVersion, &r.granted)
	if errors.Is(err, pgx.ErrNoRows) { return r, ErrNotFound }
	r.target.TenantID, r.target.RequestID = s.tenant, id
	if r.expires != nil { r.target.ExpiresAt = *r.expires }
	return r, err
}

// A dedicated session lock serializes this request without holding audit_head
// across external I/O. Failed unlock discards the session, never pools a lock.
func (s *Service) lock(ctx context.Context, id string) (*pgxpool.Conn, func(), error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil { return nil, nil, err }
	h := sha256.Sum256([]byte("warden.jit\x00"+s.tenant+"\x00"+id))
	key := int64(binary.BigEndian.Uint64(h[:8]))
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil || !locked {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = conn.Hijack().Close(cleanup)
			cancel()
		} else { conn.Release(); err = ErrBusy }
		return nil, nil, err
	}
	release := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Hijack().Close(cleanup)
			return
		}
		conn.Release()
	}
	return conn, release, nil
}

// save commits state and its audit event together; expected is also a DB fence.
func (s *Service) save(ctx context.Context, conn *pgxpool.Conn, r requestRow, expected, event, cause string) error {
	tx, err := conn.Begin(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE jit_requests SET state=$3,approver=$4,approved_at=$5,expires_at=$6,namespace=$7,role_name=$8,subject=$9,binding_uid=NULLIF($10,''),binding_version=NULLIF($11,''),grant_confirmed=$12,last_error=$13 WHERE tenant_id=$1 AND id=$2 AND state=$14`, s.tenant, r.id, r.state, r.approver, r.approved, r.expires, r.target.Namespace, r.target.Role, r.target.User, r.receipt.UID, r.receipt.ResourceVersion, r.granted, cause, expected)
	if err != nil { return err }
	if tag.RowsAffected() != 1 { return ErrBusy }
	if event != "" {
		payload, err := json.Marshal(map[string]any{"request_id": r.id, "requester": r.requester, "approver": r.approver, "role": r.alias, "reason": r.reason, "approved_at": r.approved, "expires_at": r.expires, "target": r.target, "grant_confirmed": r.granted, "outcome": cause})
		if err != nil { return err }
		if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: s.tenant, Type: event, Payload: payload}); err != nil { return err }
	}
	return tx.Commit(ctx)
}

// Approve starts the duration at the first committed approval, never at Request
// and never again on retry. PostgreSQL microsecond rounding is downward: very
// short windows can expire before activation, but cannot be lengthened.
func (s *Service) Approve(id, approver string) (err error) {
	if s == nil || !requestID(id) || !textID(approver, 256) { return ErrInvalid }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, release, err := s.lock(ctx, id)
	if err != nil { return err }
	defer release()
	r, err := s.load(ctx, conn, id)
	if err != nil { return err }
	if err = s.caller.Authorize(ctx, s.tenant, approver, r.alias, "approve"); err != nil { return err }
	if approver == r.requester { return ErrSelfApproval }
	if err = s.caller.AuthorizeGrant(ctx, s.tenant, r.requester, approver, r.alias); err != nil { return err }
	role, configured := s.config.Roles[r.alias]
	if !configured { return ErrInvalid }
	if r.state == "active" && r.approver == approver && role.Namespace == r.target.Namespace && role.Name == r.target.Role && s.now().Before(*r.expires) { return nil }
	if r.state != "requested" {
		if r.state != "expired" { return errors.Join(ErrExpired, s.revoke(ctx, conn, r, "approval_retry")) }
		return ErrExpired
	}
	approved := s.now().UTC().Truncate(time.Microsecond)
	expires := approved.Add(time.Duration(r.duration)).Truncate(time.Microsecond)
	r.approver, r.approved, r.expires = approver, &approved, &expires
	r.target.Namespace, r.target.Role, r.target.User, r.target.ExpiresAt = role.Namespace, role.Name, r.requester, expires
	r.state = "grant_pending"
	if err = s.save(ctx, conn, r, "requested", "jit.approval_intent", "approved"); err != nil { return err }
	// After durable intent, every error attempts removal, including ambiguous
	// remote success or audit commit. Restart never finishes this activation.
	defer func() {
		if err == nil { return }
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if latest, readErr := s.load(cleanup, conn, id); readErr == nil { r = latest }
		err = errors.Join(err, s.revoke(cleanup, conn, r, "grant_failed"))
	}()
	if !s.now().Before(expires) { return ErrExpired }
	r.receipt, err = s.bindings.Reserve(ctx, r.target)
	if err != nil { return err }
	if !textID(r.receipt.UID, 256) || !textID(r.receipt.ResourceVersion, 256) { return ErrUnavailable }
	if err = s.save(ctx, conn, r, "grant_pending", "", "reserved"); err != nil { return err }
	// Recheck the authenticated policy and session after reservation. The
	// external UID/version fence still protects against late I/O/session loss.
	if err = s.caller.Authorize(ctx, s.tenant, approver, r.alias, "approve"); err != nil { return err }
	if err = s.caller.AuthorizeGrant(ctx, s.tenant, r.requester, approver, r.alias); err != nil { return err }
	if !s.now().Before(expires) { return ErrExpired }
	if err = conn.Ping(ctx); err != nil { return err }
	if err = s.bindings.Activate(ctx, r.target, r.receipt); err != nil { return err }
	if !s.now().Before(expires) { return ErrExpired }
	r.state, r.granted = "active", true
	if err = s.save(ctx, conn, r, "grant_pending", "jit.granted", "granted"); err != nil { return err }
	return nil
}

func (s *Service) revoke(ctx context.Context, conn *pgxpool.Conn, r requestRow, cause string) error {
	if r.state == "expired" { return nil }
	if r.state == "requested" { return ErrInvalid }
	previous := r.state
	r.state = "revoke_pending"
	var intentErr error
	if previous != "revoke_pending" { intentErr = s.save(ctx, conn, r, previous, "jit.revocation_intent", cause) }
	// Access removal must still be attempted if the database/audit is failing.
	// The earlier durable grant_pending/active record remains discoverable.
	removeErr := s.bindings.Remove(ctx, r.target, r.receipt)
	if intentErr != nil || removeErr != nil { return errors.Join(intentErr, removeErr) }
	r.state = "expired"
	return s.save(ctx, conn, r, "revoke_pending", "jit.expired", cause)
}

// Expire is authorized tenant maintenance, bounded to 64 rows per call. Repeat
// on startup and periodically until drained; pending grants are always revoked.
// A stopped scheduler or unavailable external API cannot enforce wall-clock TTL.
func (s *Service) Expire() error {
	if s == nil { return ErrInvalid }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.caller.Authorize(ctx, s.tenant, "", "", "expire"); err != nil { return err }
	rows, err := s.pool.Query(ctx, `SELECT id FROM jit_requests WHERE tenant_id=$1 AND (state IN ('grant_pending','revoke_pending') OR (state='active' AND expires_at <= $2)) ORDER BY reconcile_order,expires_at,id LIMIT 64`, s.tenant, s.now().UTC())
	if err != nil { return err }
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil { rows.Close(); return err }
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil { return err }
	var failures []error
	for _, id := range ids {
		if ctx.Err() != nil { failures = append(failures, ctx.Err()); break }
		conn, release, err := s.lock(ctx, id)
		if err != nil { failures = append(failures, err); continue }
		r, err := s.load(ctx, conn, id)
		if err == nil && (r.state == "grant_pending" || r.state == "revoke_pending" || (r.state == "active" && !s.now().Before(*r.expires))) {
			// Rotate attempted rows durably so a failing batch cannot starve
			// other due grants, including after a maintenance restart.
			_, orderErr := conn.Exec(ctx, `UPDATE jit_requests SET reconcile_order=nextval('jit_reconcile_order') WHERE tenant_id=$1 AND id=$2`, s.tenant, id)
			err = errors.Join(orderErr, s.revoke(ctx, conn, r, "expiry_or_recovery"))
		}
		release()
		if err != nil { failures = append(failures, err) }
	}
	return errors.Join(failures...)
}

func requestID(id string) bool {
	if len(id) != 26 { return false }
	for _, c := range id { if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') { return false } }
	return true
}

func dnsName(s string, max int) bool {
	if len(s) == 0 || len(s) > max { return false }
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return false }
		for _, c := range label { if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') { return false } }
	}
	return true
}
