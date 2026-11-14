// Package jit manages tenant-bound, approved operator access. Its caller port
// must authenticate and authorize identities; user strings are not credentials.
package jit

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"warden/controlplane/internal/audit"
)

var (
	ErrInvalid = errors.New("invalid JIT request")
	ErrSelfApproval = errors.New("JIT self-approval forbidden")
	ErrUnavailable = errors.New("WARDEN_JIT_NOT_IMPLEMENTED")
)

type Role struct {
	Namespace string
	Name string
}

type Config struct { Roles map[string]Role }

// Authorizer is a trusted integration port, never populated from request JSON.
// It must compare user to its authenticated principal and authorize this action.
type Authorizer interface {
	Authorize(context.Context, string, string, string, string) error
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

// Bindings must reserve without subjects, activate with UID/version fencing,
// and remove only the owned binding. A test fixture is not real RBAC evidence.
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

func New(pool *pgxpool.Pool, tenant string, config Config, caller Authorizer, bindings Bindings, now func() time.Time) (*Service, error) {
	if pool == nil || strings.TrimSpace(tenant) == "" || caller == nil || bindings == nil || now == nil || len(config.Roles) == 0 {
		return nil, ErrInvalid
	}
	roles := make(map[string]Role, len(config.Roles))
	for alias, role := range config.Roles {
		if strings.TrimSpace(alias) == "" || strings.TrimSpace(role.Namespace) == "" || strings.TrimSpace(role.Name) == "" {
			return nil, ErrInvalid
		}
		roles[alias] = role
	}
	return &Service{pool: pool, tenant: tenant, config: Config{Roles: roles}, caller: caller, bindings: bindings, now: now}, nil
}

// Request is real durable scaffolding so the first RED reaches business
// assertions. Approval and expiry below remain explicitly fail-closed.
func (s *Service) Request(user, role string, d time.Duration, reason string) (string, error) {
	if s == nil || strings.TrimSpace(user) == "" || len(user) > 256 || strings.TrimSpace(reason) == "" || len(reason) > 2048 || d <= 0 || d > 2*time.Hour {
		return "", ErrInvalid
	}
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

func (s *Service) Approve(id, approver string) error { return ErrUnavailable }
func (s *Service) Expire() error { return ErrUnavailable }
