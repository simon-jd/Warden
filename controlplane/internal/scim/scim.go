// Package scim provisions tenant users over SCIM 2.0 (RFC 7643/7644) and maps
// verified OIDC identities to them. A user who is deactivated or deleted here
// is refused on their next API request: TenantVerifier reads this table on
// every request and there is no session cache.
package scim

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/tenant"
)

var (
	ErrNotFound       = errors.New("scim user not found")
	ErrConflict       = errors.New("scim user already exists")
	ErrNotProvisioned = errors.New("identity not provisioned")
)

type User struct {
	ID          string
	UserName    string
	ExternalID  string
	DisplayName string
	Active      bool
	Version     int64
	Created     time.Time
	Updated     time.Time
}

type Store struct{ Pool *pgxpool.Pool }

const columns = `id,user_name,external_id,display_name,active,version,created_at,updated_at`

func scan(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.UserName, &u.ExternalID, &u.DisplayName, &u.Active, &u.Version, &u.Created, &u.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func uniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// mutate runs fn and the audit append in one transaction.
func (s *Store) mutate(ctx context.Context, tenantID, event string, fn func(pgx.Tx) (User, error)) (User, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	u, err := fn(tx)
	if uniqueViolation(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, err
	}
	// No userName or other profile data in the audit chain, only the decision.
	payload, err := json.Marshal(map[string]any{"user_id": u.ID, "active": u.Active})
	if err != nil {
		return User{}, err
	}
	if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: tenantID, Type: event, Payload: payload}); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

func (s *Store) Create(ctx context.Context, tenantID string, u User) (User, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return User{}, err
	}
	id := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	return s.mutate(ctx, tenantID, "scim.user.created", func(tx pgx.Tx) (User, error) {
		return scan(tx.QueryRow(ctx, `INSERT INTO scim_users(id,tenant_id,user_name,external_id,display_name,active)
VALUES($1,$2,$3,$4,$5,$6) RETURNING `+columns, id, tenantID, u.UserName, u.ExternalID, u.DisplayName, u.Active))
	})
}

func (s *Store) Get(ctx context.Context, tenantID, id string) (User, error) {
	return scan(s.Pool.QueryRow(ctx, `SELECT `+columns+` FROM scim_users WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

// List returns one page in creation order and the tenant-wide match count.
func (s *Store) List(ctx context.Context, tenantID string, f *filter, offset, limit int) ([]User, int, error) {
	where, args := `tenant_id=$1`, []any{tenantID}
	if f != nil {
		switch f.attr {
		case "userName":
			where += ` AND lower(user_name)=lower($2)`
		case "externalId":
			where += ` AND external_id=$2`
		}
		args = append(args, f.value)
	}
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM scim_users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	page := fmt.Sprintf(` ORDER BY created_at,id OFFSET $%d LIMIT $%d`, len(args)+1, len(args)+2)
	rows, err := s.Pool.Query(ctx, `SELECT `+columns+` FROM scim_users WHERE `+where+page, append(args, offset, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *Store) Update(ctx context.Context, tenantID, id string, c change) (User, error) {
	event := "scim.user.updated"
	if c.active != nil && !*c.active {
		event = "scim.user.deactivated"
	}
	return s.mutate(ctx, tenantID, event, func(tx pgx.Tx) (User, error) {
		return scan(tx.QueryRow(ctx, `UPDATE scim_users SET
 active=COALESCE($3,active), user_name=COALESCE($4,user_name), external_id=COALESCE($5,external_id),
 display_name=COALESCE($6,display_name), version=version+1, updated_at=clock_timestamp()
WHERE tenant_id=$1 AND id=$2 RETURNING `+columns, tenantID, id, c.active, c.userName, c.externalID, c.displayName))
	})
}

func (s *Store) Delete(ctx context.Context, tenantID, id string) error {
	_, err := s.mutate(ctx, tenantID, "scim.user.deleted", func(tx pgx.Tx) (User, error) {
		var u User
		err := tx.QueryRow(ctx, `DELETE FROM scim_users WHERE tenant_id=$1 AND id=$2 RETURNING id`, tenantID, id).Scan(&u.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return u, err
	})
	return err
}

// Resolve maps a verified object ID to the one tenant where it is an active
// user. Zero or several matches are refused rather than guessed.
func (s *Store) Resolve(ctx context.Context, objectID string) (string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tenant_id FROM scim_users WHERE external_id=$1 AND active LIMIT 2`, objectID)
	if err != nil {
		return "", err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", err
	}
	if len(tenants) != 1 {
		return "", ErrNotProvisioned
	}
	return tenants[0], nil
}

// Directory is the lookup TenantVerifier needs; *Store implements it.
type Directory interface {
	Resolve(ctx context.Context, objectID string) (tenantID string, err error)
}

var errUnauthorized = errors.New("unauthorized")

type tenantVerifier struct {
	ids tenant.IdentityVerifier
	dir Directory
}

// TenantVerifier turns a verified IdP identity into Warden tenant claims, using
// only the provisioned directory for tenant membership. With a missing
// dependency it returns nil, which makes the API deny every request.
func TenantVerifier(ids tenant.IdentityVerifier, dir Directory) tenant.Verifier {
	if ids == nil || dir == nil {
		return nil
	}
	return tenantVerifier{ids: ids, dir: dir}
}

func (v tenantVerifier) Verify(ctx context.Context, raw string) (tenant.Claims, error) {
	id, err := v.ids.VerifyIdentity(ctx, raw)
	if err != nil || id.ObjectID == "" {
		return tenant.Claims{}, errUnauthorized
	}
	tenantID, err := v.dir.Resolve(ctx, id.ObjectID)
	if err != nil || tenantID == "" {
		return tenant.Claims{}, errUnauthorized
	}
	return tenant.Claims{TenantID: tenantID}, nil
}
