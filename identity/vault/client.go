// Package vault is the small part of the Vault HTTP API Warden uses for
// short-lived credentials: database secrets engine roles, credential issue and
// lease revocation. Standard library only.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// TTL policy for every dynamic credential role (plan Task 8).
const (
	MaxDefaultTTL = time.Hour
	MaxMaxTTL     = 4 * time.Hour
)

type Client struct {
	Addr  string // https://..., or http:// on loopback only
	Token string
	HTTP  *http.Client
}

type Creds struct {
	Username, Password, LeaseID string
	TTL                         time.Duration
	Renewable                   bool
}

// Role is a database secrets engine role. Statements use Vault's templating
// ({{name}}, {{password}}, {{expiration}}).
type Role struct {
	DBName               string
	CreationStatements   []string
	RevocationStatements []string
	DefaultTTL, MaxTTL   time.Duration
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (r Role) check() error {
	if r.DefaultTTL <= 0 || r.MaxTTL <= 0 || r.DefaultTTL > r.MaxTTL || r.DefaultTTL > MaxDefaultTTL || r.MaxTTL > MaxMaxTTL {
		return fmt.Errorf("role TTL out of policy: default %v (max %v), max %v (max %v)", r.DefaultTTL, MaxDefaultTTL, r.MaxTTL, MaxMaxTTL)
	}
	return nil
}

func (c *Client) validate() error {
	u, err := url.Parse(c.Addr)
	if err != nil || c.Token == "" {
		return errors.New("vault address and token required")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"):
		return nil
	}
	return errors.New("vault address must be https, or http on loopback")
}

// Do sends one API request; out may be nil.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	if err := c.validate(); err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Addr+"/v1/"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vault %s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func secs(d time.Duration) string { return fmt.Sprintf("%ds", int(d/time.Second)) }

// PutRole writes a role after enforcing the TTL policy.
func (c *Client) PutRole(ctx context.Context, mount, name string, r Role) error {
	if !namePattern.MatchString(mount) || !namePattern.MatchString(name) || !namePattern.MatchString(r.DBName) {
		return errors.New("invalid mount, role or database name")
	}
	if err := r.check(); err != nil {
		return err
	}
	body := map[string]any{"db_name": r.DBName, "creation_statements": r.CreationStatements,
		"default_ttl": secs(r.DefaultTTL), "max_ttl": secs(r.MaxTTL)}
	if len(r.RevocationStatements) > 0 {
		body["revocation_statements"] = r.RevocationStatements
	}
	return c.Do(ctx, http.MethodPost, mount+"/roles/"+name, body, nil)
}

// ReadRoleTTL returns the TTLs Vault actually stored for a role.
func (c *Client) ReadRoleTTL(ctx context.Context, mount, name string) (time.Duration, time.Duration, error) {
	if !namePattern.MatchString(mount) || !namePattern.MatchString(name) {
		return 0, 0, errors.New("invalid mount or role name")
	}
	var out struct {
		Data struct {
			DefaultTTL int64 `json:"default_ttl"`
			MaxTTL     int64 `json:"max_ttl"`
		} `json:"data"`
	}
	if err := c.Do(ctx, http.MethodGet, mount+"/roles/"+name, nil, &out); err != nil {
		return 0, 0, err
	}
	return time.Duration(out.Data.DefaultTTL) * time.Second, time.Duration(out.Data.MaxTTL) * time.Second, nil
}

// DBCreds issues a fresh credential pair under a lease.
func (c *Client) DBCreds(ctx context.Context, mount, role string) (Creds, error) {
	if !namePattern.MatchString(mount) || !namePattern.MatchString(role) {
		return Creds{}, errors.New("invalid mount or role name")
	}
	var out struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		Data          struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := c.Do(ctx, http.MethodGet, mount+"/creds/"+role, nil, &out); err != nil {
		return Creds{}, err
	}
	if out.LeaseID == "" || out.Data.Username == "" || out.Data.Password == "" || out.LeaseDuration <= 0 {
		return Creds{}, errors.New("vault returned an incomplete credential")
	}
	return Creds{Username: out.Data.Username, Password: out.Data.Password, LeaseID: out.LeaseID,
		TTL: time.Duration(out.LeaseDuration) * time.Second, Renewable: out.Renewable}, nil
}

// Revoke ends a lease now; Vault runs the role's revocation statements.
func (c *Client) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return errors.New("lease ID required")
	}
	return c.Do(ctx, http.MethodPut, "sys/leases/revoke", map[string]string{"lease_id": leaseID}, nil)
}
