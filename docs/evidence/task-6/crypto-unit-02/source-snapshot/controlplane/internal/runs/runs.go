// Package runs owns normalized launch specifications and durable queued runs.
package runs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/canonical"
	"warden/runtimes"
)

var ErrConflict = errors.New("idempotency key already used with another payload")
var ErrNotFound = errors.New("run not found")

type Store struct {
	Pool     *pgxpool.Pool
	Policies PolicyProvider
}
type Limits struct {
	CPU       float64 `json:"cpu"`
	MemoryMiB int     `json:"memory_mib"`
	Pids      int     `json:"pids"`
	TimeoutS  int     `json:"timeout_s"`
}
type Spec struct {
	ImageDigest     string   `json:"image_digest"`
	Cmd             []string `json:"cmd"`
	Limits          Limits   `json:"limits"`
	Runtime         string   `json:"runtime"`
	Network         string   `json:"network"`
	AllowDomains    []string `json:"allow_domains"`
	RootfsReadonly  bool     `json:"rootfs_readonly"`
	UID             int      `json:"uid"`
	NoNewPrivileges bool     `json:"no_new_privileges"`
}
type Run struct {
	Logs           Logs            `json:"logs"`
	Result         *runtimes.Exit  `json:"result"`
	ErrorCode      string          `json:"error_code"`
	CleanupPending bool            `json:"cleanup_pending"`
	UpdatedAt      time.Time       `json:"updated_at"`
	RunID          string          `json:"run_id"`
	State          string          `json:"state"`
	Spec           json.RawMessage `json:"spec"`
	CreatedAt      time.Time       `json:"created_at"`
}
type request struct {
	ImageDigest string   `json:"image_digest"`
	Cmd         []string `json:"cmd"`
	Limits      *struct {
		CPU       *float64 `json:"cpu"`
		MemoryMiB *int     `json:"memory_mib"`
		Pids      *int     `json:"pids"`
		TimeoutS  *int     `json:"timeout_s"`
	} `json:"limits"`
	Runtime      string   `json:"runtime"`
	Network      string   `json:"network"`
	AllowDomains []string `json:"allow_domains"`
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Normalize returns owned canonical bytes; omitted fields receive secure defaults.
func Normalize(raw []byte) ([]byte, error) {
	normalized, err := canonical.JSON(raw)
	if err != nil {
		return nil, err
	}
	if err = validateRequestKeys(normalized); err != nil {
		return nil, err
	}
	var r request
	d := json.NewDecoder(bytes.NewReader(normalized))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(r.ImageDigest) || len(r.Cmd) == 0 {
		return nil, errors.New("digest and nonempty cmd required")
	}
	for _, arg := range r.Cmd {
		if strings.ContainsRune(arg, 0) {
			return nil, errors.New("NUL in command")
		}
	}
	if r.Cmd[0] == "" {
		return nil, errors.New("empty executable")
	}
	spec := Spec{ImageDigest: r.ImageDigest, Cmd: r.Cmd, Limits: Limits{CPU: 1, MemoryMiB: 512, Pids: 128, TimeoutS: 300}, Runtime: r.Runtime, Network: r.Network, AllowDomains: []string{}, RootfsReadonly: true, UID: 65534, NoNewPrivileges: true}
	if spec.Runtime == "" {
		spec.Runtime = "runc"
	}
	if spec.Runtime != "runc" && spec.Runtime != "gvisor" && spec.Runtime != "firecracker" {
		return nil, errors.New("invalid runtime")
	}
	if spec.Network == "" {
		spec.Network = "none"
	}
	if spec.Network != "none" && spec.Network != "allowlist" {
		return nil, errors.New("invalid network")
	}
	if r.Limits != nil {
		if r.Limits.CPU != nil {
			spec.Limits.CPU = *r.Limits.CPU
		}
		if r.Limits.MemoryMiB != nil {
			spec.Limits.MemoryMiB = *r.Limits.MemoryMiB
		}
		if r.Limits.Pids != nil {
			spec.Limits.Pids = *r.Limits.Pids
		}
		if r.Limits.TimeoutS != nil {
			spec.Limits.TimeoutS = *r.Limits.TimeoutS
		}
	}
	if math.IsInf(spec.Limits.CPU, 0) || math.IsNaN(spec.Limits.CPU) || spec.Limits.CPU <= 0 || spec.Limits.MemoryMiB <= 0 || spec.Limits.Pids <= 0 || spec.Limits.TimeoutS <= 0 {
		return nil, errors.New("limits must be positive")
	}
	if (spec.Network == "allowlist") != (len(r.AllowDomains) > 0) {
		return nil, errors.New("allowlist network requires domains; none forbids domains")
	}
	for _, domain := range r.AllowDomains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if len(domain) > 253 || net.ParseIP(domain) != nil || !domainPattern.MatchString(domain) {
			return nil, errors.New("invalid allowlist domain")
		}
		spec.AllowDomains = append(spec.AllowDomains, domain)
	}
	sort.Strings(spec.AllowDomains)
	spec.AllowDomains = compact(spec.AllowDomains)
	encoded, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	return canonical.JSON(encoded)
}

// encoding/json accepts case-insensitive struct field aliases and null strings.
// Check the wire schema explicitly before decoding into normalized typed values.
func validateRequestKeys(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for key, value := range fields {
		switch key {
		case "image_digest", "runtime", "network", "allow_domains":
		case "cmd":
			var args []json.RawMessage
			if err := json.Unmarshal(value, &args); err != nil {
				return err
			}
			for _, arg := range args {
				if len(arg) == 0 || arg[0] != '"' {
					return errors.New("command arguments must be strings")
				}
			}
		case "limits":
			var limits map[string]json.RawMessage
			if err := json.Unmarshal(value, &limits); err != nil {
				return err
			}
			for name := range limits {
				switch name {
				case "cpu", "memory_mib", "pids", "timeout_s":
				default:
					return errors.New("unknown limit field")
				}
			}
		default:
			return errors.New("unknown run field")
		}
	}
	return nil
}

func compact(s []string) []string {
	if len(s) < 2 {
		return s
	}
	n := 1
	for _, v := range s[1:] {
		if v != s[n-1] {
			s[n] = v
			n++
		}
	}
	return s[:n]
}

// Create commits the queued run and its audit event in a single transaction.
// The unique constraint waits for concurrent same-key commits before lookup.
func (s *Store) Create(ctx context.Context, tenant, key string, spec []byte) (string, error) {
	snapshot := bytes.Clone(spec)
	var launch Spec
	if err := json.Unmarshal(snapshot, &launch); err != nil {
		return "", ErrForbidden
	}
	if err := s.Authorize(ctx, tenant, launch); err != nil {
		return "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `INSERT INTO runs(run_id,tenant_id,idempotency_key,canonical_spec) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,idempotency_key) DO NOTHING`, id, tenant, key, snapshot)
	if err != nil {
		return "", err
	}
	if result.RowsAffected() == 0 {
		var existing []byte
		if err = tx.QueryRow(ctx, `SELECT run_id,canonical_spec FROM runs WHERE tenant_id=$1 AND idempotency_key=$2`, tenant, key).Scan(&id, &existing); err != nil {
			return "", err
		}
		if !bytes.Equal(existing, snapshot) {
			return "", ErrConflict
		}
	} else {
		if _, _, err = audit.AppendTx(ctx, tx, audit.Event{TenantID: tenant, Type: "run.created", RunID: id, Payload: json.RawMessage(snapshot)}); err != nil {
			return "", fmt.Errorf("append run audit: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}
func (s *Store) Get(ctx context.Context, tenant, id string) (Run, error) {
	var run Run
	var raw []byte
	err := s.Pool.QueryRow(ctx, `SELECT run_id,state,canonical_spec,created_at,result,error_code,logs,cleanup_pending,updated_at FROM runs WHERE tenant_id=$1 AND run_id=$2`, tenant, id).Scan(&run.RunID, &run.State, &raw, &run.CreatedAt, &run.Result, &run.ErrorCode, &run.Logs, &run.CleanupPending, &run.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	run.Spec = json.RawMessage(raw)
	return run, err
}
