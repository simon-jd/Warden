// Package tests holds Task 8's live Vault tests, opt-in with WARDEN_LIVE_VAULT=1
// (`make test-vault`). They start a throwaway Postgres 18 and a Vault server
// with integrated (raft) storage on a private Docker network, initialise and
// unseal it, configure the database secrets engine and remove everything at
// the end. Vault listens without TLS on a 127.0.0.1-published port only.
package tests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"warden/identity/vault"
)

var (
	vaultImage = "hashicorp/vault:2.2.1"
	pgImage    = "postgres:18-alpine"
)

type vlab struct {
	prefix, network, dir string
	pgPassword, pgPort   string
	v                    *vault.Client
	mu                   sync.Mutex
	evidence             map[string]any
}

var (
	once   sync.Once
	lab    *vlab
	labErr error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if lab != nil {
		lab.writeEvidence()
		lab.close()
	}
	os.Exit(code)
}

func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %v: %s", strings.Join(args[:min(3, len(args))], " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (l *vlab) record(k string, v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evidence[k] = v
}

func hostPort(name, port string) (string, error) {
	out, err := docker("port", name, port)
	if err != nil {
		return "", err
	}
	line := strings.Split(out, "\n")[0]
	return line[strings.LastIndex(line, ":")+1:], nil
}

func (l *vlab) superuser(ctx context.Context) (*pgx.Conn, error) {
	return pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%s/warden?sslmode=disable", l.pgPassword, l.pgPort))
}

func (l *vlab) login(ctx context.Context, user, password string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/warden?sslmode=disable", user, password, l.pgPort))
	if err != nil {
		return nil, err
	}
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM app_data").Scan(&n); err != nil {
		conn.Close(context.Background())
		return nil, err
	}
	return conn, nil
}

func (l *vlab) roleExists(ctx context.Context, user string) (bool, error) {
	conn, err := l.superuser(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close(ctx)
	var n int
	err = conn.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname = $1", user).Scan(&n)
	return n > 0, err
}

const vaultHCL = `storage "raft" {
  path    = "/vault/file"
  node_id = "warden-1"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
api_addr      = "http://127.0.0.1:8200"
cluster_addr  = "http://127.0.0.1:8201"
disable_mlock = true
ui            = false
`

func start() (*vlab, error) {
	l := &vlab{prefix: "warden-vault-" + randHex(4), pgPassword: randHex(16), evidence: map[string]any{}}
	l.network = l.prefix + "-net"
	var err error
	if l.dir, err = os.MkdirTemp("", "warden-vault-"); err != nil {
		return nil, err
	}
	_ = os.Chmod(l.dir, 0o755)
	if err := os.WriteFile(filepath.Join(l.dir, "warden.hcl"), []byte(vaultHCL), 0o644); err != nil {
		return l, err
	}
	if _, err := docker("network", "create", "--label", "warden.test=task8", l.network); err != nil {
		return l, err
	}
	if _, err := docker("run", "-d", "--name", l.prefix+"-pg", "--label", "warden.test=task8", "--network", l.network,
		"--network-alias", "pg", "--memory", "512m", "--pids-limit", "128", "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD="+l.pgPassword, "-e", "POSTGRES_DB=warden", pgImage); err != nil {
		return l, err
	}
	if _, err := docker("run", "-d", "--name", l.prefix+"-vault", "--label", "warden.test=task8", "--network", l.network,
		"--memory", "256m", "--pids-limit", "256", "-p", "127.0.0.1::8200", "-e", "SKIP_SETCAP=1",
		"-v", l.dir+":/vault/config:ro", vaultImage, "server"); err != nil {
		return l, err
	}
	if l.pgPort, err = hostPort(l.prefix+"-pg", "5432/tcp"); err != nil {
		return l, err
	}
	vport, err := hostPort(l.prefix+"-vault", "8200/tcp")
	if err != nil {
		return l, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Postgres: an app table and a dedicated Vault admin role (not the superuser).
	var admin *pgx.Conn
	for admin == nil {
		if admin, err = l.superuser(ctx); err != nil {
			if ctx.Err() != nil {
				return l, fmt.Errorf("postgres not ready: %v", err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	vaultAdminPW := randHex(16)
	for _, q := range []string{
		"CREATE TABLE app_data (id int)", "INSERT INTO app_data VALUES (1)",
		"CREATE ROLE vault_admin WITH LOGIN CREATEROLE PASSWORD '" + vaultAdminPW + "'",
		"GRANT SELECT ON app_data TO vault_admin WITH GRANT OPTION",
		"GRANT pg_signal_backend TO vault_admin",
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			return l, fmt.Errorf("%s: %v", q, err)
		}
	}
	admin.Close(ctx)
	// Vault: init with one key share (lab only), unseal, wait for the raft leader.
	l.v = &vault.Client{Addr: "http://127.0.0.1:" + vport, Token: "uninitialised"}
	var initOut struct {
		Keys      []string `json:"keys_base64"`
		RootToken string   `json:"root_token"`
	}
	for {
		if err = l.v.Do(ctx, "PUT", "sys/init", map[string]int{"secret_shares": 1, "secret_threshold": 1}, &initOut); err == nil {
			break
		}
		if ctx.Err() != nil {
			logs, _ := docker("logs", "--tail", "30", l.prefix+"-vault")
			return l, fmt.Errorf("vault init: %v\n%s", err, logs)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := l.v.Do(ctx, "PUT", "sys/unseal", map[string]string{"key": initOut.Keys[0]}, nil); err != nil {
		return l, err
	}
	l.v.Token = initOut.RootToken
	for {
		var leader struct {
			IsSelf bool `json:"is_self"`
		}
		if err = l.v.Do(ctx, "GET", "sys/leader", nil, &leader); err == nil && leader.IsSelf {
			break
		}
		if ctx.Err() != nil {
			return l, fmt.Errorf("raft leader: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	var health map[string]any
	_ = l.v.Do(ctx, "GET", "sys/health", nil, &health)
	l.record("vault_health", health)
	var storage map[string]any
	_ = l.v.Do(ctx, "GET", "sys/storage/raft/configuration", nil, &storage)
	l.record("raft_configuration", storage["data"])
	// Database secrets engine; the mount itself caps every lease at 4h.
	steps := []struct {
		path string
		body any
	}{
		{"sys/mounts/database", map[string]any{"type": "database", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "4h"}}},
		{"database/config/warden-pg", map[string]any{"plugin_name": "postgresql-database-plugin",
			"connection_url": "postgresql://{{username}}:{{password}}@pg:5432/warden?sslmode=disable",
			"username":       "vault_admin", "password": vaultAdminPW, "allowed_roles": []string{"warden-*"}, "verify_connection": true}},
		{"database/rotate-root/warden-pg", nil},
	}
	for _, s := range steps {
		if err := l.v.Do(ctx, "POST", s.path, s.body, nil); err != nil {
			return l, err
		}
	}
	if _, err := l.login(ctx, "vault_admin", vaultAdminPW); err == nil {
		return l, fmt.Errorf("vault_admin's original password still works after rotate-root")
	}
	l.record("rotate_root", "vault_admin's bootstrap password rejected after rotate-root; only Vault holds the new one")
	create := []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
		`GRANT SELECT ON app_data TO "{{name}}";`}
	revoke := []string{`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';`,
		`REVOKE ALL ON app_data FROM "{{name}}";`, `DROP ROLE IF EXISTS "{{name}}";`}
	for name, ttl := range map[string][2]time.Duration{"warden-test-1m": {time.Minute, time.Hour}, "warden-app": {time.Hour, 4 * time.Hour}} {
		if err := l.v.PutRole(ctx, "database", name, vault.Role{DBName: "warden-pg", CreationStatements: create,
			RevocationStatements: revoke, DefaultTTL: ttl[0], MaxTTL: ttl[1]}); err != nil {
			return l, err
		}
	}
	version, _ := docker("image", "inspect", "--format", "{{json .RepoDigests}}", vaultImage)
	l.record("vault_image", vaultImage+" "+version)
	l.record("postgres_image", pgImage)
	return l, nil
}

func (l *vlab) close() {
	_, _ = docker("rm", "-f", "-v", l.prefix+"-vault", l.prefix+"-pg")
	_, _ = docker("network", "rm", l.network)
	if l.dir != "" {
		_ = os.RemoveAll(l.dir)
	}
}

func (l *vlab) writeEvidence() {
	out := os.Getenv("VAULT_OUT")
	if out == "" {
		return
	}
	load, _ := os.ReadFile("/proc/loadavg")
	l.record("host", map[string]any{"nproc": runtime.NumCPU(), "loadavg": strings.TrimSpace(string(load))})
	b, _ := json.MarshalIndent(l.evidence, "", "  ")
	_ = os.WriteFile(out, append(b, '\n'), 0o644)
}

func live(t *testing.T) *vlab {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_VAULT") != "1" {
		t.Skip("live Vault: run `make test-vault`")
	}
	once.Do(func() { lab, labErr = start() })
	if labErr != nil {
		t.Fatal(labErr)
	}
	return lab
}

func TestRoleTTLWithinPolicy(t *testing.T) {
	l := live(t)
	ctx := context.Background()
	for _, role := range []string{"warden-test-1m", "warden-app"} {
		def, max, err := l.v.ReadRoleTTL(ctx, "database", role)
		if err != nil {
			t.Fatal(err)
		}
		l.record("role_ttl_"+role, map[string]string{"default_ttl": def.String(), "max_ttl": max.String()})
		if def > vault.MaxDefaultTTL || max > vault.MaxMaxTTL {
			t.Errorf("%s: default %v max %v out of policy", role, def, max)
		}
	}
	// A role written straight to the API with a 24h TTL still gets a lease
	// capped by the mount's max_lease_ttl.
	if err := l.v.Do(ctx, "POST", "database/roles/warden-raw-24h", map[string]any{"db_name": "warden-pg",
		"creation_statements": []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`},
		"default_ttl":         "24h", "max_ttl": "24h"}, nil); err != nil {
		t.Fatal(err)
	}
	c, err := l.v.DBCreds(ctx, "database", "warden-raw-24h")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.v.Revoke(ctx, c.LeaseID) }()
	l.record("mount_cap_raw_24h_role_lease", c.TTL.String())
	if c.TTL > vault.MaxMaxTTL {
		t.Errorf("lease %v exceeds mount cap", c.TTL)
	}
}

func TestDynamicCredsExpire(t *testing.T) {
	l := live(t)
	ctx := context.Background()
	issued := time.Now()
	c, err := l.v.DBCreds(ctx, "database", "warden-test-1m")
	if err != nil {
		t.Fatal(err)
	}
	if c.TTL != time.Minute {
		t.Fatalf("lease TTL %v, want 1m", c.TTL)
	}
	session, err := l.login(ctx, c.Username, c.Password)
	if err != nil {
		t.Fatalf("fresh credential cannot log in: %v", err)
	}
	defer session.Close(context.Background())
	var lastOK, firstFail time.Duration
	var failErr string
	for time.Since(issued) < c.TTL+45*time.Second {
		conn, err := l.login(ctx, c.Username, c.Password)
		if err != nil {
			firstFail, failErr = time.Since(issued), err.Error()
			break
		}
		conn.Close(ctx)
		lastOK = time.Since(issued)
		time.Sleep(time.Second)
	}
	var sessionErr string
	if _, err := session.Exec(ctx, "SELECT 1"); err != nil {
		sessionErr = err.Error()
	}
	var dropped time.Duration
	for time.Since(issued) < c.TTL+90*time.Second {
		exists, err := l.roleExists(ctx, c.Username)
		if err == nil && !exists {
			dropped = time.Since(issued)
			break
		}
		time.Sleep(time.Second)
	}
	l.record("expire", map[string]any{"ttl": c.TTL.String(), "last_successful_login_s": lastOK.Seconds(),
		"first_failed_login_s": firstFail.Seconds(), "failed_login_error": failErr,
		"open_session_after_expiry_error": sessionErr, "role_dropped_by_s": dropped.Seconds()})
	if firstFail == 0 {
		t.Fatalf("credential still works %v after issue (TTL %v)", time.Since(issued), c.TTL)
	}
	if firstFail < c.TTL-2*time.Second {
		t.Errorf("credential failed early at %v", firstFail)
	}
	if sessionErr == "" {
		t.Error("open session survived lease expiry")
	}
	if dropped == 0 {
		t.Error("database role not dropped after expiry")
	}
}

func TestLeaseRevocation(t *testing.T) {
	l := live(t)
	ctx := context.Background()
	c, err := l.v.DBCreds(ctx, "database", "warden-app")
	if err != nil {
		t.Fatal(err)
	}
	if c.TTL != time.Hour {
		t.Fatalf("lease TTL %v, want 1h", c.TTL)
	}
	session, err := l.login(ctx, c.Username, c.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(context.Background())
	t0 := time.Now()
	if err := l.v.Revoke(ctx, c.LeaseID); err != nil {
		t.Fatal(err)
	}
	revokeCall := time.Since(t0)
	_, loginErr := l.login(ctx, c.Username, c.Password)
	firstLogin := time.Since(t0)
	_, sessionErr := session.Exec(ctx, "SELECT 1")
	exists, _ := l.roleExists(ctx, c.Username)
	l.record("revoke", map[string]any{"revoke_call_ms": revokeCall.Milliseconds(), "login_after_revoke_ms": firstLogin.Milliseconds(),
		"login_error": fmt.Sprint(loginErr), "open_session_error": fmt.Sprint(sessionErr), "role_exists_after": exists})
	if loginErr == nil {
		t.Error("login still works right after revoke")
	}
	if sessionErr == nil {
		t.Error("open session survived revoke")
	}
	if exists {
		t.Error("database role still exists after revoke")
	}
}
