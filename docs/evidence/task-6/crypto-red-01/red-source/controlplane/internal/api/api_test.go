package api_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"warden/controlplane/internal/api"
	"warden/controlplane/internal/audit"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scheduler"
	"warden/controlplane/internal/tenant"
	"warden/controlplane/internal/testutil"
	"warden/runtimes"
	"warden/runtimes/gate"
)

const valid = `{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`

func setup(t *testing.T, policies ...runs.PolicyProvider) (http.Handler, *runs.Store) {
	t.Helper()
	s := &runs.Store{Pool: testutil.Database(t)}
	if len(policies) > 0 {
		s.Policies = policies[0]
	}
	v := tenant.VerifyFunc(func(_ context.Context, token string) (tenant.Claims, error) {
		switch token {
		case "signed-A":
			return tenant.Claims{TenantID: "A"}, nil
		case "signed-B":
			return tenant.Claims{TenantID: "B"}, nil
		default:
			return tenant.Claims{}, errors.New("invalid token")
		}
	})
	return api.New(s, v), s
}
func request(h http.Handler, method, path, token, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func create(t *testing.T, h http.Handler, key string) string {
	t.Helper()
	w := request(h, "POST", "/v1/runs", "signed-A", key, valid)
	if w.Code != 201 {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		ID string `json:"run_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

// Break caught: duplicate requests create separate durable runs.
func TestIdempotencyKeyReturnsSameRun(t *testing.T) {
	h, s := setup(t)
	a := create(t, h, "same")
	b := create(t, h, "same")
	if a != b {
		t.Fatalf("run IDs differ: %s %s", a, b)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("not 128-bit base32: %q", a)
	}
	var n int
	if err = s.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_entries").Scan(&n); err != nil || n != 1 {
		t.Fatalf("one audit event required, count=%d err=%v", n, err)
	}
}

// Break caught: missing tenant predicates disclose run metadata or logs.
func TestCrossTenantReadDenied(t *testing.T) {
	h, _ := setup(t)
	id := create(t, h, "isolated")
	for _, suffix := range []string{"", "/logs"} {
		for _, other := range []string{id, "AAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			w := request(h, "GET", "/v1/runs/"+other+suffix, "signed-B", "", "")
			if w.Code != 404 {
				t.Fatalf("path=%s status=%d body=%s", other+suffix, w.Code, w.Body.String())
			}
		}
	}
	for _, suffix := range []string{"", "/logs"} {
		w := request(h, "GET", "/v1/runs/"+id+suffix, "signed-A", "", "")
		if w.Code != 200 {
			t.Fatalf("owner read status=%d", w.Code)
		}
	}
}

// Break caught: concurrent equal keys append multiple runs or audit entries.
func TestConcurrentIdempotency(t *testing.T) {
	h, s := setup(t)
	const count = 16
	ids := make(chan string, count)
	errs := make(chan string, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := request(h, "POST", "/v1/runs", "signed-A", "race", valid)
			if w.Code != 201 {
				errs <- fmt.Sprintf("%d %s", w.Code, w.Body.String())
				return
			}
			var v map[string]string
			if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
				errs <- e.Error()
				return
			}
			ids <- v["run_id"]
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Errorf("IDs differ")
		}
	}
	var n int
	if err := s.Pool.QueryRow(context.Background(), "SELECT count(*) FROM runs").Scan(&n); err != nil || n != 1 {
		t.Fatalf("runs=%d err=%v", n, err)
	}
	if err := (&audit.Log{Pool: s.Pool}).Verify(1, 1); err != nil {
		t.Fatal(err)
	}
}

// Break caught: changing payload silently reuses a prior run, or keys collide across tenants.
func TestIdempotencyPayloadAndTenantScope(t *testing.T) {
	h, _ := setup(t)
	id := create(t, h, "key")
	changed := strings.Replace(valid, "/bin/true", "/bin/false", 1)
	if w := request(h, "POST", "/v1/runs", "signed-A", "key", changed); w.Code != 409 {
		t.Fatalf("changed payload status=%d", w.Code)
	}
	reordered := `{ "cmd": ["/bin/true"], "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "runtime":"runc", "network":"none", "limits":{"cpu":1,"memory_mib":512,"pids":128,"timeout_s":300}}`
	w := request(h, "POST", "/v1/runs", "signed-A", "key", reordered)
	if w.Code != 201 || !strings.Contains(w.Body.String(), id) {
		t.Fatalf("normalized equivalent: %d %s", w.Code, w.Body.String())
	}
	w = request(h, "POST", "/v1/runs", "signed-B", "key", valid)
	if w.Code != 201 || strings.Contains(w.Body.String(), id) {
		t.Fatalf("tenant key isolation: %d %s", w.Code, w.Body.String())
	}
}

// Break caught: defaults falsely claim execution or omit secure launch requirements.
func TestQueuedRunPersistsSecureDefaults(t *testing.T) {
	h, _ := setup(t)
	id := create(t, h, "defaults")
	w := request(h, "GET", "/v1/runs/"+id, "signed-A", "", "")
	var out struct {
		State string `json:"state"`
		Spec  struct {
			Runtime, Network string
			Limits           struct {
				CPU     float64 `json:"cpu"`
				Memory  int     `json:"memory_mib"`
				Pids    int     `json:"pids"`
				Timeout int     `json:"timeout_s"`
			}
			Rootfs bool `json:"rootfs_readonly"`
			UID    int  `json:"uid"`
			NNP    bool `json:"no_new_privileges"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.State != "queued" || out.Spec.Runtime != "runc" || out.Spec.Network != "none" || out.Spec.Limits.CPU != 1 || out.Spec.Limits.Memory != 512 || out.Spec.Limits.Pids != 128 || out.Spec.Limits.Timeout != 300 || !out.Spec.Rootfs || out.Spec.UID != 65534 || !out.Spec.NNP {
		t.Fatalf("unexpected defaults %s", w.Body.String())
	}
	logs := request(h, "GET", "/v1/runs/"+id+"/logs", "signed-A", "", "")
	if strings.TrimSpace(logs.Body.String()) != `{"logs":[],"status":"pending","truncated":false,"dropped_bytes":0}` {
		t.Fatalf("queued logs=%s", logs.Body.String())
	}
}

// Break caught: untrusted headers, empty claims, or absent auth gain tenant access.
func TestAuthenticationFailsClosed(t *testing.T) {
	h, s := setup(t)
	for index, handler := range []http.Handler{h, api.New(s, nil), api.New(s, tenant.VerifyFunc(func(context.Context, string) (tenant.Claims, error) { return tenant.Claims{}, nil }))} {
		for _, token := range []string{"", "A", "signed-A"} {
			if index == 0 && token == "signed-A" {
				continue
			}
			r := httptest.NewRequest("POST", "/v1/runs", strings.NewReader(valid))
			r.Header.Set("X-Tenant", "A")
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			r.Header.Set("Idempotency-Key", "auth")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("token=%q status=%d", token, w.Code)
			}
		}
	}
}

// Break caught: malformed or dangerous requests persist as executable specifications.
func TestInvalidRequestsRejectedWithoutWrites(t *testing.T) {
	h, s := setup(t)
	cases := []string{`{}`, strings.Replace(valid, `"/bin/true"`, ``, 1), strings.Replace(valid, "sha256:", "latest:", 1), valid + `{}`, strings.Replace(valid, `"cmd":`, `"cmd":["x"],"cmd":`, 1), strings.Replace(valid, `"cmd":`, `"unknown":true,"cmd":`, 1), strings.TrimSuffix(valid, "}") + `,"runtime":"invalid"}`, strings.TrimSuffix(valid, "}") + `,"network":"allowlist"}`, strings.TrimSuffix(valid, "}") + `,"allow_domains":["example.com"]}`, strings.TrimSuffix(valid, "}") + `,"limits":{"cpu":-1}}`, strings.TrimSuffix(valid, "}") + `,"limits":{"pids":0}}`, strings.TrimSuffix(valid, "}") + `,"limits":{"memory_mib":-1}}`, strings.TrimSuffix(valid, "}") + `,"limits":{"timeout_s":0}}`, strings.TrimSuffix(valid, "}") + `,"rootfs_readonly":false}`, strings.TrimSuffix(valid, "}") + `,"network":"allowlist","allow_domains":["http://example.com"]}`}
	for i, body := range cases {
		w := request(h, "POST", "/v1/runs", "signed-A", fmt.Sprint(i), body)
		if w.Code != 400 {
			t.Errorf("case %d status=%d body=%s", i, w.Code, w.Body.String())
		}
	}
	if w := request(h, "POST", "/v1/runs", "signed-A", "", valid); w.Code != 400 {
		t.Errorf("missing idempotency key status=%d", w.Code)
	}
	oversized := append([]byte(`{"padding":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	if w := request(h, "POST", "/v1/runs", "signed-A", "large", string(oversized)); w.Code != 413 {
		t.Errorf("oversized status=%d", w.Code)
	}
	var n int
	if err := s.Pool.QueryRow(context.Background(), "SELECT count(*) FROM runs").Scan(&n); err != nil || n != 0 {
		t.Fatalf("invalid requests wrote runs=%d err=%v", n, err)
	}
}

// Break caught: run survives a failed audit append rather than rolling back.
func TestCreateRollsBackWhenAuditFails(t *testing.T) {
	h, s := setup(t)
	ctx := context.Background()
	_, err := s.Pool.Exec(ctx, `CREATE FUNCTION fail_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$; CREATE TRIGGER fail_append BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fail_append()`)
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/v1/runs", "signed-A", "rollback", valid)
	if w.Code != 500 {
		t.Fatalf("status=%d", w.Code)
	}
	var n int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM runs").Scan(&n); err != nil || n != 0 {
		t.Fatalf("run escaped transaction: %d %v", n, err)
	}
}

// Break caught: case-insensitive decoding accepts ambiguous aliases of security fields.
func TestRejectsCaseAliasedFields(t *testing.T) {
	h, _ := setup(t)
	for _, body := range []string{
		strings.Replace(valid, `"cmd":`, `"CMD":`, 1),
		strings.Replace(valid, `"cmd":`, `"Cmd":["/bin/false"],"cmd":`, 1),
		strings.TrimSuffix(valid, "}") + `,"limits":{"CPU":2}}`,
	} {
		w := request(h, "POST", "/v1/runs", "signed-A", "case", body)
		if w.Code != 400 {
			t.Errorf("ambiguous field accepted status=%d body=%s", w.Code, body)
		}
	}
}

// Break caught: a null command argument is silently converted to an empty string.
func TestRejectsNullCommandArguments(t *testing.T) {
	h, _ := setup(t)
	body := strings.Replace(valid, `["/bin/true"]`, `["/bin/echo",null]`, 1)
	if w := request(h, "POST", "/v1/runs", "signed-A", "null-arg", body); w.Code != 400 {
		t.Fatalf("null command argument accepted status=%d", w.Code)
	}
}

// Break caught: IP literals are treated as domain names in future egress policies.
func TestRejectsIPAllowlistEntries(t *testing.T) {
	h, _ := setup(t)
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "::1"} {
		body := strings.TrimSuffix(valid, "}") + `,"network":"allowlist","allow_domains":["` + ip + `"]}`
		if w := request(h, "POST", "/v1/runs", "signed-A", ip, body); w.Code != 400 {
			t.Errorf("IP literal %s accepted status=%d", ip, w.Code)
		}
	}
}

func withFields(fields string) string { return strings.TrimSuffix(valid, "}") + "," + fields + "}" }
func assertCounts(t *testing.T, s *runs.Store, want int) {
	t.Helper()
	for _, table := range []string{"runs", "audit_entries"} {
		var count int
		if err := s.Pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != want {
			t.Errorf("%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
}
func explicitPolicy() *runs.Policy {
	return &runs.Policy{TenantID: "A", MaxLimits: runs.Limits{CPU: 2, MemoryMiB: 1024, Pids: 256, TimeoutS: 600}, AllowedRuntimes: []string{"gvisor"}, AllowDomains: []string{"api.example.com"}}
}

const relaxedFields = `"runtime":"gvisor","network":"allowlist","allow_domains":["API.Example.com."],"limits":{"cpu":2,"memory_mib":1024,"pids":256,"timeout_s":600}`

// Break caught: absent tenant policy permits callers to raise global resource/network ceilings.
func TestTenantPolicyDefaultsDenyRelaxation(t *testing.T) {
	for _, provider := range []runs.PolicyProvider{nil, runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) { return nil, nil })} {
		h, s := setup(t, provider)
		for i, fields := range []string{`"network":"allowlist","allow_domains":["api.example.com"]`, `"limits":{"cpu":1.01}`, `"limits":{"memory_mib":513}`, `"limits":{"pids":129}`, `"limits":{"timeout_s":301}`} {
			w := request(h, "POST", "/v1/runs", "signed-A", fmt.Sprint(i), withFields(fields))
			if w.Code != 403 {
				t.Errorf("no-policy fields=%s status=%d want403", fields, w.Code)
			}
		}
		assertCounts(t, s, 0)
	}
}

// Break caught: the policy is applied to the wrong tenant or authorizes unlisted domains/limits.
func TestTenantPolicyAllowsExplicitScopedRelaxation(t *testing.T) {
	provider := runs.PolicyFunc(func(_ context.Context, id string) (*runs.Policy, error) {
		if id == "A" {
			return explicitPolicy(), nil
		}
		return nil, nil
	})
	h, s := setup(t, provider)
	body := withFields(relaxedFields)
	allowed := request(h, "POST", "/v1/runs", "signed-A", "allowed", body)
	if allowed.Code != 201 {
		t.Fatalf("explicit policy status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(allowed.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	got := request(h, "GET", "/v1/runs/"+result["run_id"], "signed-A", "", "")
	var persisted struct {
		Spec runs.Spec `json:"spec"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Spec.Limits.CPU != 2 || persisted.Spec.Limits.MemoryMiB != 1024 || persisted.Spec.Limits.Pids != 256 || persisted.Spec.Limits.TimeoutS != 600 || persisted.Spec.Runtime != "gvisor" || persisted.Spec.Network != "allowlist" || len(persisted.Spec.AllowDomains) != 1 || persisted.Spec.AllowDomains[0] != "api.example.com" {
		t.Fatalf("wrong authorized spec: %s", got.Body.String())
	}
	for i, denied := range []struct{ token, body string }{{"signed-B", body}, {"signed-A", strings.Replace(body, "API.Example.com.", "evil.example.com", 1)}, {"signed-A", strings.Replace(body, `"cpu":2`, `"cpu":2.01`, 1)}, {"signed-A", strings.Replace(body, `"memory_mib":1024`, `"memory_mib":1025`, 1)}, {"signed-A", strings.Replace(body, `"pids":256`, `"pids":257`, 1)}, {"signed-A", strings.Replace(body, `"timeout_s":600`, `"timeout_s":601`, 1)}} {
		if w := request(h, "POST", "/v1/runs", denied.token, fmt.Sprint(i), denied.body); w.Code != 403 {
			t.Errorf("denial %d status=%d", i, w.Code)
		}
	}
	assertCounts(t, s, 1)
}

// Break caught: provider errors, cross-tenant policies or malformed trusted configuration fail open.
func TestTenantPolicyLookupFailsClosed(t *testing.T) {
	cases := []runs.PolicyProvider{
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) { return nil, errors.New("provider unavailable") }),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.TenantID = "B"
			return p, nil
		}),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.TenantID = ""
			return p, nil
		}),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.MaxLimits.CPU = math.NaN()
			return p, nil
		}),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.MaxLimits.Pids = -1
			return p, nil
		}),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.AllowedRuntimes = []string{"privileged-runtime"}
			return p, nil
		}),
		runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
			p := explicitPolicy()
			p.AllowDomains = []string{"*.example.com"}
			return p, nil
		}),
	}
	for i, provider := range cases {
		h, s := setup(t, provider)
		if w := request(h, "POST", "/v1/runs", "signed-A", "fail", valid); w.Code != 503 {
			t.Errorf("provider %d status=%d want503", i, w.Code)
		}
		assertCounts(t, s, 0)
	}
}

// Break caught: the handler lets body/header tenant assertions select another tenant's policy.
func TestTenantPolicyCannotComeFromRequest(t *testing.T) {
	provider := runs.PolicyFunc(func(_ context.Context, id string) (*runs.Policy, error) {
		if id == "B" {
			p := explicitPolicy()
			p.TenantID = "B"
			return p, nil
		}
		return nil, nil
	})
	h, s := setup(t, provider)
	for _, field := range []string{`"policy":{"TenantID":"B","MaxLimits":{"cpu":99}}`, `"tenant_id":"B"`} {
		w := request(h, "POST", "/v1/runs", "signed-A", "body", withFields(field))
		if w.Code != 400 {
			t.Errorf("body supplied policy accepted: %d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/v1/runs", strings.NewReader(withFields(relaxedFields)))
	r.Header.Set("Authorization", "Bearer signed-A")
	r.Header.Set("Idempotency-Key", "header")
	r.Header.Set("X-Tenant", "B")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("header selected privileged policy status=%d", w.Code)
	}
	assertCounts(t, s, 0)
}

// Break caught: the idempotency cache bypasses revoked or unavailable policy on a retry.
func TestTenantPolicyRecheckedOnIdempotentReplay(t *testing.T) {
	var mode atomic.Int32
	provider := runs.PolicyFunc(func(_ context.Context, id string) (*runs.Policy, error) {
		switch mode.Load() {
		case 0:
			return explicitPolicy(), nil
		case 1:
			return nil, nil
		default:
			return nil, errors.New("lookup unavailable")
		}
	})
	h, s := setup(t, provider)
	body := withFields(relaxedFields)
	if w := request(h, "POST", "/v1/runs", "signed-A", "replay", body); w.Code != 201 {
		t.Fatalf("initial status=%d", w.Code)
	}
	mode.Store(1)
	if w := request(h, "POST", "/v1/runs", "signed-A", "replay", body); w.Code != 403 {
		t.Errorf("revoked replay status=%d", w.Code)
	}
	mode.Store(2)
	if w := request(h, "POST", "/v1/runs", "signed-A", "replay", body); w.Code != 503 {
		t.Errorf("failed lookup replay status=%d", w.Code)
	}
	assertCounts(t, s, 1)
}

// Break caught: runtime selection ignores the trusted allowed runtime set.
func TestTenantPolicyRuntimeAndPartialLimits(t *testing.T) {
	provider := runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
		return &runs.Policy{TenantID: "A", MaxLimits: runs.Limits{CPU: 2}, AllowedRuntimes: []string{"gvisor"}}, nil
	})
	h, s := setup(t, provider)
	for i, fields := range []string{`"runtime":"runc"`, `"runtime":"firecracker"`, `"runtime":"gvisor","limits":{"cpu":2,"memory_mib":513}`} {
		if w := request(h, "POST", "/v1/runs", "signed-A", fmt.Sprint(i), withFields(fields)); w.Code != 403 {
			t.Errorf("unapproved runtime/limit status=%d", w.Code)
		}
	}
	if w := request(h, "POST", "/v1/runs", "signed-A", "gvisor", withFields(`"runtime":"gvisor","limits":{"cpu":2}`)); w.Code != 201 {
		t.Fatalf("approved runtime status=%d", w.Code)
	}
	assertCounts(t, s, 1)
	h, s = setup(t, runs.PolicyFunc(func(context.Context, string) (*runs.Policy, error) {
		return &runs.Policy{TenantID: "A", AllowedRuntimes: []string{}}, nil
	}))
	if w := request(h, "POST", "/v1/runs", "signed-A", "deny-all", valid); w.Code != 403 {
		t.Errorf("empty runtime set status=%d", w.Code)
	}
	assertCounts(t, s, 0)
}

// Break caught: canceling the completed HTTP request cancels queued execution,
// persisted output is replaced by the old empty placeholder, or tenant B sees it.
func TestCompletedRequestCancellationDoesNotCancelExecution(t *testing.T) {
	h, s := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/v1/runs", strings.NewReader(valid)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer signed-A")
	req.Header.Set("Idempotency-Key", "cancel")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	cancel()
	if response.Code != 201 {
		t.Fatal(response.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created["run_id"]
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	driver, err := gate.New(dir, "node-A", apiRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	w := scheduler.Scheduler{Store: s, Node: "node-A", Drivers: map[string]*gate.Gate{"runc": driver}, OperationTimeout: time.Second}
	if err = w.Process(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	logs := request(h, "GET", "/v1/runs/"+id+"/logs", "signed-A", "", "")
	var out runs.Logs
	if err = json.Unmarshal(logs.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if logs.Code != 200 || out.Status != "complete" || strings.Join(out.Lines, "") != "private A output" {
		t.Fatalf("logs %s", logs.Body.String())
	}
	for _, suffix := range []string{"", "/logs"} {
		denied := request(h, "GET", "/v1/runs/"+id+suffix, "signed-B", "", "")
		if denied.Code != 404 || strings.Contains(denied.Body.String(), "private A") {
			t.Fatal("cross tenant disclosure")
		}
	}
	var run runs.Run
	response = request(h, "GET", "/v1/runs/"+id, "signed-A", "", "")
	if err = json.Unmarshal(response.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.State != "succeeded" || run.Result == nil || run.Result.PeakPids != 4 {
		t.Fatalf("result %s", response.Body.String())
	}
}

type apiRuntime struct{}

func (apiRuntime) Start(context.Context, runtimes.Spec) (runtimes.Handle, error) {
	return apiRuntime{}, nil
}
func (apiRuntime) Reap(context.Context, string) error { return nil }
func (apiRuntime) Wait(context.Context) (runtimes.Exit, error) {
	return runtimes.Exit{CgroupEmpty: true, PeakPids: 4}, nil
}
func (apiRuntime) Kill() error         { return nil }
func (apiRuntime) Logs() io.ReadCloser { return io.NopCloser(strings.NewReader("private A output")) }
