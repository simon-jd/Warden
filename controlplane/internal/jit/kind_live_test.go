package jit

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"warden/respond/kindlab"
)

const (
	jitNS         = "warden-jit"
	jitSA         = "warden-jit"
	jitTenantNS   = "tenant-a"
	jitRole       = "limited-operator"
	jitKindGrants = 5
)

type kindJIT struct {
	t       *testing.T
	ctx     context.Context
	cluster kindlab.Cluster
	admin   kindlab.API
}

func (k *kindJIT) must(err error, what string) {
	k.t.Helper()
	if err != nil {
		k.t.Fatalf("%s: %v", what, err)
	}
}

func (k *kindJIT) create(path string, obj any) {
	k.t.Helper()
	if err := k.admin.Do(k.ctx, http.MethodPost, path, "", obj, nil); err != nil && !kindlab.IsStatus(err, http.StatusConflict) {
		k.t.Fatalf("POST %s: %v", path, err)
	}
}

// asAlice lists pods in ns impersonating user alice, i.e. with exactly the
// RBAC the JIT binding grants her, and returns the HTTP status.
func (k *kindJIT) asAlice(ns string) int {
	k.t.Helper()
	req, err := http.NewRequestWithContext(k.ctx, http.MethodGet, k.cluster.Server+"/api/v1/namespaces/"+ns+"/pods", nil)
	k.must(err, "request")
	req.Header.Set("Impersonate-User", "alice")
	resp, err := k.admin.HTTP.Do(req)
	k.must(err, "impersonated list")
	resp.Body.Close()
	return resp.StatusCode
}

func (k *kindJIT) bindingStatus(name string) int {
	err := k.admin.Do(k.ctx, http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/namespaces/"+jitTenantNS+"/rolebindings/"+name, "", nil, nil)
	switch {
	case err == nil:
		return http.StatusOK
	case kindlab.IsStatus(err, http.StatusNotFound):
		return http.StatusNotFound
	}
	k.t.Fatalf("get binding: %v", err)
	return 0
}

func (k *kindJIT) saAllowed(token, verb, group, resource, ns string) bool {
	hc, err := k.cluster.HTTPClient(false)
	k.must(err, "sa client")
	var r struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	k.must(kindlab.API{Server: k.cluster.Server, HTTP: hc, Token: token}.Do(k.ctx, http.MethodPost,
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", map[string]any{
			"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
			"spec": map[string]any{"resourceAttributes": map[string]string{"verb": verb, "group": group, "resource": resource, "namespace": ns}}},
		&r), "access review")
	return r.Status.Allowed
}

func p50p95(v []float64) map[string]float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	rank := func(p float64) float64 { return s[max(0, int(math.Ceil(p/100*float64(len(s))))-1)] }
	return map[string]float64{"p50": rank(50), "p95": rank(95), "max": s[len(s)-1]}
}

func msSince(t time.Time) float64 { return math.Round(time.Since(t).Seconds()*1e4) / 10 }

// TestJITGrantOnKindCluster runs the JIT service (real Postgres) with the
// real KubernetesBindings adapter against the kind lab: approval creates a
// RoleBinding that really lets the requester list pods in the tenant
// namespace, and Expire at the deadline (fake clock) deletes it and takes the
// access away. The adapter authenticates with a short-lived token of a
// ServiceAccount that may only manage RoleBindings in that namespace and bind
// the one configured Role.
func TestJITGrantOnKindCluster(t *testing.T) {
	if os.Getenv("WARDEN_LIVE_KIND") != "1" {
		t.Skip("live kind test: run `make test-kind`")
	}
	raw, err := os.ReadFile(os.Getenv("WARDEN_KIND_KUBECONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := kindlab.ParseKubeconfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := cluster.HTTPClient(true)
	if err != nil {
		t.Fatal(err)
	}
	k := &kindJIT{t: t, ctx: context.Background(), cluster: cluster, admin: kindlab.API{Server: cluster.Server, HTTP: hc}}
	loadStart := readLoad()
	pool, _, _, _, now := fixture(t) // Postgres + migrations; the fake bindings are not used

	meta := func(name, ns string) map[string]string {
		m := map[string]string{"name": name}
		if ns != "" {
			m["namespace"] = ns
		}
		return m
	}
	rbac := "/apis/rbac.authorization.k8s.io/v1"
	for _, ns := range []string{jitNS, jitTenantNS, "tenant-b"} {
		k.create("/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": meta(ns, "")})
	}
	for _, ns := range []string{jitTenantNS, "tenant-b"} {
		k.create(rbac+"/namespaces/"+ns+"/roles", map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
			"metadata": meta(jitRole, ns), "rules": []map[string]any{{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get", "list"}}}})
	}
	k.create("/api/v1/namespaces/"+jitNS+"/serviceaccounts", map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta(jitSA, jitNS)})
	k.create(rbac+"/namespaces/"+jitTenantNS+"/roles", map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
		"metadata": meta("warden-jit-manager", jitTenantNS), "rules": []map[string]any{
			{"apiGroups": []string{"rbac.authorization.k8s.io"}, "resources": []string{"rolebindings"}, "verbs": []string{"create", "get", "update", "delete"}},
			{"apiGroups": []string{"rbac.authorization.k8s.io"}, "resources": []string{"roles"}, "verbs": []string{"bind"}, "resourceNames": []string{jitRole}}}})
	k.create(rbac+"/namespaces/"+jitTenantNS+"/rolebindings", map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": meta("warden-jit-manager", jitTenantNS),
		"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "warden-jit-manager"},
		"subjects": []map[string]string{{"kind": "ServiceAccount", "name": jitSA, "namespace": jitNS}}})
	var tr struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	issued := time.Now()
	k.must(k.admin.Do(k.ctx, http.MethodPost, "/api/v1/namespaces/"+jitNS+"/serviceaccounts/"+jitSA+"/token", "",
		map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": map[string]any{"expirationSeconds": 600}}, &tr), "token")
	token := tr.Status.Token
	result := map[string]any{"token_ttl_s": tr.Status.ExpirationTimestamp.Sub(issued).Seconds(), "grants": jitKindGrants}
	saRBAC := map[string]bool{
		"create rolebindings tenant-a":     k.saAllowed(token, "create", "rbac.authorization.k8s.io", "rolebindings", jitTenantNS),
		"create rolebindings tenant-b":     k.saAllowed(token, "create", "rbac.authorization.k8s.io", "rolebindings", "tenant-b"),
		"create rolebindings kube-system":  k.saAllowed(token, "create", "rbac.authorization.k8s.io", "rolebindings", "kube-system"),
		"create clusterrolebindings":       k.saAllowed(token, "create", "rbac.authorization.k8s.io", "clusterrolebindings", ""),
		"update roles tenant-a":            k.saAllowed(token, "update", "rbac.authorization.k8s.io", "roles", jitTenantNS),
		"list pods tenant-a (sa itself)":   k.saAllowed(token, "list", "", "pods", jitTenantNS),
		"get secrets tenant-a (sa itself)": k.saAllowed(token, "get", "", "secrets", jitTenantNS),
	}
	result["jit_sa_rbac"] = saRBAC
	for what, got := range saRBAC {
		if want := what == "create rolebindings tenant-a"; got != want {
			t.Errorf("JIT ServiceAccount may %s = %v, want %v", what, got, want)
		}
	}

	transport, err := cluster.HTTPClient(false)
	k.must(err, "adapter client")
	b, err := NewKubernetesBindings(KubernetesConfig{Endpoint: cluster.Server, Transport: transport.Transport,
		BearerToken: func(context.Context) (string, error) { return token, nil }})
	k.must(err, "bindings")
	config := Config{Roles: map[string]Role{"operator": {Namespace: jitTenantNS, Name: jitRole}}}
	clock := func() time.Time { return *now }
	alice, err := New(pool, "tenant-a", config, callerFixture{user: "alice"}, b, clock)
	k.must(err, "requester")
	bob, err := New(pool, "tenant-a", config, callerFixture{user: "bob"}, b, clock)
	k.must(err, "approver")

	var approveMS, expireMS []float64
	var runs []map[string]any
	for i := range jitKindGrants {
		if got := k.asAlice(jitTenantNS); got != http.StatusForbidden {
			t.Fatalf("grant %d: alice can list pods before approval: HTTP %d", i, got)
		}
		id, err := alice.Request("alice", "operator", time.Hour, fmt.Sprintf("kind lab grant %d", i))
		k.must(err, "request")
		if err := alice.Approve(id, "alice"); err == nil {
			t.Fatal("self-approval accepted")
		}
		name := "jit-" + strings.ToLower(id)
		t0 := time.Now()
		k.must(bob.Approve(id, "bob"), "approve")
		approve := msSince(t0)
		during, other := k.asAlice(jitTenantNS), k.asAlice("tenant-b")
		if k.bindingStatus(name) != http.StatusOK || during != http.StatusOK || other != http.StatusForbidden {
			t.Fatalf("grant %d: binding %d, alice tenant-a %d, tenant-b %d", i, k.bindingStatus(name), during, other)
		}
		deadline := now.Add(time.Hour)
		*now = deadline.Add(-time.Nanosecond)
		k.must(bob.Expire(), "expire before deadline")
		if k.bindingStatus(name) != http.StatusOK || k.asAlice(jitTenantNS) != http.StatusOK {
			t.Fatalf("grant %d: access removed before the deadline", i)
		}
		*now = deadline
		t1 := time.Now()
		k.must(bob.Expire(), "expire")
		expire := msSince(t1)
		after := k.asAlice(jitTenantNS)
		if k.bindingStatus(name) != http.StatusNotFound || after != http.StatusForbidden {
			t.Fatalf("grant %d: after expiry binding %d, alice %d", i, k.bindingStatus(name), after)
		}
		var state string
		k.must(pool.QueryRow(k.ctx, `SELECT state FROM jit_requests WHERE id=$1 AND tenant_id='tenant-a'`, id).Scan(&state), "state")
		approveMS, expireMS = append(approveMS, approve), append(expireMS, expire)
		runs = append(runs, map[string]any{"request": id, "binding": name, "approve_ms": approve, "expire_ms": expire,
			"alice_during": during, "alice_other_ns_during": other, "alice_after": after, "state_after": state})
		*now = now.Add(time.Minute)
	}
	result["runs"] = runs
	result["approve_to_binding_active_ms"] = p50p95(approveMS)
	result["expire_to_binding_deleted_ms"] = p50p95(expireMS)
	result["load"] = map[string]any{"nproc": runtime.NumCPU(), "loadavg_start": loadStart, "loadavg_end": readLoad()}
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("%s", out)
	if p := os.Getenv("JIT_OUT"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readLoad() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
