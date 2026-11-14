package jit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func adapterTarget() Target {
	return Target{TenantID: "tenant-a", RequestID: strings.Repeat("A", 26), Name: "jit-"+strings.Repeat("a", 26), Namespace: "tenant-a", Role: "limited-operator", User: "alice", ExpiresAt: time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC)}
}
func adapter(t *testing.T, transport http.RoundTripper) *KubernetesBindings {
	t.Helper()
	k, err := NewKubernetesBindings(KubernetesConfig{Endpoint: "https://cluster.invalid", Transport: transport, BearerToken: func(context.Context) (string, error) { return "fixture-token", nil }})
	if err != nil { t.Fatal(err) }
	return k
}

// This in-process protocol fixture is not Kubernetes, RBAC or real-identity
// acceptance. It enforces UID/version preconditions to expose stale writes.
type apiFixture struct {
	t *testing.T
	object *bindingObject
	version int
	calls []string
	keepDeleted bool
	conflictClear bool
}
func (a *apiFixture) RoundTrip(req *http.Request) (*http.Response, error) {
	a.calls = append(a.calls, req.Method)
	if req.Header.Get("Authorization") != "Bearer fixture-token" || req.URL.Scheme != "https" || req.URL.Host != "cluster.invalid" { a.t.Fatal("unexpected authenticated endpoint") }
	if req.URL.Path != "/apis/"+rbacAPI+"/v1/namespaces/tenant-a/rolebindings" && req.URL.Path != "/apis/"+rbacAPI+"/v1/namespaces/tenant-a/rolebindings/"+adapterTarget().Name { a.t.Fatal("wrong namespace/name path") }
	encode := func() *http.Response { b, err := json.Marshal(a.object); if err != nil { a.t.Fatal(err) }; return response(http.StatusOK, string(b)) }
	switch req.Method {
	case http.MethodPost:
		if a.object != nil { return response(http.StatusConflict, `{}`), nil }
		var o bindingObject
		if err := json.NewDecoder(req.Body).Decode(&o); err != nil { a.t.Fatal(err) }
		if len(o.Subjects) != 0 { a.t.Fatal("reservation grants access") }
		a.version++
		o.Metadata["uid"], o.Metadata["resourceVersion"] = raw("fixture-uid"), raw(strconv.Itoa(a.version))
		a.object = &o
		r := encode(); r.StatusCode = http.StatusCreated
		return r, nil
	case http.MethodGet:
		if a.object == nil { return response(http.StatusNotFound, `{}`), nil }
		return encode(), nil
	case http.MethodPut:
		if a.object == nil { return response(http.StatusNotFound, `{}`), nil }
		var o bindingObject
		if err := json.NewDecoder(req.Body).Decode(&o); err != nil { a.t.Fatal(err) }
		if metaString(o, "uid") != metaString(*a.object, "uid") || metaString(o, "resourceVersion") != metaString(*a.object, "resourceVersion") { return response(http.StatusConflict, `{}`), nil }
		if len(o.Subjects) == 0 && a.conflictClear { a.conflictClear = false; return response(http.StatusConflict, `{}`), nil }
		a.version++
		o.Metadata["resourceVersion"] = raw(strconv.Itoa(a.version))
		a.object = &o
		return encode(), nil
	case http.MethodDelete:
		var opts struct { Preconditions struct { UID string `json:"uid"`; ResourceVersion string `json:"resourceVersion"` } `json:"preconditions"` }
		if err := json.NewDecoder(req.Body).Decode(&opts); err != nil { a.t.Fatal(err) }
		if a.object == nil { return response(http.StatusNotFound, `{}`), nil }
		if opts.Preconditions.UID != metaString(*a.object, "uid") || opts.Preconditions.ResourceVersion != metaString(*a.object, "resourceVersion") || len(a.object.Subjects) != 0 { a.t.Fatal("delete lacks current UID/version or prior clearing") }
		if !a.keepDeleted { a.object = nil }
		return response(http.StatusAccepted, `{}`), nil
	}
	a.t.Fatal("unexpected method")
	return nil, errors.New("unexpected method")
}

func TestKubernetesBindingLifecycleAndFencing(t *testing.T) {
	api := &apiFixture{t: t, conflictClear: true}
	k := adapter(t, api)
	target := adapterTarget()
	r, err := k.Reserve(context.Background(), target)
	if err != nil { t.Fatal(err) }
	if err = k.Activate(context.Background(), target, r); err != nil { t.Fatal(err) }
	if len(api.object.Subjects) != 1 || api.object.Subjects[0].Name != "alice" { t.Fatal("wrong subject activated") }
	if err = k.Remove(context.Background(), target, r); err != nil { t.Fatal(err) }
	if api.object != nil { t.Fatal("external object remains") }
	if err = k.Activate(context.Background(), target, r); err == nil || api.object != nil { t.Fatal("late activation recreated access") }
	if err = k.Remove(context.Background(), target, r); err != nil { t.Fatal("absence is not idempotent", err) }
	if strings.Join(api.calls, ",") != "POST,PUT,GET,PUT,GET,PUT,DELETE,GET,PUT,GET" { t.Fatalf("unexpected mutation/retry sequence: %v", api.calls) }
}

func TestKubernetesStrictResponseValidation(t *testing.T) {
	target := adapterTarget()
	o := newBinding(target)
	o.Metadata["uid"], o.Metadata["resourceVersion"] = raw("fixture-uid"), raw("1")
	good, err := json.Marshal(o)
	if err != nil { t.Fatal(err) }
	cases := map[string]string{
		"duplicate": strings.Replace(string(good), `"kind":"RoleBinding"`, `"kind":"RoleBinding","kind":"RoleBinding"`, 1),
		"case-alias": strings.Replace(string(good), `"kind":`, `"Kind":`, 1),
		"trailing": string(good)+` {}`,
		"wrong-role": strings.Replace(string(good), "limited-operator", "admin", 1),
		"wrong-tenant": strings.Replace(string(good), `"warden.io/tenant":"tenant-a"`, `"warden.io/tenant":"tenant-b"`, 1),
		"wrong-kind": strings.Replace(string(good), "RoleBinding", "ClusterRoleBinding", 1),
		"unknown-field": strings.Replace(string(good), `"subjects":[]`, `"subjects":[],"unexpected":true`, 1),
		"grant-in-reservation": strings.Replace(string(good), `"subjects":[]`, `"subjects":[{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"alice"}]`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			k := adapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusCreated, body), nil }))
			if _, err := k.Reserve(context.Background(), target); err == nil { t.Fatal("malformed/foreign granting response accepted") }
		})
	}
	// Kubernetes may omit subjects when the reservation is empty.
	empty := strings.Replace(string(good), `,"subjects":[]`, "", 1)
	k := adapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusCreated, empty), nil }))
	if _, err := k.Reserve(context.Background(), target); err != nil { t.Fatal("empty omitted subjects rejected", err) }
}

func TestKubernetesRemovalRejectsForeignUIDAndUnconfirmedDeletion(t *testing.T) {
	api := &apiFixture{t: t}
	k, target := adapter(t, api), adapterTarget()
	r, err := k.Reserve(context.Background(), target)
	if err != nil { t.Fatal(err) }
	foreign := r; foreign.UID = "foreign-uid"
	before := len(api.calls)
	if err = k.Remove(context.Background(), target, foreign); err == nil { t.Fatal("foreign UID removed") }
	if len(api.calls) != before+1 || api.calls[before] != "GET" { t.Fatal("foreign object mutated") }
	api.keepDeleted = true
	if err = k.Remove(context.Background(), target, r); err == nil { t.Fatal("accepted deletion without confirmed absence") }
	if api.object == nil || len(api.object.Subjects) != 0 { t.Fatal("pending deletion did not retain a fenced empty binding") }
}

func TestKubernetesTransportErrorsDoNotRetryActivation(t *testing.T) {
	calls := 0
	k := adapter(t, roundTripFunc(func(req *http.Request) (*http.Response, error) { calls++; return nil, errors.New("ambiguous transport error with private token") }))
	if err := k.Activate(context.Background(), adapterTarget(), Receipt{UID: "uid", ResourceVersion: "1"}); !errors.Is(err, ErrUnavailable) { t.Fatalf("unsafe transport error: %v", err) }
	if calls != 1 { t.Fatal("ambiguous activation retried") }
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		calls = 0
		k = adapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(status, `{}`), nil }))
		if _, err := k.Reserve(context.Background(), adapterTarget()); err == nil || calls != 1 { t.Fatal("failed/redirected response accepted or followed") }
	}
	k = adapter(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusCreated, strings.Repeat(" ", maxBindingBody+1)), nil }))
	if _, err := k.Reserve(context.Background(), adapterTarget()); !errors.Is(err, ErrUnavailable) { t.Fatal("oversized response accepted") }
}
