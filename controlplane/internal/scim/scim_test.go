package scim_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/controlplane/internal/api"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scim"
	"warden/controlplane/internal/tenant"
	"warden/controlplane/internal/testutil"
)

const (
	oidAlice = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	oidBob   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	runBody  = `{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`
)

func digest(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// fakeIdentities stands in for the OIDC verifier: "oid:<guid>" is a verified token.
var fakeIdentities = tenant.IdentityVerifierFunc(func(_ context.Context, raw string) (tenant.Identity, error) {
	if oid, ok := strings.CutPrefix(raw, "oid:"); ok {
		return tenant.Identity{ObjectID: oid}, nil
	}
	return tenant.Identity{}, errors.New("invalid token")
})

type env struct {
	scim, api http.Handler
}

func setup(t *testing.T) env {
	t.Helper()
	pool := testutil.Database(t)
	st := &scim.Store{Pool: pool}
	tokens, err := scim.NewStaticTokens(map[string]string{digest("prov-A"): "A", digest("prov-B"): "B"})
	if err != nil {
		t.Fatal(err)
	}
	return env{scim: scim.NewHandler(st, tokens), api: api.New(&runs.Store{Pool: pool}, scim.TenantVerifier(fakeIdentities, st))}
}

func do(h http.Handler, method, path, token, body string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("status %d: body is not JSON: %q", w.Code, w.Body.String())
	}
	return out
}

// entraUser mirrors what the Entra provisioning service sends for a new user.
func entraUser(userName, oid string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
"externalId":"` + oid + `","userName":"` + userName + `","active":true,"displayName":"Test User",
"name":{"givenName":"Test","familyName":"User","formatted":"Test User"},
"emails":[{"primary":true,"type":"work","value":"` + userName + `"}],
"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"QA"}}`
}

func createUser(t *testing.T, e env, token, userName, oid string) string {
	t.Helper()
	w := do(e.scim, "POST", "/scim/v2/Users", token, entraUser(userName, oid))
	if w.Code != 201 {
		t.Fatalf("create user: %d %s", w.Code, w.Body.String())
	}
	id, _ := decode(t, w)["id"].(string)
	return id
}

func patchActive(t *testing.T, e env, id string, value string) {
	t.Helper()
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":` + value + `}]}`
	if w := do(e.scim, "PATCH", "/scim/v2/Users/"+id, "prov-A", body); w.Code != 200 {
		t.Fatalf("patch active=%s: %d %s", value, w.Code, w.Body.String())
	}
}

func TestSCIMConformanceBasic(t *testing.T) {
	e := setup(t)
	if w := do(e.scim, "POST", "/scim/v2/Users", "", entraUser("alice@example.test", oidAlice)); w.Code != 401 {
		t.Fatalf("unauthenticated create: %d", w.Code)
	}

	w := do(e.scim, "POST", "/scim/v2/Users", "prov-A", entraUser("alice@example.test", oidAlice))
	if w.Code != 201 || w.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("create: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	u := decode(t, w)
	id, _ := u["id"].(string)
	meta, _ := u["meta"].(map[string]any)
	if len(id) != 26 || u["userName"] != "alice@example.test" || u["externalId"] != oidAlice || u["active"] != true ||
		meta["resourceType"] != "User" || meta["location"] != "/scim/v2/Users/"+id || w.Header().Get("Location") != "/scim/v2/Users/"+id {
		t.Fatalf("created resource: %v", u)
	}
	if w := do(e.scim, "POST", "/scim/v2/Users", "prov-A", entraUser("alice@example.test", oidBob)); w.Code != 409 || decode(t, w)["scimType"] != "uniqueness" {
		t.Fatalf("duplicate userName: %d %s", w.Code, w.Body.String())
	}

	if w := do(e.scim, "GET", "/scim/v2/Users/"+id, "prov-A", ""); w.Code != 200 || decode(t, w)["userName"] != "alice@example.test" {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	for filter, want := range map[string]float64{
		`userName eq "alice@example.test"`: 1, `externalId eq "` + oidAlice + `"`: 1, `userName eq "nobody@example.test"`: 0,
	} {
		w := do(e.scim, "GET", "/scim/v2/Users?filter="+urlQuery(filter), "prov-A", "")
		l := decode(t, w)
		if w.Code != 200 || l["totalResults"] != want {
			t.Fatalf("filter %s: %d %v", filter, w.Code, l)
		}
	}
	if w := do(e.scim, "GET", "/scim/v2/Users?filter="+urlQuery(`displayName co "x"`), "prov-A", ""); w.Code != 400 || decode(t, w)["scimType"] != "invalidFilter" {
		t.Fatalf("unsupported filter: %d %s", w.Code, w.Body.String())
	}

	// Another tenant's provisioning token cannot see or change this user.
	if w := do(e.scim, "GET", "/scim/v2/Users/"+id, "prov-B", ""); w.Code != 404 {
		t.Fatalf("cross-tenant get: %d", w.Code)
	}
	if l := decode(t, do(e.scim, "GET", "/scim/v2/Users?filter="+urlQuery(`userName eq "alice@example.test"`), "prov-B", "")); l["totalResults"] != 0.0 {
		t.Fatalf("cross-tenant filter: %v", l)
	}
	if w := do(e.scim, "DELETE", "/scim/v2/Users/"+id, "prov-B", ""); w.Code != 404 {
		t.Fatalf("cross-tenant delete: %d", w.Code)
	}

	// Entra's legacy form sends booleans as strings.
	patchActive(t, e, id, `"False"`)
	if u := decode(t, do(e.scim, "GET", "/scim/v2/Users/"+id, "prov-A", "")); u["active"] != false {
		t.Fatalf("after deactivate: %v", u)
	}
	noPath := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":true,"displayName":"Renamed"}}]}`
	if w := do(e.scim, "PATCH", "/scim/v2/Users/"+id, "prov-A", noPath); w.Code != 200 || decode(t, w)["active"] != true {
		t.Fatalf("path-less replace: %d %s", w.Code, w.Body.String())
	}
	bad := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"move","path":"active","value":false}]}`
	if w := do(e.scim, "PATCH", "/scim/v2/Users/"+id, "prov-A", bad); w.Code != 400 {
		t.Fatalf("invalid op: %d", w.Code)
	}

	if w := do(e.scim, "DELETE", "/scim/v2/Users/"+id, "prov-A", ""); w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := do(e.scim, "GET", "/scim/v2/Users/"+id, "prov-A", ""); w.Code != 404 {
		t.Fatalf("get after delete: %d", w.Code)
	}
	if w := do(e.scim, "DELETE", "/scim/v2/Users/"+id, "prov-A", ""); w.Code != 404 {
		t.Fatalf("second delete: %d", w.Code)
	}
}

func TestSCIMDeactivateRevokesSessions(t *testing.T) {
	e := setup(t)
	id := createUser(t, e, "prov-A", "alice@example.test", oidAlice)
	createUser(t, e, "prov-B", "bob@example.test", oidBob)

	w := do(e.api, "POST", "/v1/runs", "oid:"+oidAlice, runBody, "Idempotency-Key", "k1")
	if w.Code != 201 {
		t.Fatalf("provisioned user create run: %d %s", w.Code, w.Body.String())
	}
	runID, _ := decode(t, w)["run_id"].(string)
	runPath := "/v1/runs/" + runID
	if w := do(e.api, "GET", runPath, "oid:"+oidAlice, ""); w.Code != 200 {
		t.Fatalf("provisioned user read: %d", w.Code)
	}
	if w := do(e.api, "GET", runPath, "oid:"+oidBob, ""); w.Code != 404 {
		t.Fatalf("other tenant's user read: %d", w.Code)
	}
	if w := do(e.api, "GET", runPath, "oid:cccccccc-cccc-4ccc-8ccc-cccccccccccc", ""); w.Code != 401 {
		t.Fatalf("unprovisioned identity: %d", w.Code)
	}

	start := time.Now()
	patchActive(t, e, id, "false")
	var elapsed time.Duration
	for {
		elapsed = time.Since(start)
		if do(e.api, "GET", runPath, "oid:"+oidAlice, "").Code == 401 {
			break
		}
		if elapsed > 60*time.Second {
			t.Fatal("deactivated user still authorized after 60s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("deactivation to first 401: %s", elapsed)
	if w := do(e.api, "POST", "/v1/runs", "oid:"+oidAlice, runBody, "Idempotency-Key", "k2"); w.Code != 401 {
		t.Fatalf("deactivated user create: %d", w.Code)
	}

	patchActive(t, e, id, "true")
	if w := do(e.api, "GET", runPath, "oid:"+oidAlice, ""); w.Code != 200 {
		t.Fatalf("reactivated user: %d", w.Code)
	}
	if w := do(e.scim, "DELETE", "/scim/v2/Users/"+id, "prov-A", ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := do(e.api, "GET", runPath, "oid:"+oidAlice, ""); w.Code != 401 {
		t.Fatalf("deleted user: %d", w.Code)
	}
}

func urlQuery(s string) string {
	r := strings.NewReplacer(" ", "%20", `"`, "%22", "@", "%40")
	return r.Replace(s)
}
