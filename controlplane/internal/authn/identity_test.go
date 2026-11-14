package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"warden/controlplane/internal/api"
	"warden/controlplane/internal/runs"
	"warden/controlplane/internal/scim"
	"warden/controlplane/internal/tenant"
	"warden/controlplane/internal/testutil"
)

const testOID = "3333aaaa-3333-4333-8333-33333333cccc"

func withOID(f *fixture, oid any) string {
	c := f.claims()
	c["oid"] = oid
	return signed(ephemeralKeys()[0], `{"alg":"RS256","typ":"JWT","kid":"A"}`, encoded(c))
}

func TestVerify_ObjectIDClaim(t *testing.T) {
	f := newFixture(t)
	if c := accept(t, f.v, withOID(f, testOID)); c.ObjectID != testOID {
		t.Fatalf("oid not surfaced: %+v", c)
	}
	if c := accept(t, f.v, token(f, 0, "A")); c.ObjectID != "" {
		t.Fatalf("absent oid invented: %+v", c)
	}
	for _, bad := range []any{"", "not-a-guid", strings.ToUpper(testOID), 42, []string{testOID}} {
		reject(t, f.v, withOID(f, bad))
	}
	id, err := f.v.VerifyIdentity(context.Background(), withOID(f, testOID))
	if err != nil || id.ObjectID != testOID {
		t.Fatalf("VerifyIdentity: %+v %v", id, err)
	}
	if _, err := f.v.VerifyIdentity(context.Background(), token(f, 0, "A")); err == nil {
		t.Fatal("identity without oid accepted")
	}
}

// The production chain with only the network replaced: a token signed by a
// locally generated key, served from a local JWKS, mapped to a SCIM-provisioned
// user, creates a run and reads it back.
func TestEndToEndLocalJWKSRunCreateAndRead(t *testing.T) {
	pool := testutil.Database(t)
	f := newFixture(t)
	dir := &scim.Store{Pool: pool}
	sum := sha256.Sum256([]byte("e2e-provisioning-token"))
	tokens, err := scim.NewStaticTokens(map[string]string{hex.EncodeToString(sum[:]): "tenant-e2e"})
	if err != nil {
		t.Fatal(err)
	}
	user := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"e2e@example.test","externalId":"` + testOID + `","active":true}`
	if w := serve(scim.NewHandler(dir, tokens), "POST", "/scim/v2/Users", "e2e-provisioning-token", user, ""); w.Code != 201 {
		t.Fatalf("provision: %d %s", w.Code, w.Body.String())
	}
	h := api.New(&runs.Store{Pool: pool}, scim.TenantVerifier(tenant.IdentityVerifierFunc(f.v.VerifyIdentity), dir))

	good := withOID(f, testOID)
	body := `{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cmd":["/bin/true"]}`
	w := serve(h, "POST", "/v1/runs", good, body, "e2e-1")
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.RunID == "" {
		t.Fatalf("create body: %s", w.Body.String())
	}
	w = serve(h, "GET", "/v1/runs/"+created.RunID, good, "", "")
	var got struct {
		RunID string `json:"run_id"`
		State string `json:"state"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.RunID != created.RunID || got.State != "queued" {
		t.Fatalf("read back: %d %s", w.Code, w.Body.String())
	}

	wrongAud := f.claims()
	wrongAud["oid"], wrongAud["aud"] = testOID, "other-resource"
	otherKey := f.claims()
	otherKey["oid"] = testOID
	for name, raw := range map[string]string{
		"wrong-audience": signed(ephemeralKeys()[0], `{"alg":"RS256","kid":"A"}`, encoded(wrongAud)),
		"wrong-key":      signed(ephemeralKeys()[1], `{"alg":"RS256","kid":"A"}`, encoded(otherKey)),
		"unprovisioned":  withOID(f, "44444444-4444-4444-8444-444444444444"),
		"no-oid":         token(f, 0, "A"),
	} {
		if w := serve(h, "GET", "/v1/runs/"+created.RunID, raw, "", ""); w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func serve(h http.Handler, method, path, bearer, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
