package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"warden/controlplane/internal/tenant"
)

func TestParseFilter(t *testing.T) {
	for in, want := range map[string]filter{
		`userName eq "alice@example.test"`:                     {attr: "userName", value: "alice@example.test"},
		`USERNAME EQ "Alice"`:                                  {attr: "userName", value: "Alice"},
		`externalId eq "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"`: {attr: "externalId", value: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
		`userName eq "quote\"inside"`:                          {attr: "userName", value: `quote"inside`},
		`  userName   eq   "spaced"  `:                         {attr: "userName", value: "spaced"},
	} {
		got, err := parseFilter(in)
		if err != nil || got != want {
			t.Errorf("parseFilter(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{
		``, `userName`, `userName eq`, `userName eq alice`, `userName ne "a"`, `displayName eq "a"`,
		`userName eq "a" and active eq true`, `userName eq "a" or userName eq "b"`, `userName eq "unterminated`,
		`userName eq "a"x`, `emails[type eq "work"].value eq "a"`,
	} {
		if _, err := parseFilter(in); err == nil {
			t.Errorf("parseFilter(%q) accepted", in)
		}
	}
}

func TestParsePatch(t *testing.T) {
	f := false
	tr := true
	name := "New Name"
	for body, want := range map[string]change{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`:                   {active: &f},
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`:                      {active: &tr},
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false,"displayName":"New Name"}}]}`: {active: &f, displayName: &name},
		// Attributes Warden does not store are accepted and ignored, as on create.
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"name.givenName","value":"x"},{"op":"Replace","path":"emails[type eq \"work\"].value","value":"a@b"}]}`: {},
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"displayName","value":"New Name"}]}`:                                                                {displayName: &name},
	} {
		got, err := parsePatch([]byte(body))
		if err != nil || !sameChange(got, want) {
			t.Errorf("parsePatch(%s) = %+v, %v", body, got, err)
		}
	}
	for _, body := range []string{
		`{}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`,
		`{"schemas":["wrong"],"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"move","path":"active","value":false}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"maybe"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":1}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"active"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":""}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"externalId","value":"not-a-guid"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":"not-an-object"}]}`,
	} {
		if _, err := parsePatch([]byte(body)); err == nil {
			t.Errorf("parsePatch(%s) accepted", body)
		}
	}
}

func sameChange(a, b change) bool {
	eqB := func(x, y *bool) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	eqS := func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return eqB(a.active, b.active) && eqS(a.userName, b.userName) && eqS(a.externalID, b.externalID) && eqS(a.displayName, b.displayName)
}

func TestParseUserRequiresUserNameAndObjectID(t *testing.T) {
	ok := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a@example.test","externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`
	u, err := parseUser([]byte(ok))
	if err != nil || u.UserName != "a@example.test" || !u.Active {
		t.Fatalf("minimal user: %+v %v (active defaults to true)", u, err)
	}
	for _, body := range []string{
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a"}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","externalId":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}`,
		`{"userName":"a","externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","userName":"b","externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + strings.Repeat("a", 257) + `","externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","externalId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {}`,
	} {
		if _, err := parseUser([]byte(body)); err == nil {
			t.Errorf("parseUser(%s) accepted", body)
		}
	}
}

func TestStaticTokens(t *testing.T) {
	if _, err := NewStaticTokens(map[string]string{"short": "A"}); err == nil {
		t.Fatal("non-hex digest accepted")
	}
	if _, err := NewStaticTokens(map[string]string{strings.Repeat("0", 64): ""}); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if _, err := NewStaticTokens(nil); err == nil {
		t.Fatal("empty token set accepted")
	}
	sum := sha256.Sum256([]byte("prov-A"))
	tokens, err := NewStaticTokens(map[string]string{hex.EncodeToString(sum[:]): "A"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(nil, tokens) // auth is checked before any database access
	for _, auth := range []string{"", "Bearer", "Bearer wrong", "Basic cHJvdi1BOg==", "Bearer prov-A extra"} {
		r := httptest.NewRequest("GET", "/scim/v2/Users/X", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: %d", auth, w.Code)
		}
	}
}

type fakeDirectory map[string]string

func (d fakeDirectory) Resolve(_ context.Context, oid string) (string, error) {
	if t, ok := d[oid]; ok {
		return t, nil
	}
	return "", ErrNotProvisioned
}

func TestTenantVerifierRequiresProvisionedIdentity(t *testing.T) {
	ids := tenant.IdentityVerifierFunc(func(_ context.Context, raw string) (tenant.Identity, error) {
		switch raw {
		case "good":
			return tenant.Identity{ObjectID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, nil
		case "no-oid":
			return tenant.Identity{}, nil
		case "unknown":
			return tenant.Identity{ObjectID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}, nil
		}
		return tenant.Identity{}, errors.New("bad signature")
	})
	v := TenantVerifier(ids, fakeDirectory{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": "A"})
	if c, err := v.Verify(context.Background(), "good"); err != nil || c.TenantID != "A" {
		t.Fatalf("provisioned: %+v %v", c, err)
	}
	for _, raw := range []string{"no-oid", "unknown", "forged"} {
		if c, err := v.Verify(context.Background(), raw); err == nil || c.TenantID != "" {
			t.Errorf("%s accepted: %+v", raw, c)
		}
	}
	if TenantVerifier(nil, fakeDirectory{}) != nil || TenantVerifier(ids, nil) != nil {
		t.Fatal("missing dependency must yield nil (API then denies everything)")
	}
}
