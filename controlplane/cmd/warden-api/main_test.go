package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	issuer   = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0"
	audience = "22222222-2222-4222-8222-222222222222"
	jwks     = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestIdentityConfig(t *testing.T) {
	full := map[string]string{"WARDEN_OIDC_ISSUER": issuer, "WARDEN_OIDC_AUDIENCE": audience, "WARDEN_OIDC_JWKS_URL": jwks}

	v, scimH, err := identity(envOf(nil), nil)
	if err != nil || v != nil || scimH != nil {
		t.Fatalf("unconfigured must deny all without error: %v %v %v", v, scimH, err)
	}
	v, _, err = identity(envOf(full), nil)
	if err != nil || v == nil {
		t.Fatalf("full OIDC config: %v %v", v, err)
	}
	for name, change := range map[string]func(map[string]string){
		"missing-audience": func(m map[string]string) { delete(m, "WARDEN_OIDC_AUDIENCE") },
		"wrong-jwks":       func(m map[string]string) { m["WARDEN_OIDC_JWKS_URL"] = "https://attacker.example/keys" },
		"not-entra":        func(m map[string]string) { m["WARDEN_OIDC_ISSUER"] = "https://idp.example/" },
		"missing-digests":  func(m map[string]string) { m["WARDEN_SCIM_TOKEN_DIGESTS"] = filepath.Join(t.TempDir(), "absent.json") },
		"scim-without-oidc": func(m map[string]string) {
			for k := range m {
				delete(m, k)
			}
			m["WARDEN_SCIM_TOKEN_DIGESTS"] = digestFile(t)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range full {
				m[k] = v
			}
			change(m)
			if _, _, err := identity(envOf(m), nil); err == nil {
				t.Fatal("invalid identity configuration accepted")
			}
		})
	}
	full["WARDEN_SCIM_TOKEN_DIGESTS"] = digestFile(t)
	if v, scimH, err = identity(envOf(full), nil); err != nil || v == nil || scimH == nil {
		t.Fatalf("OIDC + SCIM: %v %v %v", v, scimH, err)
	}
}

func TestRoutesSendSCIMOnlyToSCIM(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	scimH := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(298) })
	for path, want := range map[string]int{"/v1/runs": 299, "/scim/v2/Users": 298, "/scim/v2/Users/X": 298, "/scim/v2": 299} {
		w := httptest.NewRecorder()
		routes(api, scimH).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s -> %d, want %d", path, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	routes(api, nil).ServeHTTP(w, httptest.NewRequest("GET", "/scim/v2/Users", nil))
	if w.Code != 299 { // without SCIM the API handler answers (and denies) everything
		t.Errorf("unconfigured SCIM routed to %d", w.Code)
	}
}

func digestFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "digests.json")
	if err := os.WriteFile(p, []byte(`{"`+strings.Repeat("ab", 32)+`":"tenant-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
