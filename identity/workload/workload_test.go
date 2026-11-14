package workload

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jwt(t *testing.T, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
}

// tokenEndpoint is a stand-in for Entra's v2 token endpoint. It answers a
// well-formed client-credentials request with a JWT assertion from the
// expected client; anything else gets Entra's error shape.
func tokenEndpoint(t *testing.T, access string, seen *[]string) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		f := r.PostForm
		if r.Method != http.MethodPost || r.URL.Path != "/tenant-1/oauth2/v2.0/token" ||
			f.Get("grant_type") != "client_credentials" || f.Get("client_id") != "client-1" ||
			f.Get("client_assertion_type") != AssertionType || f.Get("scope") != "https://management.azure.com/.default" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_request","error_description":"AADSTS900144: bad request. Trace ID: x","error_codes":[900144]}`)
			return
		}
		if f.Get("client_assertion") != "sa-token-for-the-control-plane" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS700213: No matching federated identity record found for presented assertion subject 'system:serviceaccount:warden-lab:default'. Trace ID: x","error_codes":[700213]}`)
			return
		}
		fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":86399,"ext_expires_in":86399,"access_token":%q}`, access)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestExchangeTradesTheAssertionForAnAccessToken(t *testing.T) {
	access := jwt(t, map[string]any{"aud": "https://management.azure.com/", "iat": 1700000000, "nbf": 1700000000,
		"exp": 1700086400, "idtyp": "app", "tid": "tenant-1", "oid": "object-1", "xms_mirid": "/subscriptions/s/x"})
	var seen []string
	s := tokenEndpoint(t, access, &seen)
	x := Exchanger{HTTP: s.Client(), Authority: s.URL}
	tok, err := x.Exchange(context.Background(), "tenant-1", "client-1", "sa-token-for-the-control-plane", "https://management.azure.com/.default")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Type != "Bearer" || tok.ExpiresIn != 86399 || tok.Value() != access {
		t.Fatalf("got %+v", tok)
	}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v", tok, tok, tok)} {
		if strings.Contains(s, access) || strings.Contains(s, "eyJ") {
			t.Fatalf("formatting a Token shows it: %s", s)
		}
	}
	if len(seen) != 1 || seen[0] != "POST /tenant-1/oauth2/v2.0/token" {
		t.Fatalf("requests %q", seen)
	}
	c, err := Claims(tok.Value())
	if err != nil {
		t.Fatal(err)
	}
	if life, err := Lifetime(c); err != nil || life != 86400 {
		t.Fatalf("lifetime %d, %v", life, err)
	}
	pub := Public(c)
	want := `{"aud":"https://management.azure.com/","claims":["aud","exp","iat","idtyp","nbf","oid","tid","xms_mirid"],"exp":1700086400,"iat":1700000000,"idtyp":"app","nbf":1700000000}`
	if b, _ := json.Marshal(pub); string(b) != want {
		t.Fatalf("Public: %s\nwant      %s", b, want)
	}
}

func TestExchangeReportsEntraErrorCodesWithoutTheDescription(t *testing.T) {
	var seen []string
	s := tokenEndpoint(t, "unused", &seen)
	x := Exchanger{HTTP: s.Client(), Authority: s.URL}
	_, err := x.Exchange(context.Background(), "tenant-1", "client-1", "sa-token-for-a-sandbox", "https://management.azure.com/.default")
	var e *Error
	if !asError(err, &e) || e.Status != 400 || e.Code != "invalid_client" || !e.Has(700213) || e.Has(70021) {
		t.Fatalf("got %v (%+v)", err, e)
	}
	if strings.Contains(err.Error(), "serviceaccount") || strings.Contains(err.Error(), "Trace") {
		t.Fatalf("error carries the description: %v", err)
	}
}

func TestExchangeRefusesNamesThatChangeTheURL(t *testing.T) {
	x := Exchanger{HTTP: http.DefaultClient, Authority: "http://127.0.0.1:1"}
	for _, tc := range [][2]string{{"", "client"}, {"tenant", ""}, {"a/b", "client"}, {"tenant?x=1", "client"}, {"..", "client"}} {
		if _, err := x.Exchange(context.Background(), tc[0], tc[1], "assertion", "scope"); err == nil || strings.Contains(err.Error(), "connect") {
			t.Errorf("tenant %q client %q: got %v, want refused before any request", tc[0], tc[1], err)
		}
	}
}

func TestClaimsAndLifetimeRejectWhatIsNotAJWT(t *testing.T) {
	for _, s := range []string{"", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if _, err := Claims(s); err == nil {
			t.Errorf("Claims(%q) accepted", s)
		}
	}
	for _, c := range []map[string]any{{}, {"iat": json.Number("1")}, {"iat": "1", "exp": "2"}, {"iat": json.Number("1.5"), "exp": json.Number("2")}} {
		if _, err := Lifetime(c); err == nil {
			t.Errorf("Lifetime(%v) accepted", c)
		}
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}
