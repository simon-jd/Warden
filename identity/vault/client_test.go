package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoleTTLPolicy(t *testing.T) {
	ok := []Role{{DefaultTTL: time.Minute, MaxTTL: time.Hour}, {DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour}}
	for _, r := range ok {
		if err := r.check(); err != nil {
			t.Errorf("%+v rejected: %v", r, err)
		}
	}
	bad := []Role{{}, {DefaultTTL: time.Hour + time.Second, MaxTTL: 4 * time.Hour},
		{DefaultTTL: time.Hour, MaxTTL: 4*time.Hour + time.Second}, {DefaultTTL: 2 * time.Hour, MaxTTL: time.Hour}}
	for _, r := range bad {
		if err := r.check(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestDBCredsAndRevokeUseVaultAPI(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/v1/database/creds/app":
			_, _ = w.Write([]byte(`{"lease_id":"database/creds/app/L1","lease_duration":60,"renewable":true,"data":{"username":"v-app-x","password":"p"}}`))
		case "/v1/sys/leases/revoke":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["lease_id"] != "database/creds/app/L1" {
				w.WriteHeader(400)
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errors":["no handler"]}`))
		}
	}))
	defer srv.Close()
	c := &Client{Addr: srv.URL, Token: "tok"}
	creds, err := c.DBCreds(context.Background(), "database", "app")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Username != "v-app-x" || creds.Password != "p" || creds.LeaseID != "database/creds/app/L1" || creds.TTL != time.Minute {
		t.Fatalf("creds %+v", creds)
	}
	if err := c.Revoke(context.Background(), creds.LeaseID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DBCreds(context.Background(), "database", "../sys"); err == nil {
		t.Fatal("path traversal in role name accepted")
	}
	bad := &Client{Addr: srv.URL, Token: "wrong"}
	if _, err := bad.DBCreds(context.Background(), "database", "app"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
	if got := strings.Join(seen, ","); got != "GET /v1/database/creds/app,PUT /v1/sys/leases/revoke,GET /v1/database/creds/app" {
		t.Fatalf("requests %s", got)
	}
}

func TestClientRequiresTLSOrLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{"https://vault.example:8200": true, "http://127.0.0.1:8200": true,
		"http://localhost:8200": true, "http://10.0.0.5:8200": false, "ftp://x": false} {
		c := &Client{Addr: addr, Token: "t"}
		if err := c.validate(); (err == nil) != ok {
			t.Errorf("%s: err=%v", addr, err)
		}
	}
}
