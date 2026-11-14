package azurelab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/respond"
)

const (
	testTenant = "0f1e2d3c-4b5a-4968-8776-655443322110"
	testApp    = "3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f"
	testSecret = "s3cr3t~value.that-must-never-leak"
	testToken  = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.sig"
)

func TestClientCredentialsClassifiesTokenResponses(t *testing.T) {
	var form url.Values
	reply := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/"+testTenant+"/oauth2/v2.0/token" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		r.ParseForm()
		form = r.PostForm
		switch form.Get("client_secret") {
		case testSecret:
			reply(w, 200, `{"token_type":"Bearer","expires_in":3599,"access_token":"`+testToken+`"}`)
		case "gone":
			reply(w, 401, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. Trace ID: x","error_codes":[7000215]}`)
		default:
			reply(w, 503, `{"error":"temporarily_unavailable","error_description":"AADSTS90033: busy"}`)
		}
	}))
	defer srv.Close()
	c := TokenClient{Authority: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()

	ok := c.ClientCredentials(ctx, testTenant, testApp, testSecret, ARMScope)
	if !ok.OK || ok.Rejected() || ok.Token() != testToken || ok.ExpiresIn != 3599 || ok.Status != 200 {
		t.Fatalf("success probe %+v", ok)
	}
	want := url.Values{"grant_type": {"client_credentials"}, "client_id": {testApp},
		"client_secret": {testSecret}, "scope": {ARMScope}}
	if form.Encode() != want.Encode() {
		t.Fatalf("form %v, want %v", form, want)
	}
	raw, _ := json.Marshal(ok)
	if strings.Contains(string(raw), testToken) || strings.Contains(string(raw), testSecret) {
		t.Fatalf("probe JSON carries the token or secret: %s", raw)
	}

	gone := c.ClientCredentials(ctx, testTenant, testApp, "gone", ARMScope)
	if gone.OK || !gone.Rejected() || gone.Error != "invalid_client" || strings.Join(gone.AADSTS, ",") != "AADSTS7000215" || gone.Token() != "" {
		t.Fatalf("rejected probe %+v", gone)
	}
	// Anything that is not an explicit invalid_client is not evidence of
	// containment: a busy token service or a network error is inconclusive.
	busy := c.ClientCredentials(ctx, testTenant, testApp, "other", ARMScope)
	if busy.OK || busy.Rejected() || busy.Status != 503 {
		t.Fatalf("busy probe %+v", busy)
	}
	down := TokenClient{Authority: "http://127.0.0.1:1", HTTP: srv.Client()}.ClientCredentials(ctx, testTenant, testApp, testSecret, ARMScope)
	if down.OK || down.Rejected() || down.Error == "" {
		t.Fatalf("transport failure probe %+v", down)
	}
}

func TestAnalyzeFindsStableRejection(t *testing.T) {
	ok := Probe{OK: true, Status: 200}
	rej := Probe{Status: 401, Error: "invalid_client"}
	flaky := Probe{Status: 0, Error: "transport: reset"}
	at := func(p Probe, ms float64) Probe { p.AtMs = ms; return p }
	s := Analyze([]Probe{at(ok, 0), at(ok, 500), at(rej, 1000), at(flaky, 1500), at(ok, 2000), at(rej, 2500), at(rej, 3000)})
	if s.FirstRejectMs == nil || *s.FirstRejectMs != 1000 || s.LastSuccessMs == nil || *s.LastSuccessMs != 2000 ||
		s.StableRejectMs == nil || *s.StableRejectMs != 2500 || s.SuccessesAfterFirstReject != 1 || s.Inconclusive != 1 || s.Probes != 7 {
		t.Fatalf("series %+v", s)
	}
	if s := Analyze([]Probe{at(ok, 0), at(ok, 500)}); s.FirstRejectMs != nil || s.StableRejectMs != nil {
		t.Fatalf("never rejected, got %+v", s)
	}
}

func TestAnalyzeAcceptanceFindsStableSuccess(t *testing.T) {
	ok := Probe{OK: true, Status: 200}
	rej := Probe{Status: 401, Error: "invalid_client"}
	busy := Probe{Status: 503, Error: "temporarily_unavailable"}
	at := func(p Probe, ms float64) Probe { p.AtMs = ms; return p }
	a := AnalyzeAcceptance([]Probe{at(rej, 0), at(ok, 1000), at(rej, 2000), at(busy, 3000), at(ok, 4000), at(ok, 5000)})
	if a.FirstOKMs == nil || *a.FirstOKMs != 1000 || a.LastRejectMs == nil || *a.LastRejectMs != 2000 ||
		a.StableOKMs == nil || *a.StableOKMs != 4000 || a.RejectsAfterFirstOK != 1 || a.Inconclusive != 1 || a.Probes != 6 {
		t.Fatalf("acceptance %+v", a)
	}
}

func TestStableWindow(t *testing.T) {
	ok := Probe{OK: true, Status: 200}
	rej := Probe{Status: 401, Error: "invalid_client"}
	busy := Probe{Status: 0, Error: "transport: reset"}
	t0 := time.Unix(1000, 0)
	s := Stable{WantOK: false, Window: time.Minute}
	steps := []struct {
		p    Probe
		at   time.Duration
		done bool
	}{
		{rej, 0, false}, {busy, 10 * time.Second, false}, {ok, 20 * time.Second, false}, // success resets
		{rej, 30 * time.Second, false}, {busy, 60 * time.Second, false}, {rej, 89 * time.Second, false},
		{rej, 90 * time.Second, true},
	}
	for i, st := range steps {
		if got := s.Observe(st.p, t0.Add(st.at)); got != st.done {
			t.Fatalf("step %d (%v at %v): done=%v", i, st.p.OK, st.at, got)
		}
	}
	if s.Since() != t0.Add(30*time.Second) {
		t.Fatalf("stable since %v", s.Since())
	}
	acc := Stable{WantOK: true, Window: time.Minute}
	if acc.Observe(ok, t0) || acc.Observe(rej, t0.Add(59*time.Second)) || acc.Observe(ok, t0.Add(60*time.Second)) ||
		!acc.Observe(ok, t0.Add(120*time.Second)) {
		t.Fatal("acceptance window must restart after a refusal")
	}
}

func TestStatsNearestRank(t *testing.T) {
	s := Stats([]float64{5, 1, 4, 2, 3})
	if s["p50"] != 3 || s["p95"] != 5 || s["min"] != 1 || s["max"] != 5 || s["n"] != 5 {
		t.Fatalf("stats %v", s)
	}
	if Stats(nil) != nil {
		t.Fatal("empty stats")
	}
}

func TestGraphCredentialPresent(t *testing.T) {
	keys := []string{"k1", "k2"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" || r.URL.Path != "/v1.0/applications/obj" ||
			r.URL.Query().Get("$select") != "passwordCredentials" {
			w.WriteHeader(403)
			return
		}
		var creds []map[string]string
		for _, k := range keys {
			creds = append(creds, map[string]string{"keyId": k})
		}
		json.NewEncoder(w).Encode(map[string]any{"passwordCredentials": creds})
	}))
	defer srv.Close()
	g := Graph{Base: srv.URL, Token: "graph-token", HTTP: srv.Client()}
	if present, err := g.CredentialPresent(context.Background(), "obj", "k2"); err != nil || !present {
		t.Fatalf("k2 present=%v err=%v", present, err)
	}
	keys = []string{"k1"}
	if present, err := g.CredentialPresent(context.Background(), "obj", "k2"); err != nil || present {
		t.Fatalf("k2 after delete present=%v err=%v", present, err)
	}
	if _, err := (Graph{Base: srv.URL, Token: "wrong", HTTP: srv.Client()}).CredentialPresent(context.Background(), "obj", "k2"); err == nil {
		t.Fatal("HTTP 403 reported as an answer")
	}
}

func TestRedactAndLeakCheck(t *testing.T) {
	raw := []byte(`{"tenant":"` + testTenant + `","owner":"OID-1"}`)
	out := Redact(raw, map[string]string{testTenant: "<tenant-id>", "OID-1": "<user-oid>", "": "<empty>"})
	if string(out) != `{"tenant":"<tenant-id>","owner":"<user-oid>"}` {
		t.Fatalf("redacted %s", out)
	}
	if err := LeakCheck(out, []string{testSecret, testToken, ""}); err != nil {
		t.Fatal(err)
	}
	if err := LeakCheck([]byte("x"+testSecret[:20]+"y"), []string{testSecret}); err == nil {
		t.Fatal("a 20-character prefix of a secret passed the leak check")
	}
}

func TestAzRunsWithMinimalEnvironment(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "az")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + dir + "/args\nenv > " + dir + "/env\n[ \"$1\" = fail ] && { echo 'ERROR: boom' >&2; exit 3; }\necho '{\"ok\":true}'\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_SHOULD_NOT_LEAK", "1")
	az := Az{Path: fake, ConfigDir: "/cfg/.azure"}
	out, err := az.Run(context.Background(), "ad", "app", "show")
	if err != nil || strings.TrimSpace(string(out)) != `{"ok":true}` {
		t.Fatalf("out %q err %v", out, err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if string(args) != "ad\napp\nshow\n--only-show-errors\n" {
		t.Fatalf("args %q", args)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if !strings.Contains(string(env), "AZURE_CONFIG_DIR=/cfg/.azure") || strings.Contains(string(env), "WARDEN_SHOULD_NOT_LEAK") {
		t.Fatalf("env %s", env)
	}
	if _, err := az.Run(context.Background(), "fail"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failure: %v", err)
	}
	if _, err := (Az{Path: "az", ConfigDir: "/cfg"}).Run(context.Background(), "x"); err == nil {
		t.Fatal("relative az path accepted")
	}
}

func TestPlaybookFileParses(t *testing.T) {
	raw, err := os.ReadFile("../playbooks/disable-azure-app-credential.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := respond.ParsePlaybook(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Name != respond.DisableAzureServicePrincipalCredential || p.Steps[0].Resource.Type != "azure_app_credential" ||
		p.Steps[0].Resource.ID != "" || p.RequiresApproval || p.Trigger != Trigger {
		t.Fatalf("playbook %+v", p)
	}
}

func TestSourceStateRecordsCommitAndDirtyState(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
			"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "a.txt")
	git("commit", "-q", "-m", "a")
	s, err := SourceState(context.Background(), dir)
	if err != nil || len(s.Commit) != 40 || len(s.TrackedChanges) != 0 || len(s.Untracked) != 0 {
		t.Fatalf("clean checkout: %+v %v", s, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := SourceState(context.Background(), dir)
	if err != nil || s2.Commit != s.Commit || strings.Join(s2.TrackedChanges, ",") != " M a.txt" || strings.Join(s2.Untracked, ",") != "new.go" {
		t.Fatalf("dirty checkout: %+v %v", s2, err)
	}
	raw, _ := json.Marshal(s2)
	if !strings.Contains(string(raw), `"commit":"`+s.Commit+`"`) || !strings.Contains(string(raw), `"untracked":["new.go"]`) {
		t.Fatalf("serialized %s", raw)
	}
	if _, err := SourceState(context.Background(), "/"); err == nil {
		t.Fatal("a directory outside any checkout gave a source state")
	}
}
