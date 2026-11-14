package azurelab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/respond"
)

const (
	appPrefix     = "warden-lab-respond"
	graphBase     = "https://graph.microsoft.com"
	labTenant     = "warden-lab" // the alert's Warden tenant, not the Entra tenant
	probeInterval = time.Second
	graphInterval = 200 * time.Millisecond
	// The token service answers from several instances that learn about a
	// changed app at different times (run0 of 2026-11-10), so "works" and
	// "refused" both mean: the same answer to every conclusive probe for a
	// whole minute.
	stableWindow  = time.Minute
	activationCap = 20 * time.Minute
	rejectCap     = 30 * time.Minute
)

type lab struct {
	ctx    context.Context
	az     Az
	tc     TokenClient
	hc     *http.Client
	tenant string

	mu      sync.Mutex
	secrets []string
}

func (l *lab) keep(secret string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, secret)
}

func (l *lab) text(args ...string) (string, error) {
	out, err := l.az.Run(l.ctx, args...)
	return strings.TrimSpace(string(out)), err
}

// decode runs az until it succeeds (Graph is eventually consistent right
// after an object is created) and unmarshals its JSON.
func (l *lab) decode(v any, tries int, args ...string) error {
	var err error
	for i := 0; i < tries; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		var out []byte
		if out, err = l.az.Run(l.ctx, args...); err == nil {
			if err = json.Unmarshal(out, v); err == nil {
				return nil
			}
		}
	}
	return err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func loadavg() string {
	la, _ := os.ReadFile("/proc/loadavg")
	return strings.TrimSpace(string(la))
}

func ptr(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// arm calls ARM with an app token. The lab apps have no Azure role, so a
// working token lists zero subscriptions; only status and count are kept.
func (l *lab) arm(token string) map[string]any {
	req, _ := http.NewRequestWithContext(l.ctx, http.MethodGet, "https://management.azure.com/subscriptions?api-version=2022-12-01", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := l.hc.Do(req)
	if err != nil {
		return map[string]any{"error": "transport"}
	}
	defer resp.Body.Close()
	var body struct {
		Value []json.RawMessage `json:"value"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	return map[string]any{"status": resp.StatusCode, "subscriptions": len(body.Value)}
}

// poll asks for a token every probeInterval from t0 until the answer has been
// stable for stableWindow (true) or cap passes (false). It returns the probes
// (without tokens) and the newest access token it received.
func (l *lab) poll(t0 time.Time, clientID, secret string, wantOK bool, limit time.Duration) ([]Probe, bool, string) {
	var probes []Probe
	var token string
	s := Stable{WantOK: wantOK, Window: stableWindow}
	next := t0
	for {
		time.Sleep(time.Until(next))
		start := time.Now()
		next = start.Add(probeInterval)
		p := l.tc.ClientCredentials(l.ctx, l.tenant, clientID, secret, ARMScope)
		if p.OK {
			token = p.Token()
			l.keep(token)
		}
		p.AtMs, p.token = Ms(start.Sub(t0)), ""
		probes = append(probes, p)
		if s.Observe(p, start) {
			return probes, true, token
		}
		if time.Since(t0) > limit {
			return probes, false, token
		}
	}
}

type entraObject struct {
	ID      string `json:"id"`
	AppID   string `json:"appId"`
	Created string `json:"createdDateTime,omitempty"`
}

type shared struct {
	ex       *respond.Executor
	adapter  respond.AzureCLI
	pb       respond.Playbook
	tags     []string
	runStart time.Time
}

// rep runs one repetition on its own app and always deletes the app.
func (l *lab) rep(i int, sh shared) (rep map[string]any, fails []string) {
	rep = map[string]any{"rep": i}
	fail := func(format string, args ...any) {
		fails = append(fails, fmt.Sprintf("rep %d: ", i)+fmt.Sprintf(format, args...))
	}
	name := fmt.Sprintf("%s-%d", appPrefix, i)
	var app, sp entraObject
	objects := map[string]any{}
	rep["objects"] = objects
	defer func() { l.cleanup(app, sp, objects) }()

	body, _ := json.Marshal(map[string]any{"displayName": name, "signInAudience": "AzureADMyOrg", "tags": sh.tags})
	if err := l.decode(&app, 1, "rest", "--method", "POST", "--uri", graphBase+"/v1.0/applications", "--body", string(body),
		"--query", "{id:id,appId:appId,createdDateTime:createdDateTime}", "-o", "json"); err != nil || app.ID == "" {
		fail("create application: %v", err)
		return
	}
	objects["application"] = map[string]any{"display_name": name, "object_id": app.ID, "app_id": app.AppID, "created": app.Created, "tags": sh.tags}
	fmt.Printf("rep %d: created application %s (appId %s); if this run dies: az ad app delete --id %s\n", i, app.ID, app.AppID, app.ID)
	body, _ = json.Marshal(map[string]any{"appId": app.AppID, "tags": sh.tags})
	if err := l.decode(&sp, 15, "rest", "--method", "POST", "--uri", graphBase+"/v1.0/servicePrincipals", "--body", string(body),
		"--query", "{id:id,appId:appId}", "-o", "json"); err != nil || sp.ID == "" {
		fail("create service principal: %v", err)
		return
	}
	objects["service_principal"] = map[string]any{"object_id": sp.ID, "created_by_test_at": time.Now().UTC().Format(time.RFC3339Nano)}
	var owned []string
	for t := 0; t < 15 && len(owned) == 0; t++ {
		if t > 0 {
			time.Sleep(2 * time.Second)
		}
		l.decode(&owned, 1, "ad", "app", "list", "--show-mine", "--query", "[?id=='"+app.ID+"'].id", "-o", "json")
	}
	if len(owned) != 1 {
		fail("application not owned by the signed-in user")
		return
	}
	objects["owned_by_signed_in_user"] = true

	var cred struct {
		KeyID  string `json:"keyId"`
		Secret string `json:"secretText"`
		Start  string `json:"startDateTime"`
		End    string `json:"endDateTime"`
	}
	body, _ = json.Marshal(map[string]any{"passwordCredential": map[string]any{
		"displayName": name + " secret", "endDateTime": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)}})
	if err := l.decode(&cred, 15, "rest", "--method", "POST", "--uri", graphBase+"/v1.0/applications/"+app.ID+"/addPassword", "--body", string(body),
		"--query", "{keyId:keyId,secretText:secretText,startDateTime:startDateTime,endDateTime:endDateTime}", "-o", "json"); err != nil || cred.Secret == "" {
		fail("addPassword: %v", err)
		return
	}
	l.keep(cred.Secret)
	rep["key_id"], rep["secret_start"], rep["secret_end"] = cred.KeyID, cred.Start, cred.End

	// 1. The secret works: every conclusive token request succeeds for a minute.
	added := time.Now()
	probes, ok, token := l.poll(added, app.AppID, cred.Secret, true, activationCap)
	acc := AnalyzeAcceptance(probes)
	rep["activation"], rep["activation_probes"] = acc, probes
	if !ok {
		fail("secret not stably accepted within %v: %+v", activationCap, acc)
		return
	}
	issued := time.Now()
	rep["arm_with_token_before_alert"] = l.arm(token)

	alert := respond.Alert{ID: fmt.Sprintf("azcred-%d-%d", sh.runStart.Unix(), i), RuleID: sh.pb.Trigger, TenantID: labTenant,
		Resource: respond.Resource{Type: "azure_app_credential", ID: app.ID + "/" + cred.KeyID}}
	rep["alert_id"] = alert.ID
	gtok, err := l.text("account", "get-access-token", "--resource-type", "ms-graph", "--query", "accessToken", "-o", "tsv")
	if err != nil {
		fail("graph token: %v", err)
		return
	}
	l.keep(gtok)
	graph := Graph{Token: gtok, HTTP: l.hc}

	// 2. Dry run: nothing changes.
	res, err := sh.ex.Handle(alert, true)
	present, perr := graph.CredentialPresent(l.ctx, app.ID, cred.KeyID)
	after := l.tc.ClientCredentials(l.ctx, l.tenant, app.AppID, cred.Secret, ARMScope)
	l.keep(after.Token())
	rep["dry_run"] = map[string]any{"status": res.Status, "err": errString(err), "credential_still_listed": present,
		"graph_err": errString(perr), "token_after": after}
	if res.Status != respond.Preview || err != nil || perr != nil || !present || !after.OK {
		fail("dry run was not a pure preview: %v", rep["dry_run"])
	}

	// 3. The real alert.
	t0 := time.Now()
	type polled struct {
		probes []Probe
		ok     bool
	}
	ch := make(chan polled, 1)
	go func() { p, ok, _ := l.poll(t0, app.AppID, cred.Secret, false, rejectCap); ch <- polled{p, ok} }()
	res, err = sh.ex.Handle(alert, false)
	h := Ms(time.Since(t0))
	rep["handle"] = map[string]any{"ms": h, "status": res.Status, "noop": res.NoOp, "err": errString(err)}
	if res.Status != respond.Completed || err != nil || res.NoOp {
		fail("Handle %s %v", res.Status, err)
	}
	gone, polls, graphErrs := -1.0, 0, 0
	for time.Since(t0) < 2*time.Minute {
		polls++
		at := time.Now()
		present, gerr := graph.CredentialPresent(l.ctx, app.ID, cred.KeyID)
		if gerr != nil {
			graphErrs++
		} else if !present {
			gone = Ms(at.Sub(t0))
			break
		}
		time.Sleep(graphInterval)
	}
	rep["graph"] = map[string]any{"absent_ms": gone, "polls": polls, "errors": graphErrs}
	if gone < 0 {
		fail("Graph still lists the secret 2 min after the alert")
	}
	pr := <-ch
	series := Analyze(pr.probes)
	rep["token_after_alert"], rep["token_after_alert_stable"], rep["token_probes"] = series, pr.ok, pr.probes
	if !pr.ok {
		fail("deleted secret not stably refused within %v: %d successes after the first refusal, last success at %v ms",
			rejectCap, series.SuccessesAfterFirstReject, ptr(series.LastSuccessMs))
	}

	// 4. The same alert again is a no-op; another alert for the same, already
	// deleted credential runs the adapter again and must also complete.
	r0 := time.Now()
	rr, rerr := sh.ex.Handle(alert, false)
	rep["replay"] = map[string]any{"ms": Ms(time.Since(r0)), "status": rr.Status, "noop": rr.NoOp, "err": errString(rerr)}
	if !rr.NoOp || rr.Status != respond.Completed || rerr != nil {
		fail("replayed alert was not a completed no-op: %v", rep["replay"])
	}
	again := alert
	again.ID += "-again"
	a0 := time.Now()
	ra, aerr := sh.ex.Handle(again, false)
	rep["distinct_alert_same_deleted_credential"] = map[string]any{"ms": Ms(time.Since(a0)), "status": ra.Status, "noop": ra.NoOp, "err": errString(aerr)}
	if ra.Status != respond.Completed || aerr != nil {
		fail("second alert for the deleted credential: %s %v", ra.Status, aerr)
	}
	rep["arm_with_token_issued_before_alert"] = map[string]any{"result": l.arm(token),
		"token_age_s": time.Since(issued).Seconds()}
	fmt.Printf("rep %d: handle %.1f ms, graph absent %.1f ms, token refused first %v ms, stable %v ms (confirmed %v), %d successes after first refusal\n",
		i, h, gone, ptr(series.FirstRejectMs), ptr(series.StableRejectMs), pr.ok, series.SuccessesAfterFirstReject)
	return rep, fails
}

// cleanup deletes the service principal and the application and records
// what Entra says afterwards, by exact object ID only.
func (l *lab) cleanup(app, sp entraObject, objects map[string]any) {
	ctx := context.Background()
	stamp := func() string { return time.Now().UTC().Format(time.RFC3339Nano) }
	check := map[string]any{}
	objects["cleanup"] = check
	if sp.ID != "" {
		_, err := l.az.Run(ctx, "ad", "sp", "delete", "--id", sp.ID)
		check["sp_delete"] = map[string]any{"at": stamp(), "err": errString(err)}
	}
	if app.ID == "" {
		return
	}
	_, err := l.az.Run(ctx, "ad", "app", "delete", "--id", app.ID)
	check["app_delete"] = map[string]any{"at": stamp(), "err": errString(err)}
	for _, o := range []struct{ kind, id string }{{"app", app.ID}, {"sp", sp.ID}} {
		if o.id == "" {
			continue
		}
		_, err := l.az.Run(ctx, "ad", o.kind, "show", "--id", o.id)
		check[o.kind+"_show_after"] = map[string]any{"at": stamp(), "err": errString(err)}
		var item map[string]any
		err = l.decode(&item, 5, "rest", "--method", "GET", "--uri", graphBase+"/v1.0/directory/deletedItems/"+o.id,
			"--query", `{type:"@odata.type",id:id,displayName:displayName,deletedDateTime:deletedDateTime}`, "-o", "json")
		check[o.kind+"_deleted_item"] = map[string]any{"item": item, "err": errString(err)}
	}
}

// TestLiveDisableAzureAppCredential: WARDEN_AZURE_REPS (default 5) throwaway
// apps owned by the signed-in user, in parallel, each with one client secret.
// Once the secret has worked for a minute, an alert naming it goes through
// respond.Executor with the real AzureCLI adapter: dry run, real, the same
// alert again (no-op), and a second alert for the deleted credential.
// Measured from the alert reaching the executor: Handle returning, Graph no
// longer listing the secret, and Entra refusing the secret (invalid_client)
// first and then for a whole minute. Every app is deleted at the end.
func TestLiveDisableAzureAppCredential(t *testing.T) {
	if os.Getenv("WARDEN_LIVE_AZURE") != "1" {
		t.Skip("live Azure test: run `make test-azure-respond`")
	}
	azPath, cfg := os.Getenv("WARDEN_AZ"), os.Getenv("AZURE_CONFIG_DIR")
	if !filepath.IsAbs(azPath) || !filepath.IsAbs(cfg) {
		t.Fatal("WARDEN_AZ and AZURE_CONFIG_DIR must be absolute paths")
	}
	reps := 5
	if v := os.Getenv("WARDEN_AZURE_REPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10 {
			t.Fatal("WARDEN_AZURE_REPS must be 1..10")
		}
		reps = n
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	l := &lab{ctx: context.Background(), az: Az{Path: azPath, ConfigDir: cfg}, tc: TokenClient{HTTP: hc}, hc: hc}
	runStart := time.Now()
	result := map[string]any{"test": t.Name(), "started": runStart.UTC().Format(time.RFC3339Nano),
		"go": runtime.Version(), "host_load_start": loadavg(), "token_scope": ARMScope, "reps_in_parallel": reps,
		"poll": map[string]any{"token_interval_ms": probeInterval.Milliseconds(), "graph_interval_ms": graphInterval.Milliseconds(),
			"stable_window_s": stableWindow.Seconds(), "activation_cap_s": activationCap.Seconds(), "reject_cap_s": rejectCap.Seconds()}}
	must := func(args ...string) string {
		s, err := l.text(args...)
		if err != nil || s == "" {
			t.Fatalf("az %s: %v", strings.Join(args[:2], " "), err)
		}
		return s
	}
	// Provenance before any Entra object exists: the run is only as good as
	// the source it can name.
	src, err := SourceState(l.ctx, ".")
	if err != nil {
		t.Fatalf("source state: %v", err)
	}
	result["source"] = src
	result["az_version"] = must("version", "--query", `"azure-cli"`, "-o", "tsv")
	l.tenant = must("account", "show", "--query", "tenantId", "-o", "tsv")
	redact := map[string]string{l.tenant: "<tenant-id>",
		must("account", "show", "--query", "id", "-o", "tsv"):                             "<subscription-id>",
		must("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv"):                "<user-oid>",
		must("ad", "signed-in-user", "show", "--query", "userPrincipalName", "-o", "tsv"): "<user-upn>"}

	raw, err := os.ReadFile("../playbooks/disable-azure-app-credential.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := respond.ParsePlaybook(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := respond.AzureCLI{Az: azPath}
	ex, err := respond.New(respond.Config{Playbook: pb, AllowedTenantIDs: []string{labTenant},
		JournalPath: filepath.Join(dir, "attempts.journal"), Actions: adapter})
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Close()
	result["playbook"] = pb
	sh := shared{ex: ex, adapter: adapter, pb: pb, runStart: runStart,
		tags: []string{"project=warden", "owner=warden-lab", "ttl=" + runStart.UTC().Add(3*time.Hour).Format(time.RFC3339), "est_usd_per_hour=0"}}

	runs := make([]map[string]any, reps)
	fails := make([][]string, reps)
	var wg sync.WaitGroup
	for i := 1; i <= reps; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i-1) * 3 * time.Second) // stagger the az calls
			runs[i-1], fails[i-1] = l.rep(i, sh)
		}(i)
	}
	wg.Wait()
	result["reps"] = runs
	var failures []string
	for _, f := range fails {
		failures = append(failures, f...)
	}

	collect := func(get func(map[string]any) (float64, bool)) []float64 {
		var v []float64
		for _, r := range runs {
			if x, ok := get(r); ok {
				v = append(v, x)
			}
		}
		return v
	}
	num := func(path ...string) func(map[string]any) (float64, bool) {
		return func(r map[string]any) (float64, bool) {
			var cur any = r
			for _, k := range path {
				m, ok := cur.(map[string]any)
				if !ok {
					return 0, false
				}
				cur = m[k]
			}
			x, ok := cur.(float64)
			return x, ok && x >= 0
		}
	}
	series := func(field func(Series) *float64, stableOnly bool) func(map[string]any) (float64, bool) {
		return func(r map[string]any) (float64, bool) {
			s, ok := r["token_after_alert"].(Series)
			if !ok || field(s) == nil || stableOnly && r["token_after_alert_stable"] != true {
				return 0, false
			}
			return *field(s), true
		}
	}
	activation := func(field func(Acceptance) *float64) func(map[string]any) (float64, bool) {
		return func(r map[string]any) (float64, bool) {
			a, ok := r["activation"].(Acceptance)
			if !ok || field(a) == nil {
				return 0, false
			}
			return *field(a), true
		}
	}
	result["summary"] = map[string]any{
		"handle_ms":                            Stats(collect(num("handle", "ms"))),
		"alert_to_graph_absent_ms":             Stats(collect(num("graph", "absent_ms"))),
		"alert_to_first_token_refusal_ms":      Stats(collect(series(func(s Series) *float64 { return s.FirstRejectMs }, false))),
		"alert_to_stable_token_refusal_ms":     Stats(collect(series(func(s Series) *float64 { return s.StableRejectMs }, true))),
		"alert_to_last_token_success_ms":       Stats(collect(series(func(s Series) *float64 { return s.LastSuccessMs }, false))),
		"secret_added_to_first_token_ms":       Stats(collect(activation(func(a Acceptance) *float64 { return a.FirstOKMs }))),
		"secret_added_to_stable_token_ms":      Stats(collect(activation(func(a Acceptance) *float64 { return a.StableOKMs }))),
		"replay_ms":                            Stats(collect(num("replay", "ms"))),
		"distinct_alert_deleted_credential_ms": Stats(collect(num("distinct_alert_same_deleted_credential", "ms"))),
	}
	var mine []string
	for i := 0; i < 10; i++ {
		mine = nil
		if l.decode(&mine, 1, "ad", "app", "list", "--show-mine", "--query", "[?starts_with(displayName,'warden-lab-')].displayName", "-o", "json") == nil && len(mine) == 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	result["show_mine_warden_lab_apps_after"] = mine
	if len(mine) != 0 {
		failures = append(failures, fmt.Sprintf("warden-lab- apps still listed by --show-mine: %v", mine))
	}
	result["finished"] = time.Now().UTC().Format(time.RFC3339Nano)
	result["host_load_end"] = loadavg()
	result["failures"] = failures
	result["pass"] = len(failures) == 0

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = Redact(out, redact)
	l.mu.Lock()
	leak := LeakCheck(out, l.secrets)
	l.mu.Unlock()
	if leak != nil {
		t.Fatal(errors.Join(leak, errors.New("result not written")))
	}
	if p := os.Getenv("AZURE_OUT"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Error(err)
		}
	}
	summary, _ := json.Marshal(result["summary"])
	t.Logf("summary %s", Redact(summary, redact))
	for _, f := range failures {
		t.Error(f)
	}
}
