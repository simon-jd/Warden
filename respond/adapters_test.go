package respond

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"warden/identity/vault"
)

type recorded struct {
	Method, Path, ContentType, Auth string
	Body                            map[string]any
}

func recorder(t *testing.T, status int) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.Header.Get("X-Vault-Token")
		}
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.Path, r.Header.Get("Content-Type"), auth, body})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestVaultLeasesRevokesThroughVaultAPI(t *testing.T) {
	srv, got := recorder(t, http.StatusNoContent)
	v := VaultLeases{Client: &vault.Client{Addr: srv.URL, Token: "test-token"}}
	lease := "database/creds/warden-app/Xy3kP9qL2mN8"
	if err := v.Contain(context.Background(), Action{Name: RevokeVaultLease, Resource: Resource{Type: "vault_lease", ID: lease}}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("requests %+v", *got)
	}
	r := (*got)[0]
	if r.Method != http.MethodPut || r.Path != "/v1/sys/leases/revoke" || r.Body["lease_id"] != lease || r.Auth != "test-token" {
		t.Fatalf("request %+v", r)
	}
	if err := v.Contain(context.Background(), Action{Name: CordonNode, Resource: Resource{Type: "node", ID: "n"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong action accepted: %v", err)
	}
}

func TestKubernetesIsolatePodAndCordonNode(t *testing.T) {
	srv, got := recorder(t, http.StatusOK)
	k := Kubernetes{Server: srv.URL, Token: "sa-token"}
	ctx := context.Background()
	if err := k.Contain(ctx, Action{Name: IsolatePod, Resource: Resource{Type: "pod", ID: "tenant-a-sandbox/run-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := k.Contain(ctx, Action{Name: CordonNode, Resource: Resource{Type: "node", ID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("requests %+v", *got)
	}
	pod, node := (*got)[0], (*got)[1]
	labels, _ := pod.Body["metadata"].(map[string]any)["labels"].(map[string]any)
	if pod.Method != http.MethodPatch || pod.Path != "/api/v1/namespaces/tenant-a-sandbox/pods/run-1" ||
		pod.ContentType != "application/merge-patch+json" || pod.Auth != "Bearer sa-token" || labels[QuarantineLabel] != "true" {
		t.Fatalf("isolate request %+v", pod)
	}
	spec, _ := node.Body["spec"].(map[string]any)
	if node.Method != http.MethodPatch || node.Path != "/api/v1/nodes/node-1" || spec["unschedulable"] != true {
		t.Fatalf("cordon request %+v", node)
	}

	failing, _ := recorder(t, http.StatusForbidden)
	if err := (Kubernetes{Server: failing.URL, Token: "t"}).Contain(ctx, Action{Name: CordonNode, Resource: Resource{Type: "node", ID: "node-1"}}); err == nil {
		t.Fatal("403 from the API server reported as success")
	}
	if err := (Kubernetes{Server: "http://10.0.0.1:6443", Token: "t"}).Contain(ctx, Action{Name: CordonNode, Resource: Resource{Type: "node", ID: "node-1"}}); err == nil {
		t.Fatal("plain http to a non-loopback API server accepted")
	}
	if err := k.Contain(ctx, Action{Name: IsolatePod, Resource: Resource{Type: "pod", ID: "../x"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid pod accepted: %v", err)
	}
}

func fakeAz(t *testing.T, exit int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\nexit " + string(rune('0'+exit)) + "\n"
	path := filepath.Join(dir, "az")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, args
}

func TestAzureCLIDeletesAppCredential(t *testing.T) {
	az, argsFile := fakeAz(t, 0)
	app, key := "3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f", "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	a := Action{Name: DisableAzureServicePrincipalCredential, Resource: Resource{Type: "azure_app_credential", ID: app + "/" + key}}
	if err := (AzureCLI{Az: az}).Contain(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "ad\napp\ncredential\ndelete\n--id\n" + app + "\n--key-id\n" + key + "\n--only-show-errors\n"
	if string(raw) != want {
		t.Fatalf("az args %q, want %q", raw, want)
	}
	failing, _ := fakeAz(t, 3)
	if err := (AzureCLI{Az: failing}).Contain(context.Background(), a); err == nil {
		t.Fatal("az exit 3 reported as success")
	}
	if err := (AzureCLI{Az: "az"}).Contain(context.Background(), a); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative az path accepted: %v", err)
	}
}

// azCase is one answer of fakeAzCases: when the arguments of a call ("$*")
// are exactly args, print stdout and stderr and exit with exit.
type azCase struct {
	args, stdout, stderr string
	exit                 int
}

// fakeAzCases is an az that logs every call (one line, arguments joined by
// spaces) and answers only the calls listed; any other call exits 97.
func fakeAzCases(t *testing.T, cases ...azCase) (az, calls string) {
	t.Helper()
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + calls + "\ncase \"$*\" in\n"
	for i, c := range cases {
		out, errOut := filepath.Join(dir, fmt.Sprintf("out%d", i)), filepath.Join(dir, fmt.Sprintf("err%d", i))
		if os.WriteFile(out, []byte(c.stdout), 0o600) != nil || os.WriteFile(errOut, []byte(c.stderr), 0o600) != nil {
			t.Fatal("write fake az answer")
		}
		script += fmt.Sprintf("%q) cat %s; cat %s >&2; exit %d ;;\n", c.args, out, errOut, c.exit)
	}
	script += "*) echo \"unexpected az call: $*\" >&2; exit 97 ;;\nesac\n"
	az = filepath.Join(dir, "az")
	if err := os.WriteFile(az, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return az, calls
}

func azCalls(t *testing.T, calls string) []string {
	t.Helper()
	raw, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

const (
	testApp = "3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f"
	testKey = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
)

var (
	azDeletePassword = "ad app credential delete --id " + testApp + " --key-id " + testKey + " --only-show-errors"
	azDeleteCert     = "ad app credential delete --id " + testApp + " --key-id " + testKey + " --cert --only-show-errors"
	azShowApp        = "ad app show --id " + testApp + " --only-show-errors -o json"
	azListFederated  = "ad app federated-credential list --id " + testApp + " --only-show-errors -o json"
	// Graph's removePassword answer (az 2.91.0/2.92.0) for any keyId that is
	// not one of the app's password credentials: an already deleted secret,
	// but just as well a certificate or a federated credential.
	noPassword = "ERROR: No password credential found with keyId as '" + testKey + "'.\n"
)

func appJSON(passwords, certificates []string) string {
	creds := func(ids []string) []map[string]any {
		out := []map[string]any{}
		for _, id := range ids {
			out = append(out, map[string]any{"keyId": id, "displayName": "x"})
		}
		return out
	}
	raw, _ := json.Marshal(map[string]any{"id": testApp, "passwordCredentials": creds(passwords), "keyCredentials": creds(certificates)})
	return string(raw)
}

func federatedJSON(ids ...string) string {
	out := []map[string]any{}
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "name": "gh"})
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}

func azureAction() Action {
	return Action{Name: DisableAzureServicePrincipalCredential, Resource: Resource{Type: "azure_app_credential", ID: testApp + "/" + testKey}}
}

// "No password credential found" is containment only once the app lists the
// key nowhere: not as a password, not as a certificate, not as a federated
// credential (the action must be idempotent, but not blind).
func TestAzureCLIMissingPasswordIsContainedOnlyWhenListedNowhere(t *testing.T) {
	other := "0a0a0a0a-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	az, calls := fakeAzCases(t,
		azCase{args: azDeletePassword, stderr: noPassword, exit: 1},
		azCase{args: azShowApp, stdout: appJSON([]string{other}, []string{other})},
		azCase{args: azListFederated, stdout: federatedJSON(other)})
	if err := (AzureCLI{Az: az}).Contain(context.Background(), azureAction()); err != nil {
		t.Fatalf("credential listed nowhere: %v", err)
	}
	if got := azCalls(t, calls); strings.Join(got, "|") != strings.Join([]string{azDeletePassword, azShowApp, azListFederated}, "|") {
		t.Fatalf("az calls %q", got)
	}
	// The same answer for another key, or an authorization failure, is no proof.
	for _, msg := range []string{"ERROR: No password credential found with keyId as '" + other + "'.", "ERROR: Insufficient privileges to complete the operation."} {
		az, _ := fakeAzCases(t, azCase{args: azDeletePassword, stderr: msg, exit: 1},
			azCase{args: azShowApp, stdout: appJSON(nil, nil)}, azCase{args: azListFederated, stdout: federatedJSON()})
		if err := (AzureCLI{Az: az}).Contain(context.Background(), azureAction()); err == nil {
			t.Fatalf("%q counted as contained", msg)
		}
	}
}

// A certificate keyId gets the same removePassword answer; it is removed
// with --cert, and only that call's success counts.
func TestAzureCLIDeletesCertificateCredentialWithCert(t *testing.T) {
	for _, certExit := range []int{0, 1} {
		az, calls := fakeAzCases(t,
			azCase{args: azDeletePassword, stderr: noPassword, exit: 1},
			azCase{args: azShowApp, stdout: appJSON(nil, []string{testKey})},
			azCase{args: azDeleteCert, stderr: map[int]string{1: "ERROR: Insufficient privileges to complete the operation."}[certExit], exit: certExit})
		err := (AzureCLI{Az: az}).Contain(context.Background(), azureAction())
		if (err == nil) != (certExit == 0) {
			t.Fatalf("certificate delete exit %d: %v", certExit, err)
		}
		if got := azCalls(t, calls); strings.Join(got, "|") != strings.Join([]string{azDeletePassword, azShowApp, azDeleteCert}, "|") {
			t.Fatalf("az calls %q", got)
		}
	}
}

// A federated identity credential is another object and another command;
// this action does not remove it and says so.
func TestAzureCLIRefusesFederatedCredential(t *testing.T) {
	az, _ := fakeAzCases(t,
		azCase{args: azDeletePassword, stderr: noPassword, exit: 1},
		azCase{args: azShowApp, stdout: appJSON(nil, nil)},
		azCase{args: azListFederated, stdout: federatedJSON(testKey)})
	err := (AzureCLI{Az: az}).Contain(context.Background(), azureAction())
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "federated") {
		t.Fatalf("federated credential: %v", err)
	}
}

// When the app still lists the password, or cannot be read, nothing is proven.
func TestAzureCLIMissingPasswordUnprovenIsNotContained(t *testing.T) {
	for name, cases := range map[string][]azCase{
		"password still listed": {{args: azShowApp, stdout: appJSON([]string{testKey}, nil)}, {args: azListFederated, stdout: federatedJSON()}},
		"app unreadable":        {{args: azShowApp, stderr: "ERROR: Insufficient privileges to complete the operation.", exit: 1}, {args: azListFederated, stdout: federatedJSON()}},
		"app not JSON":          {{args: azShowApp, stdout: "not json"}, {args: azListFederated, stdout: federatedJSON()}},
		"federated unreadable":  {{args: azShowApp, stdout: appJSON(nil, nil)}, {args: azListFederated, stderr: "ERROR: Forbidden", exit: 1}},
	} {
		az, _ := fakeAzCases(t, append([]azCase{{args: azDeletePassword, stderr: noPassword, exit: 1}}, cases...)...)
		if err := (AzureCLI{Az: az}).Contain(context.Background(), azureAction()); err == nil {
			t.Fatalf("%s counted as contained", name)
		}
	}
}

func TestRouterDispatchesByAction(t *testing.T) {
	pods, nodes := &recordingActions{}, &recordingActions{}
	r := Router{IsolatePod: pods, CordonNode: nodes}
	ctx := context.Background()
	if err := r.Contain(ctx, Action{Name: CordonNode, Resource: Resource{Type: "node", ID: "n1"}}); err != nil {
		t.Fatal(err)
	}
	if len(nodes.calls) != 1 || len(pods.calls) != 0 {
		t.Fatalf("pods %v nodes %v", pods.calls, nodes.calls)
	}
	if err := r.Contain(ctx, Action{Name: RevokeVaultLease}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unrouted action: %v", err)
	}
}
