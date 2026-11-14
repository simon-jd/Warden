package respond

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"warden/identity/vault"
)

// QuarantineLabel marks a pod for policies/cilium/quarantine.yaml, which
// denies all of its ingress and egress (Cilium deny rules win over allows).
const QuarantineLabel = "warden.dev/quarantine"

// Router sends each containment action to the adapter registered for it.
type Router map[ActionName]ActionClient

func (r Router) Contain(ctx context.Context, a Action) error {
	c, ok := r[a.Name]
	if !ok {
		return ErrUnsupported
	}
	return c.Contain(ctx, a)
}

func checkAction(a Action, names ...ActionName) error {
	for _, n := range names {
		if a.Name == n && a.Resource.Type == resourceTypes[n] && validTarget(a.Resource.Type, a.Resource.ID) {
			return nil
		}
	}
	return ErrInvalid
}

// VaultLeases revokes a dynamic-secret lease; Vault then runs the role's
// revocation statements (for the database engine: drop the role, end sessions).
type VaultLeases struct{ Client *vault.Client }

func (v VaultLeases) Contain(ctx context.Context, a Action) error {
	if err := checkAction(a, RevokeVaultLease); err != nil {
		return err
	}
	return v.Client.Revoke(ctx, a.Resource.ID)
}

// Kubernetes labels a pod for quarantine or cordons a node through the API
// server with a JSON merge patch. HTTP must carry the cluster CA for https.
type Kubernetes struct {
	Server string // https://..., or http:// on loopback only
	Token  string
	HTTP   *http.Client
}

func (k Kubernetes) Contain(ctx context.Context, a Action) error {
	if err := checkAction(a, IsolatePod, TerminatePod, CordonNode); err != nil {
		return err
	}
	u, err := url.Parse(k.Server)
	if err != nil || k.Token == "" || !(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return errors.New("kubernetes API must be https, or http on loopback, with a token")
	}
	method, contentType := http.MethodPatch, "application/merge-patch+json"
	var path string
	var payload any
	switch a.Name {
	case IsolatePod, TerminatePod:
		ns, name, _ := strings.Cut(a.Resource.ID, "/")
		path = "/api/v1/namespaces/" + ns + "/pods/" + name
		payload = map[string]any{"metadata": map[string]any{"labels": map[string]string{QuarantineLabel: "true"}}}
		if a.Name == TerminatePod {
			// Grace 0 removes the pod object at once, but the kubelet still
			// sends SIGTERM first: a process that ignores it lives about 2 s
			// more (measured on kind, docs/evidence/time-to-contain.md).
			method, contentType = http.MethodDelete, "application/json"
			payload = map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0}
		}
	default:
		path = "/api/v1/nodes/" + a.Resource.ID
		payload = map[string]any{"spec": map[string]any{"unschedulable": true}}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(k.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+k.Token)
	hc := k.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if a.Name == TerminatePod && resp.StatusCode == http.StatusNotFound {
		return nil // already gone: nothing left running
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kubernetes %s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// AzureCLI removes an Entra application credential: a client secret
// (password) or a certificate. Entra has no "disable" for app credentials;
// deletion is the containment. A federated identity credential is a
// different object with its own command and is not removed here
// (ErrUnsupported). The az login it runs under must itself be short-lived.
type AzureCLI struct{ Az string }

func (z AzureCLI) Contain(ctx context.Context, a Action) error {
	if err := checkAction(a, DisableAzureServicePrincipalCredential); err != nil {
		return err
	}
	if !filepath.IsAbs(z.Az) {
		return errors.New("az must be an absolute path")
	}
	app, key, _ := strings.Cut(a.Resource.ID, "/")
	_, msg, err := z.run(ctx, false, "ad", "app", "credential", "delete", "--id", app, "--key-id", key)
	if err == nil {
		return nil
	}
	// Graph's removePassword gives this answer for every keyId that is not
	// one of the app's password credentials: a secret that is already gone
	// (another alert for the same key, an operator reconciling an Unknown
	// outcome), but just as well a certificate or a federated credential.
	// Only the app's own credential lists tell them apart.
	if !bytes.Contains(msg, []byte("No password credential found with keyId as '"+key+"'")) {
		return azError("az ad app credential delete", err, msg)
	}
	out, msg, err := z.run(ctx, true, "ad", "app", "show", "--id", app)
	if err != nil {
		return azError("az ad app show", err, msg)
	}
	var creds struct {
		Passwords    *[]struct{ KeyID string } `json:"passwordCredentials"`
		Certificates *[]struct{ KeyID string } `json:"keyCredentials"`
	}
	if json.Unmarshal(out, &creds) != nil || creds.Passwords == nil || creds.Certificates == nil {
		return errors.New("az ad app show: no password and key credential lists")
	}
	for _, c := range *creds.Passwords {
		if c.KeyID == key {
			return errors.New("Graph found no password credential " + key + " but the app still lists it")
		}
	}
	for _, c := range *creds.Certificates {
		if c.KeyID == key {
			if _, msg, err := z.run(ctx, false, "ad", "app", "credential", "delete", "--id", app, "--key-id", key, "--cert"); err != nil {
				return azError("az ad app credential delete --cert", err, msg)
			}
			return nil
		}
	}
	out, msg, err = z.run(ctx, true, "ad", "app", "federated-credential", "list", "--id", app)
	if err != nil {
		return azError("az ad app federated-credential list", err, msg)
	}
	var federated []struct{ ID string }
	if json.Unmarshal(out, &federated) != nil {
		return errors.New("az ad app federated-credential list: not a JSON list")
	}
	for _, c := range federated {
		if c.ID == key {
			return fmt.Errorf("%w: %s is a federated identity credential", ErrUnsupported, key)
		}
	}
	return nil // listed nowhere: already gone
}

// run starts az with only PATH, HOME and AZURE_CONFIG_DIR from the caller and
// returns its stdout and stderr separately; asJSON adds "-o json".
func (z AzureCLI) run(ctx context.Context, asJSON bool, args ...string) ([]byte, []byte, error) {
	args = append(append([]string(nil), args...), "--only-show-errors")
	if asJSON {
		args = append(args, "-o", "json")
	}
	cmd := exec.CommandContext(ctx, z.Az, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME")}
	if dir := os.Getenv("AZURE_CONFIG_DIR"); dir != "" {
		cmd.Env = append(cmd.Env, "AZURE_CONFIG_DIR="+dir)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func azError(what string, err error, msg []byte) error {
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return fmt.Errorf("%s: %v: %s", what, err, bytes.TrimSpace(msg))
}
