// Package azurelab is the live Azure drill for respond's
// DisableAzureServicePrincipalCredential (Task 14). The live test in this
// package creates a throwaway Entra app owned by the signed-in az user, gives
// it client secrets, deletes each one through respond.Executor and the real
// respond.AzureCLI adapter, and measures when Graph stops listing the secret
// and when Entra's token endpoint starts refusing it. Nothing here prints a
// secret or a token: Probe keeps the access token in an unexported field.
package azurelab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// ARMScope is the resource the lab app asks tokens for. The app has no
	// Azure role, so its tokens can read nothing.
	ARMScope = "https://management.azure.com/.default"
	// Trigger is the rule ID of respond/playbooks/disable-azure-app-credential.yaml.
	Trigger = "warden-azure-app-secret-misuse"
)

// Az runs the Azure CLI with a minimal environment: PATH, HOME and the
// AZURE_CONFIG_DIR of the signed-in user, nothing else from the caller.
type Az struct {
	Path      string // absolute
	ConfigDir string
}

func (a Az) Run(ctx context.Context, args ...string) ([]byte, error) {
	if !filepath.IsAbs(a.Path) || a.ConfigDir == "" {
		return nil, errors.New("az must be an absolute path with AZURE_CONFIG_DIR")
	}
	cmd := exec.CommandContext(ctx, a.Path, append(append([]string(nil), args...), "--only-show-errors")...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "AZURE_CONFIG_DIR=" + a.ConfigDir}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) > 600 {
			msg = msg[:600]
		}
		return nil, fmt.Errorf("az %s: %v: %s", strings.Join(args[:min(3, len(args))], " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// Source is the checkout a live run was built from: HEAD, and the
// `git status --porcelain` lines of changed tracked files and of untracked
// files (ignored files such as .cache are not listed).
type Source struct {
	Commit         string   `json:"commit"`
	TrackedChanges []string `json:"tracked_changes"`
	Untracked      []string `json:"untracked"`
}

// SourceState reads the checkout that contains dir.
func SourceState(ctx context.Context, dir string) (Source, error) {
	git := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			return "", fmt.Errorf("git %s: %v", args[0], err)
		}
		return string(out), nil
	}
	head, err := git("rev-parse", "--verify", "HEAD")
	if err != nil {
		return Source{}, err
	}
	status, err := git("status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return Source{}, err
	}
	s := Source{Commit: strings.TrimSpace(head), TrackedChanges: []string{}, Untracked: []string{}}
	for _, line := range strings.Split(status, "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "?? "):
			s.Untracked = append(s.Untracked, line[3:])
		default:
			s.TrackedChanges = append(s.TrackedChanges, line)
		}
	}
	return s, nil
}

// Probe is one token request. AtMs is its start relative to the alert.
type Probe struct {
	AtMs      float64  `json:"at_ms"`
	Ms        float64  `json:"ms"`
	OK        bool     `json:"ok"`
	Status    int      `json:"status"`
	Error     string   `json:"error,omitempty"`
	AADSTS    []string `json:"aadsts,omitempty"`
	ExpiresIn int      `json:"expires_in,omitempty"`
	token     string
}

// Token is the access token of a successful probe; it is never serialized.
func (p Probe) Token() string { return p.token }

// Rejected reports an explicit refusal of the client credential. A busy token
// service or a network error is not evidence of containment.
func (p Probe) Rejected() bool {
	return (p.Status == http.StatusBadRequest || p.Status == http.StatusUnauthorized) && p.Error == "invalid_client"
}

var aadstsPattern = regexp.MustCompile(`AADSTS\d+`)

// TokenClient asks Entra for app-only tokens (client credentials grant).
type TokenClient struct {
	Authority string // default https://login.microsoftonline.com
	HTTP      *http.Client
}

func (c TokenClient) ClientCredentials(ctx context.Context, tenant, clientID, secret, scope string) Probe {
	authority := c.Authority
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_secret": {secret}, "scope": {scope}}
	start := time.Now()
	p := Probe{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authority+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		p.Error = "request: " + err.Error()
		return p
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	p.Ms = msSince(start)
	if err != nil {
		p.Error = "transport: " + redactURLError(err)
		return p
	}
	defer resp.Body.Close()
	p.Status = resp.StatusCode
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil {
		p.Error = "unreadable response"
		return p
	}
	if resp.StatusCode == http.StatusOK && body.AccessToken != "" {
		p.OK, p.token, p.ExpiresIn = true, body.AccessToken, body.ExpiresIn
		return p
	}
	p.Error = body.Error
	p.AADSTS = uniqueSorted(aadstsPattern.FindAllString(body.Description, -1))
	return p
}

// redactURLError drops the request body/URL details url.Error may carry.
func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

func uniqueSorted(v []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Series summarises the token probes after an alert. StableRejectMs is the
// first rejection after the last success: from then on every conclusive
// probe was refused.
type Series struct {
	Probes                    int      `json:"probes"`
	FirstRejectMs             *float64 `json:"first_reject_ms"`
	LastSuccessMs             *float64 `json:"last_success_ms"`
	StableRejectMs            *float64 `json:"stable_reject_ms"`
	SuccessesAfterFirstReject int      `json:"successes_after_first_reject"`
	Inconclusive              int      `json:"inconclusive"`
}

func Analyze(probes []Probe) Series {
	s := Series{Probes: len(probes)}
	for i := range probes {
		p := probes[i]
		at := p.AtMs
		switch {
		case p.OK:
			s.LastSuccessMs, s.StableRejectMs = &at, nil
			if s.FirstRejectMs != nil {
				s.SuccessesAfterFirstReject++
			}
		case p.Rejected():
			if s.FirstRejectMs == nil {
				s.FirstRejectMs = &at
			}
			if s.StableRejectMs == nil {
				s.StableRejectMs = &at
			}
		default:
			s.Inconclusive++
		}
	}
	return s
}

// Acceptance summarises the token probes after a secret is added.
// StableOKMs is the first success after the last refusal.
type Acceptance struct {
	Probes              int      `json:"probes"`
	FirstOKMs           *float64 `json:"first_ok_ms"`
	LastRejectMs        *float64 `json:"last_reject_ms"`
	StableOKMs          *float64 `json:"stable_ok_ms"`
	RejectsAfterFirstOK int      `json:"rejects_after_first_ok"`
	Inconclusive        int      `json:"inconclusive"`
}

func AnalyzeAcceptance(probes []Probe) Acceptance {
	a := Acceptance{Probes: len(probes)}
	for i := range probes {
		at := probes[i].AtMs
		switch {
		case probes[i].OK:
			if a.FirstOKMs == nil {
				a.FirstOKMs = &at
			}
			if a.StableOKMs == nil {
				a.StableOKMs = &at
			}
		case probes[i].Rejected():
			a.LastRejectMs, a.StableOKMs = &at, nil
			if a.FirstOKMs != nil {
				a.RejectsAfterFirstOK++
			}
		default:
			a.Inconclusive++
		}
	}
	return a
}

// Stable decides when the token endpoint has answered the same way (success
// if WantOK, refusal otherwise) for Window: the opposite answer restarts the
// window, an inconclusive probe neither counts nor restarts it.
type Stable struct {
	WantOK bool
	Window time.Duration
	since  time.Time
}

func (s *Stable) Observe(p Probe, at time.Time) bool {
	switch {
	case p.OK == s.WantOK && (p.OK || p.Rejected()):
		if s.since.IsZero() {
			s.since = at
		}
	case p.OK || p.Rejected():
		s.since = time.Time{}
	}
	return !s.since.IsZero() && at.Sub(s.since) >= s.Window
}

// Since is the start of the current run of wanted answers (zero if none).
func (s *Stable) Since() time.Time { return s.since }

// Stats is nearest-rank p50/p95 with min, max and n.
func Stats(v []float64) map[string]float64 {
	if len(v) == 0 {
		return nil
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	rank := func(p float64) float64 {
		i := int(math.Ceil(p/100*float64(len(s)))) - 1
		return s[max(0, min(i, len(s)-1))]
	}
	return map[string]float64{"p50": rank(50), "p95": rank(95), "min": s[0], "max": s[len(s)-1], "n": float64(len(s))}
}

// Graph reads one application's password credentials with the signed-in
// user's delegated Graph token (the user owns the app).
type Graph struct {
	Base  string // default https://graph.microsoft.com
	Token string
	HTTP  *http.Client
}

func (g Graph) CredentialPresent(ctx context.Context, appObjectID, keyID string) (bool, error) {
	base := g.Base
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/v1.0/applications/"+url.PathEscape(appObjectID)+"?$select=passwordCredentials", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return false, errors.New("graph: " + redactURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("graph: HTTP %d", resp.StatusCode)
	}
	var app struct {
		PasswordCredentials []struct {
			KeyID string `json:"keyId"`
		} `json:"passwordCredentials"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&app); err != nil {
		return false, errors.New("graph: unreadable application")
	}
	for _, c := range app.PasswordCredentials {
		if c.KeyID == keyID {
			return true, nil
		}
	}
	return false, nil
}

// Redact replaces each non-empty key of pairs with its placeholder.
func Redact(raw []byte, pairs map[string]string) []byte {
	out := string(raw)
	for value, placeholder := range pairs {
		if value != "" {
			out = strings.ReplaceAll(out, value, placeholder)
		}
	}
	return []byte(out)
}

// LeakCheck fails if any 16-character window of a secret appears in raw.
func LeakCheck(raw []byte, secrets []string) error {
	s := string(raw)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		w := min(16, len(secret))
		for i := 0; i+w <= len(secret); i++ {
			if strings.Contains(s, secret[i:i+w]) {
				return errors.New("output contains part of a secret or token")
			}
		}
	}
	return nil
}

func msSince(t time.Time) float64 { return Ms(time.Since(t)) }

// Ms rounds a duration to 0.1 ms.
func Ms(d time.Duration) float64 { return math.Round(float64(d)/1e5) / 10 }
