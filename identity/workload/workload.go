// Package workload exchanges a Kubernetes service account token for a
// Microsoft Entra access token (workload identity federation: the client
// credentials grant with the service account token as a JWT client
// assertion) and reads token claims. Tokens stay in memory: nothing here
// writes, logs or formats one. Standard library only.
package workload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	// DefaultAuthority is Entra's public-cloud login host.
	DefaultAuthority = "https://login.microsoftonline.com"
	// AssertionType is the client_assertion_type of a JWT client assertion.
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// FederationAudience is the audience Entra accepts on a federated token.
	FederationAudience = "api://AzureADTokenExchange"
)

// Token is an access token. Its value is only returned by Value; printing a
// Token in any format shows no part of it.
type Token struct {
	Type      string
	ExpiresIn int64
	value     string
}

// Value is the access token itself.
func (t Token) Value() string { return t.value }

func (t Token) String() string {
	return fmt.Sprintf("workload.Token{Type:%s ExpiresIn:%d}", t.Type, t.ExpiresIn)
}

// GoString keeps %#v from printing the value.
func (t Token) GoString() string { return t.String() }

// Error is the token endpoint's refusal: the HTTP status, the OAuth error
// and Entra's AADSTS numbers. The description is dropped: it can name the
// assertion's subject and carries trace and correlation IDs.
type Error struct {
	Status int
	Code   string
	Codes  []int
}

func (e *Error) Error() string {
	return fmt.Sprintf("token endpoint: HTTP %d %s (AADSTS %v)", e.Status, e.Code, e.Codes)
}

// Has reports whether Entra answered with AADSTS code.
func (e *Error) Has(code int) bool { return slices.Contains(e.Codes, code) }

// Exchanger posts to an Entra authority's v2 token endpoint.
type Exchanger struct {
	HTTP      *http.Client
	Authority string // DefaultAuthority when empty
}

var pathSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Exchange trades assertion (a service account token whose audience
// FederationAudience a federated credential of clientID accepts) for an
// access token for scope.
func (x Exchanger) Exchange(ctx context.Context, tenant, clientID, assertion, scope string) (Token, error) {
	for _, v := range []string{tenant, clientID} {
		if !pathSafe.MatchString(v) || v == "." || v == ".." {
			return Token{}, fmt.Errorf("workload: tenant and client ID must be plain names, got %q", v)
		}
	}
	authority := x.Authority
	if authority == "" {
		authority = DefaultAuthority
	}
	form := url.Values{"client_id": {clientID}, "scope": {scope}, "grant_type": {"client_credentials"},
		"client_assertion_type": {AssertionType}, "client_assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authority, "/")+"/"+tenant+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	hc := x.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Codes []int  `json:"error_codes"`
		}
		_ = json.Unmarshal(raw, &e)
		return Token{}, &Error{Status: resp.StatusCode, Code: e.Error, Codes: e.Codes}
	}
	var ok struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &ok); err != nil || ok.AccessToken == "" {
		return Token{}, errors.New("workload: token endpoint answered 200 without an access token")
	}
	return Token{Type: ok.TokenType, ExpiresIn: ok.ExpiresIn, value: ok.AccessToken}, nil
}

// Claims decodes a JWT's payload. The signature is not checked: this is for
// reading a token's own lifetime, not for trusting it. Numbers stay
// json.Number.
func Claims(jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("workload: a JWT has 3 parts, this has %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("workload: JWT payload: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var c map[string]any
	if err := d.Decode(&c); err != nil || c == nil {
		return nil, fmt.Errorf("workload: JWT payload is not a JSON object: %v", err)
	}
	return c, nil
}

// Lifetime is exp - iat in seconds.
func Lifetime(claims map[string]any) (int64, error) {
	get := func(k string) (int64, error) {
		n, ok := claims[k].(json.Number)
		if !ok {
			return 0, fmt.Errorf("workload: claim %s is missing or not a number", k)
		}
		return n.Int64()
	}
	exp, err := get("exp")
	if err != nil {
		return 0, err
	}
	iat, err := get("iat")
	if err != nil {
		return 0, err
	}
	return exp - iat, nil
}

// publicClaims identify nothing: times, audience and token kind.
var publicClaims = []string{"aud", "exp", "iat", "idtyp", "nbf", "ver"}

// Public is what of claims may be kept in evidence: the public claims'
// values and the names of all claims. Issuer, subject, tenant, object and
// resource IDs stay out.
func Public(claims map[string]any) map[string]any {
	out := map[string]any{}
	names := make([]string, 0, len(claims))
	for k, v := range claims {
		names = append(names, k)
		if slices.Contains(publicClaims, k) {
			out[k] = v
		}
	}
	sort.Strings(names)
	out["claims"] = names
	return out
}
