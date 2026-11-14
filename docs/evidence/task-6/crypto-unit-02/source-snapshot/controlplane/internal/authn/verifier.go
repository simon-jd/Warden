// Package authn verifies delegated access tokens for the configured Warden API.
// A verified subject is not tenant authorization: a later SQL adapter must map
// Issuer/Subject to an active stored user and tenant for every API request.
package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxTokenBytes = 16 << 10
	maxHeaderBytes = 2 << 10
	requiredScope = "warden.access"
	verifyTimeout = 5 * time.Second
)

// ErrUnauthorized intentionally contains no token, subject, or key material.
var ErrUnauthorized = errors.New("access token rejected")

// Config is trusted operator configuration, never populated from token claims.
// This initial implementation supports the public Entra cloud and one v2 tenant.
type Config struct {
	Issuer string
	Audience string
	JWKSURL string
}

// Claims describe a cryptographically verified delegated user. They deliberately
// contain no Warden TenantID or authority inferred from a token's tid/oid/email.
type Claims struct {
	Issuer string
	Subject string
	Audience []string
	ExpiresAt time.Time
	NotBefore time.Time
	Scopes []string
}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateConfig(c Config) error {
	const prefix = "https://login.microsoftonline.com/"
	if !strings.HasPrefix(c.Issuer, prefix) || !strings.HasSuffix(c.Issuer, "/v2.0") {
		return errors.New("invalid fixed Entra authority")
	}
	tenant := strings.TrimSuffix(strings.TrimPrefix(c.Issuer, prefix), "/v2.0")
	if !guid.MatchString(tenant) || tenant == "00000000-0000-0000-0000-000000000000" ||
		c.JWKSURL != prefix+tenant+"/discovery/v2.0/keys" || !guid.MatchString(c.Audience) ||
		c.Audience == "00000000-0000-0000-0000-000000000000" {
		return errors.New("invalid tenant-specific API configuration")
	}
	return nil
}

// New creates an HTTPS-only verifier with ordinary certificate verification.
// The caller cannot override TLS trust, redirect policy, proxy, or transport.
func New(c Config) (*Verifier, error) {
	if err := validateConfig(c); err != nil { return nil, err }
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{Timeout: 2*time.Second, KeepAlive: 30*time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 2*time.Second,
		ResponseHeaderTimeout: 2*time.Second,
		MaxResponseHeaderBytes: 16<<10,
		DisableCompression: true,
		MaxConnsPerHost: 1,
		MaxIdleConns: 1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout: 30*time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 3*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return newVerifier(c, client, time.Now)
}

// newVerifier is private dependency injection for in-package tests. Public
// construction always uses New's fixed transport and configuration validation.
func newVerifier(c Config, client *http.Client, now func() time.Time) (*Verifier, error) {
	if err := validateConfig(c); err != nil { return nil, err }
	if client == nil || now == nil { return nil, errors.New("verifier dependencies unavailable") }
	return &Verifier{config:c, client:client, now:now, budget:2, budgetAt:now()}, nil
}

// Verify preserves the original context-free authn interface with a bounded
// lifetime. It does not implement tenant.Verifier's differently typed method.
func (v *Verifier) Verify(raw string) (Claims, error) {
	return v.VerifyContext(context.Background(), raw)
}

// VerifyContext verifies the exact JWT bytes and honors cancellation. Caller
// cancellation cannot cancel another caller's shared, independently bounded fetch.
func (v *Verifier) VerifyContext(parent context.Context, raw string) (Claims, error) {
	if v == nil || v.now == nil || parent == nil { return Claims{}, ErrUnauthorized }
	ctx, cancel := context.WithTimeout(parent, verifyTimeout)
	defer cancel()
	if ctx.Err() != nil { return Claims{}, ctx.Err() }
	if len(raw) == 0 || len(raw) > maxTokenBytes { return Claims{}, ErrUnauthorized }
	parts := strings.Split(raw, ".")
	if len(parts) != 3 { return Claims{}, ErrUnauthorized }
	headerBytes, err := canonicalBase64(parts[0])
	if err != nil || len(headerBytes) > maxHeaderBytes { return Claims{}, ErrUnauthorized }
	payloadBytes, err := canonicalBase64(parts[1])
	if err != nil { return Claims{}, ErrUnauthorized }
	signature, err := canonicalBase64(parts[2])
	if err != nil || len(signature) < 256 || len(signature) > 512 { return Claims{}, ErrUnauthorized }
	header, err := objectJSON(headerBytes)
	if err != nil || header["alg"] != "RS256" { return Claims{}, ErrUnauthorized }
	for _, forbidden := range []string{"crit", "jku", "x5u", "jwk", "b64"} {
		if _, present := header[forbidden]; present { return Claims{}, ErrUnauthorized }
	}
	if typ, exists := header["typ"]; exists && typ != "JWT" { return Claims{}, ErrUnauthorized }
	kid, ok := header["kid"].(string)
	if !ok || len(kid) == 0 || len(kid) > 128 { return Claims{}, ErrUnauthorized }
	payload, err := objectJSON(payloadBytes)
	if err != nil { return Claims{}, ErrUnauthorized }
	claims, err := v.claims(payload)
	if err != nil { return Claims{}, ErrUnauthorized }
	key, err := v.key(ctx, kid)
	if err != nil { return Claims{}, ErrUnauthorized }
	hash := sha256.Sum256([]byte(parts[0]+"."+parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) != nil { return Claims{}, ErrUnauthorized }
	if ctx.Err() != nil { return Claims{}, ctx.Err() }
	// A token or snapshot can expire while a network fetch is in flight. Token
	// dates are checked again after verification rather than using arrival time.
	if _, err := v.claims(payload); err != nil { return Claims{}, ErrUnauthorized }
	v.mu.Lock()
	current := v.now().Before(v.expires) && v.keys[kid] == key
	v.mu.Unlock()
	if !current { return Claims{}, ErrUnauthorized }
	return claims, nil
}

func (v *Verifier) claims(p map[string]any) (Claims, error) {
	issuer, _ := p["iss"].(string)
	subject, _ := p["sub"].(string)
	if issuer != v.config.Issuer || len(subject) == 0 || len(subject) > 256 || p["ver"] != "2.0" {
		return Claims{}, ErrUnauthorized
	}
	var audience []string
	switch a := p["aud"].(type) {
	case string: audience = []string{a}
	case []any:
		if len(a) == 0 || len(a) > 16 { return Claims{}, ErrUnauthorized }
		seen := make(map[string]bool, len(a))
		for _, item := range a {
			value, ok := item.(string)
			if !ok || value == "" || seen[value] { return Claims{}, ErrUnauthorized }
			seen[value] = true
			audience = append(audience, value)
		}
	default: return Claims{}, ErrUnauthorized
	}
	match := false
	for _, a := range audience { if a == v.config.Audience { match = true } }
	if !match { return Claims{}, ErrUnauthorized }
	exp, ok := integer(p["exp"])
	if !ok { return Claims{}, ErrUnauthorized }
	now := v.now()
	expires := time.Unix(exp, 0)
	if !now.Before(expires) { return Claims{}, ErrUnauthorized }
	var notBefore time.Time
	if value, exists := p["nbf"]; exists {
		nbf, valid := integer(value)
		if !valid || nbf >= exp { return Claims{}, ErrUnauthorized }
		notBefore = time.Unix(nbf, 0)
		if now.Before(notBefore) { return Claims{}, ErrUnauthorized }
	}
	scope, ok := p["scp"].(string)
	if !ok { return Claims{}, ErrUnauthorized }
	scopes := strings.Split(scope, " ")
	match = false
	for _, item := range scopes { if item == requiredScope { match = true } }
	if !match { return Claims{}, ErrUnauthorized }
	return Claims{Issuer:issuer, Subject:subject, Audience:audience, ExpiresAt:expires, NotBefore:notBefore, Scopes:scopes}, nil
}

func integer(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok { return 0, false }
	i, err := strconv.ParseInt(string(number), 10, 64)
	return i, err == nil && i >= 0
}

func canonicalBase64(encoded string) ([]byte, error) {
	if encoded == "" { return nil, ErrUnauthorized }
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded { return nil, ErrUnauthorized }
	return decoded, nil
}

// objectJSON rejects duplicate members at every nesting level, trailing values,
// malformed UTF-8 and excessive nesting before interpreting security claims.
func objectJSON(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) { return nil, ErrUnauthorized }
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	value, err := jsonValue(decoder, 0)
	if err != nil { return nil, err }
	if _, err = decoder.Token(); err != io.EOF { return nil, ErrUnauthorized }
	object, ok := value.(map[string]any)
	if !ok { return nil, ErrUnauthorized }
	return object, nil
}

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 16 { return nil, ErrUnauthorized }
	token, err := decoder.Token()
	if err != nil { return nil, ErrUnauthorized }
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok { return nil, ErrUnauthorized }
				if _, exists := object[key]; exists { return nil, ErrUnauthorized }
				value, err := jsonValue(decoder, depth+1)
				if err != nil { return nil, err }
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') { return nil, ErrUnauthorized }
			return object, nil
		case '[':
			var array []any
			for decoder.More() {
				value, err := jsonValue(decoder, depth+1)
				if err != nil { return nil, err }
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') { return nil, ErrUnauthorized }
			return array, nil
		default: return nil, ErrUnauthorized
		}
	}
	return token, nil
}
