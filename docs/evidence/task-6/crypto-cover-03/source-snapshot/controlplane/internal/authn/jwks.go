package authn

import (
	"context"
	"crypto/rsa"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	keyTTL       = 10 * time.Minute
	fetchTimeout = 3 * time.Second
	maxJWKSBytes = 1 << 20
	maxKeys      = 64
	maxWaiters   = 32
)

type refresh struct {
	done chan struct{}
	err  error
}

// Verifier owns one configured authority, one atomic keyset and at most one
// bounded refresh worker. No state is allocated per unknown or attacker kid.
type Verifier struct {
	config    Config
	client    *http.Client
	now       func() time.Time
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expires   time.Time
	nextRetry time.Time
	inflight  *refresh
	waiters   int
	budget    float64
	budgetAt  time.Time
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if ctx.Err() != nil {
		v.mu.Unlock()
		return nil, ErrUnauthorized
	}
	now := v.now()
	fresh := v.keys != nil && now.Before(v.expires)
	if fresh {
		if key := v.keys[kid]; key != nil {
			v.mu.Unlock()
			return key, nil
		}
	}
	if v.waiters >= maxWaiters {
		v.mu.Unlock()
		return nil, ErrUnauthorized
	}
	flight := v.inflight
	if flight == nil {
		if !fresh && now.Before(v.nextRetry) {
			v.mu.Unlock()
			return nil, ErrUnauthorized
		}
		if fresh && !v.admitUnknown(now) {
			v.mu.Unlock()
			return nil, ErrUnauthorized
		}
		flight = &refresh{done: make(chan struct{})}
		v.inflight = flight
		go v.refreshKeys(flight)
	}
	// Joining a shared fetch does not spend another unknown-key refresh token.
	v.waiters++
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		v.mu.Lock()
		v.waiters--
		v.mu.Unlock()
		return nil, ErrUnauthorized
	case <-flight.done:
		v.mu.Lock()
		defer v.mu.Unlock()
		v.waiters--
		if ctx.Err() != nil || flight.err != nil || !v.now().Before(v.expires) {
			return nil, ErrUnauthorized
		}
		key := v.keys[kid]
		if key == nil {
			return nil, ErrUnauthorized
		}
		return key, nil
	}
}

// Called only while holding mu. Rate exhaustion denies this request; it never
// accepts an unknown key or postpones a permitted refresh until cache expiry.
func (v *Verifier) admitUnknown(now time.Time) bool {
	if now.After(v.budgetAt) {
		v.budget += now.Sub(v.budgetAt).Seconds() * 2
		if v.budget > 2 {
			v.budget = 2
		}
		v.budgetAt = now
	}
	if v.budget < 1 {
		return false
	}
	v.budget--
	return true
}

func (v *Verifier) refreshKeys(flight *refresh) {
	// The worker outlives an individual canceled caller, but never its own 3-second
	// fetch deadline. Coalescing limits it to one worker per configured verifier.
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	keys, err := v.fetch(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err == nil {
		v.keys = keys
		v.expires = v.now().Add(keyTTL)
		v.nextRetry = time.Time{}
	} else {
		// Keep the old snapshot's original expiry, never extend stale trust.
		v.nextRetry = v.now().Add(time.Second)
	}
	flight.err = err
	v.inflight = nil
	close(flight.done)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, nil)
	if err != nil {
		return nil, ErrUnauthorized
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, ErrUnauthorized
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrUnauthorized
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes || ctx.Err() != nil {
		return nil, ErrUnauthorized
	}
	root, err := objectJSON(body)
	if err != nil {
		return nil, ErrUnauthorized
	}
	entries, ok := root["keys"].([]any)
	if !ok || len(entries) == 0 || len(entries) > maxKeys {
		return nil, ErrUnauthorized
	}
	keys := make(map[string]*rsa.PublicKey, len(entries))
	for _, entry := range entries {
		object, ok := entry.(map[string]any)
		if !ok {
			return nil, ErrUnauthorized
		}
		kid, key, err := publicKey(object)
		if err != nil || keys[kid] != nil {
			return nil, ErrUnauthorized
		}
		keys[kid] = key
	}
	return keys, nil
}

func publicKey(object map[string]any) (string, *rsa.PublicKey, error) {
	if object["kty"] != "RSA" {
		return "", nil, ErrUnauthorized
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, exists := object[name]; exists {
			return "", nil, ErrUnauthorized
		}
	}
	if algorithm, exists := object["alg"]; exists && algorithm != "RS256" {
		return "", nil, ErrUnauthorized
	}
	if use, exists := object["use"]; exists && use != "sig" {
		return "", nil, ErrUnauthorized
	}
	if operations, exists := object["key_ops"]; exists {
		ops, ok := operations.([]any)
		if !ok || len(ops) != 1 || ops[0] != "verify" {
			return "", nil, ErrUnauthorized
		}
	}
	kid, ok := object["kid"].(string)
	if !ok || len(kid) == 0 || len(kid) > 128 {
		return "", nil, ErrUnauthorized
	}
	modulus, ok := object["n"].(string)
	if !ok {
		return "", nil, ErrUnauthorized
	}
	n, err := canonicalBase64(modulus)
	if err != nil || len(n) < 256 || len(n) > 512 || n[0] == 0 {
		return "", nil, ErrUnauthorized
	}
	integerN := new(big.Int).SetBytes(n)
	if integerN.BitLen() < 2048 || integerN.BitLen() > 4096 || integerN.Bit(0) == 0 {
		return "", nil, ErrUnauthorized
	}
	exponent, ok := object["e"].(string)
	if !ok {
		return "", nil, ErrUnauthorized
	}
	e, err := canonicalBase64(exponent)
	if err != nil || len(e) == 0 || len(e) > 3 || e[0] == 0 {
		return "", nil, ErrUnauthorized
	}
	integerE := 0
	for _, b := range e {
		integerE = integerE*256 + int(b)
	}
	if integerE < 3 || integerE > 65537 || integerE%2 == 0 {
		return "", nil, ErrUnauthorized
	}
	return kid, &rsa.PublicKey{N: integerN, E: integerE}, nil
}
