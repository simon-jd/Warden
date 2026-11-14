// Package tenant defines the trusted authentication boundary.
package tenant

import "context"

type Claims struct{ TenantID string }
type Verifier interface {
	Verify(context.Context, string) (Claims, error)
}
type VerifyFunc func(context.Context, string) (Claims, error)

func (f VerifyFunc) Verify(ctx context.Context, token string) (Claims, error) { return f(ctx, token) }

// Identity is a cryptographically verified IdP user. It carries no tenant:
// tenant membership comes only from the provisioned directory.
type Identity struct{ ObjectID string }
type IdentityVerifier interface {
	VerifyIdentity(context.Context, string) (Identity, error)
}
type IdentityVerifierFunc func(context.Context, string) (Identity, error)

func (f IdentityVerifierFunc) VerifyIdentity(ctx context.Context, token string) (Identity, error) {
	return f(ctx, token)
}
