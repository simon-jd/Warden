// Package tenant defines the trusted authentication boundary.
package tenant

import "context"

type Claims struct{ TenantID string }
type Verifier interface {
	Verify(context.Context, string) (Claims, error)
}
type VerifyFunc func(context.Context, string) (Claims, error)

func (f VerifyFunc) Verify(ctx context.Context, token string) (Claims, error) { return f(ctx, token) }
