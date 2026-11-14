package runs

import (
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"strings"
)

var ErrForbidden = errors.New("run specification denied by tenant policy")
var ErrPolicyUnavailable = errors.New("tenant policy unavailable")

// Policy is trusted server configuration scoped to exactly one tenant.
// Zero maximum fields inherit global defaults. Nil AllowedRuntimes allows all
// supported runtimes; an explicit empty list allows none. Domains match exactly.
type Policy struct {
	TenantID        string
	MaxLimits       Limits
	AllowedRuntimes []string
	AllowDomains    []string
}

// PolicyProvider returns nil for a tenant with no explicit policy. Errors must
// fail closed. Providers must return immutable snapshots. The caller supplies
// only a cryptographically verified TenantID, never request body/header values.
type PolicyProvider interface {
	PolicyForTenant(context.Context, string) (*Policy, error)
}
type PolicyFunc func(context.Context, string) (*Policy, error)

func (f PolicyFunc) PolicyForTenant(ctx context.Context, id string) (*Policy, error) {
	return f(ctx, id)
}

// Authorize checks a normalized launch spec against current trusted policy.
// Create calls this before its idempotency lookup. Task 2 workers must also call
// it immediately before launching queued work, using its stored tenant ID.
func (s *Store) Authorize(ctx context.Context, tenantID string, spec Spec) error {
	if strings.TrimSpace(tenantID) == "" {
		return ErrForbidden
	}
	caps := Limits{CPU: 1, MemoryMiB: 512, Pids: 128, TimeoutS: 300}
	runtimes := []string{"runc", "gvisor", "firecracker"}
	allowedDomains := []string{}
	if s.Policies != nil {
		policy, err := s.Policies.PolicyForTenant(ctx, tenantID)
		if err != nil {
			return ErrPolicyUnavailable
		}
		if policy != nil {
			if policy.TenantID != tenantID {
				return ErrPolicyUnavailable
			}
			maximum := policy.MaxLimits
			if math.IsNaN(maximum.CPU) || math.IsInf(maximum.CPU, 0) || maximum.CPU < 0 || maximum.MemoryMiB < 0 || maximum.Pids < 0 || maximum.TimeoutS < 0 {
				return ErrPolicyUnavailable
			}
			if maximum.CPU != 0 {
				caps.CPU = maximum.CPU
			}
			if maximum.MemoryMiB != 0 {
				caps.MemoryMiB = maximum.MemoryMiB
			}
			if maximum.Pids != 0 {
				caps.Pids = maximum.Pids
			}
			if maximum.TimeoutS != 0 {
				caps.TimeoutS = maximum.TimeoutS
			}
			if policy.AllowedRuntimes != nil {
				runtimes = slices.Clone(policy.AllowedRuntimes)
				for _, runtime := range runtimes {
					if runtime != "runc" && runtime != "gvisor" && runtime != "firecracker" {
						return ErrPolicyUnavailable
					}
				}
			}
			for _, domain := range policy.AllowDomains {
				domain = strings.ToLower(strings.TrimSuffix(domain, "."))
				if len(domain) > 253 || net.ParseIP(domain) != nil || !domainPattern.MatchString(domain) {
					return ErrPolicyUnavailable
				}
				allowedDomains = append(allowedDomains, domain)
			}
		}
	}
	if !spec.RootfsReadonly || spec.UID != 65534 || !spec.NoNewPrivileges || !slices.Contains(runtimes, spec.Runtime) {
		return ErrForbidden
	}
	limits := spec.Limits
	if math.IsNaN(limits.CPU) || math.IsInf(limits.CPU, 0) || limits.CPU <= 0 || limits.MemoryMiB <= 0 || limits.Pids <= 0 || limits.TimeoutS <= 0 {
		return ErrForbidden
	}
	if limits.CPU > caps.CPU || limits.MemoryMiB > caps.MemoryMiB || limits.Pids > caps.Pids || limits.TimeoutS > caps.TimeoutS {
		return ErrForbidden
	}
	switch spec.Network {
	case "none":
		if len(spec.AllowDomains) != 0 {
			return ErrForbidden
		}
	case "allowlist":
		if len(spec.AllowDomains) == 0 {
			return ErrForbidden
		}
		for _, domain := range spec.AllowDomains {
			if !slices.Contains(allowedDomains, domain) {
				return ErrForbidden
			}
		}
	default:
		return ErrForbidden
	}
	return nil
}
