// Package respond is the response executor: one playbook step per alert,
// deduplicated per alert ID through a local journal. SuspendTenant is
// destructive and needs a second approver; the containment actions take
// their target from the alert. Adapters for Vault, Kubernetes and Azure are in
// adapters.go.
package respond

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type ActionName string

const (
	RevokeVaultLease                       ActionName = "RevokeVaultLease"
	DisableAzureServicePrincipalCredential ActionName = "DisableAzureServicePrincipalCredential"
	IsolatePod                             ActionName = "IsolatePod"
	CordonNode                             ActionName = "CordonNode"
	// TerminatePod deletes a pod with no grace period. Quarantine labels stop
	// only new connections; ending the pod's processes closes open ones.
	// Destructive: its playbook must require a second approver.
	TerminatePod  ActionName = "TerminatePod"
	SuspendTenant ActionName = "SuspendTenant"
)

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Action struct {
	Name     ActionName `json:"name"`
	Resource Resource   `json:"resource"`
}

type Playbook struct {
	ID               string   `json:"id"`
	Trigger          string   `json:"trigger"`
	Steps            []Action `json:"steps"`
	RequiresApproval bool     `json:"requires_approval"`
}

// Alert is a local DTO; no live detection integration is implied.
type Alert struct {
	ID                  string
	RuleID              string
	TenantID            string
	Resource            Resource
	RequesterCredential string
	ApprovalProof       string
}

type Binding struct {
	TenantID   string
	AlertID    string
	RuleID     string
	PlaybookID string
	StepsHash  string
	Action     ActionName
	Resource   Resource
}

// CanonicalID is the authority-resolved principal identifier, including aliases.
// Roles are current tenant-specific authorizations verified by the authority.
type Principal struct {
	Issuer      string
	Subject     string
	CanonicalID string
	Roles       []string
}

// ActionClient performs one containment action (every action except
// SuspendTenant). Implementations must honour ctx and be idempotent: the
// executor never retries, but an operator reconciling an Unknown outcome may.
type ActionClient interface {
	Contain(context.Context, Action) error
}

type ApprovalRequest struct {
	RequesterCredential string
	ApprovalProof       string
	Binding             Binding
}

type Approval struct {
	Requester Principal
	Approver  Principal
	Binding   Binding
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ApprovalAuthority must authenticate both credentials, resolve aliases, check
// revocation/current tenant roles and authenticate every returned binding.
// Recording authorities in tests are not real identity/approval proof.
type ApprovalAuthority interface {
	Verify(context.Context, ApprovalRequest) (Approval, error)
}

// TenantClient must honor context; Go cannot forcibly interrupt an arbitrary
// implementation or undo an ambiguous mutation after an error.
type TenantClient interface {
	SuspendTenant(context.Context, string) error
}

var (
	ErrInvalid          = errors.New("invalid response configuration or alert")
	ErrUnsupported      = errors.New("response action unsupported")
	ErrApprovalRequired = errors.New("authenticated second approval required")
	ErrApprovalDenied   = errors.New("response authorization denied")
	ErrConflict         = errors.New("alert binding conflict")
	ErrStorage          = errors.New("response journal unavailable; reconcile before reuse")
	ErrCapacity         = errors.New("response journal capacity exhausted")
	ErrOutcomeUnknown   = errors.New("response outcome unknown; automatic retry suppressed")
	ErrClosed           = errors.New("response executor closed")
	ErrBusy             = errors.New("response executor has in-flight work")
)

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// resourceTypes is the only resource type each action accepts.
var resourceTypes = map[ActionName]string{
	SuspendTenant:                          "tenant",
	RevokeVaultLease:                       "vault_lease",
	DisableAzureServicePrincipalCredential: "azure_app_credential",
	IsolatePod:                             "pod",
	TerminatePod:                           "pod",
	CordonNode:                             "node",
}

const guid = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

var (
	leasePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)+$`)
	azurePattern = regexp.MustCompile(`^` + guid + `/` + guid + `$`)
	// Namespace is a DNS-1123 label, pod name a DNS-1123 subdomain.
	podPattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	nodePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// validTarget checks an alert-supplied containment target for its type.
func validTarget(typ, id string) bool {
	switch typ {
	case "vault_lease":
		if len(id) > 256 || !leasePattern.MatchString(id) {
			return false
		}
		for _, part := range strings.Split(id, "/") {
			if part == "." || part == ".." {
				return false
			}
		}
		return true
	case "azure_app_credential":
		return azurePattern.MatchString(id)
	case "pod":
		return len(id) <= 63+1+253 && podPattern.MatchString(id)
	case "node":
		return len(id) <= 253 && nodePattern.MatchString(id)
	}
	return false
}

func validatePlaybook(p Playbook) error {
	if !identifier(p.ID) || !identifier(p.Trigger) || len(p.Steps) != 1 {
		return ErrInvalid
	}
	a := p.Steps[0]
	// Unknown names include the obsolete AWS/GCP actions; never translate them.
	typ, ok := resourceTypes[a.Name]
	if !ok || a.Resource.Type != typ {
		return ErrInvalid
	}
	if a.Name != SuspendTenant {
		// Containment targets come from the alert, never from the playbook.
		if a.Resource.ID != "" {
			return ErrInvalid
		}
		if a.Name == TerminatePod && !p.RequiresApproval {
			return ErrApprovalRequired
		}
		return nil
	}
	if !identifier(a.Resource.ID) {
		return ErrInvalid
	}
	if !p.RequiresApproval {
		return ErrApprovalRequired
	}
	return nil
}

// ParsePlaybook accepts strict JSON, a finite YAML 1.2 subset, not general YAML.
func ParsePlaybook(raw []byte) (Playbook, error) {
	var p Playbook
	if len(raw) == 0 || len(raw) > 16*1024 || !utf8.Valid(raw) || strictJSON(raw, &p) != nil {
		return Playbook{}, ErrInvalid
	}
	root, ok := jsonObject(raw, "id", "trigger", "steps", "requires_approval")
	if !ok {
		return Playbook{}, ErrInvalid
	}
	var steps []json.RawMessage
	if json.Unmarshal(root["steps"], &steps) != nil || len(steps) != 1 {
		return Playbook{}, ErrInvalid
	}
	step, ok := jsonObject(steps[0], "name", "resource")
	if !ok {
		return Playbook{}, ErrInvalid
	}
	if _, ok = jsonObject(step["resource"], "type", "id"); !ok {
		return Playbook{}, ErrInvalid
	}
	if err := validatePlaybook(p); err != nil {
		return Playbook{}, err
	}
	return p, nil
}

// encoding/json's field matching is case-insensitive; enforce exact required
// field names separately so ID/id aliases cannot bypass duplicate detection.
func jsonObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, exists := object[key]; !exists {
			return nil, false
		}
	}
	return object, true
}

func strictJSON(raw []byte, target any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if scanJSON(d, 0) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalid
	}
	return nil
}

func scanJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalid
	}
	tok, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	delim, compound := tok.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || len(seen) >= 1024 {
				return ErrInvalid
			}
			seen[name] = true
			if scanJSON(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 1024 || scanJSON(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
