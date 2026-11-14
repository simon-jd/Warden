// Durable backend binding: Bind ties a gate to one cluster, namespace and
// node incarnation. The driver itself is in gvisor.go.

package gvisor

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"warden/runtimes/gate"
)

// BackendIdentity contains trusted deployment configuration and identifiers
// observed through its authenticated API connection. ClusterUID is the UID of
// kube-system: Kubernetes has no intrinsic cluster UID. NamespaceUID and NodeUID
// are the actual object UIDs, not names or user labels. No credentials belong in
// this record. NodeConfigSHA256 identifies the reviewed node input manifest
// (runtime binaries, CRI handlers/base specs, runsc flags, seccomp and isolation
// policy). These values do not attest that a node applied that configuration.
type BackendIdentity struct {
	APIServer        string `json:"api_server"`
	CASHA256         string `json:"ca_sha256"`
	ClusterUID       string `json:"cluster_uid"`
	Namespace        string `json:"namespace"`
	NamespaceUID     string `json:"namespace_uid"`
	NodeName         string `json:"node_name"`
	NodeUID          string `json:"node_uid"`
	NodeConfigSHA256 string `json:"node_config_sha256"`
}

var (
	hashPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uidPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Bind constructs the concrete gVisor backend identity and opens its dedicated
// durable gate. It refuses every legacy/unbound authority, even one with no
// launches. It contacts no server and grants no runtime capabilities. The future
// driver must verify these live identifiers before every API operation; a cached
// fingerprint alone cannot detect replacement during the lifetime of a process.
func Bind(dir, node string, identity BackendIdentity, driver gate.Driver) (*gate.Gate, error) {
	u, err := url.Parse(identity.APIServer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != identity.APIServer || strings.ContainsAny(u.Host, "\\%") {
		return nil, errors.New("canonical credential-free HTTPS API server required")
	}
	if net.ParseIP(u.Hostname()) == nil && !dnsName(u.Hostname()) {
		return nil, errors.New("invalid API server host")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, errors.New("invalid API server port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty API server port")
	}
	if !hashPattern.MatchString(identity.CASHA256) || !hashPattern.MatchString(identity.NodeConfigSHA256) || !uidPattern.MatchString(identity.ClusterUID) || !uidPattern.MatchString(identity.NamespaceUID) || !uidPattern.MatchString(identity.NodeUID) || identity.Namespace != "warden-lab" || !dnsName(identity.NodeName) {
		return nil, errors.New("complete dedicated gVisor backend identity required")
	}
	// A struct fixes field ordering; JSON delimits fields so concatenation cannot
	// alias identities. Domain/version separation permits only explicit upgrades.
	raw, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("warden.gvisor.backend.v1\x00"), raw...))
	return gate.NewBound(dir, node, driver, digest)
}

func dnsName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
