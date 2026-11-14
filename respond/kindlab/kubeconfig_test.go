package kindlab

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"warden/respond"
)

func TestParseKubeconfigReadsTheOneKindCluster(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	raw := strings.Join([]string{
		"apiVersion: v1",
		"clusters:",
		"- cluster:",
		"    certificate-authority-data: " + b64("CA PEM"),
		"    server: https://127.0.0.1:40123",
		"  name: kind-warden-respond",
		"users:",
		"- name: kind-warden-respond",
		"  user:",
		"    client-certificate-data: " + b64("CERT PEM"),
		"    client-key-data: " + b64("KEY PEM"),
		"",
	}, "\n")
	c, err := ParseKubeconfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://127.0.0.1:40123" || string(c.CA) != "CA PEM" || string(c.Cert) != "CERT PEM" || string(c.Key) != "KEY PEM" {
		t.Fatalf("parsed %+v", c)
	}
	// A second cluster, a missing field, an http server or a non-loopback
	// server are all refused: the lab only talks to its own local cluster.
	for name, bad := range map[string]string{
		"two clusters": raw + "- cluster:\n    server: https://127.0.0.1:1\n",
		"no key":       strings.Replace(raw, "client-key-data", "client-key-file", 1),
		"plain http":   strings.Replace(raw, "https://127.0.0.1", "http://127.0.0.1", 1),
		"remote":       strings.Replace(raw, "https://127.0.0.1", "https://10.0.0.5", 1),
		"bad base64":   strings.Replace(raw, b64("CA PEM"), "%%%", 1),
	} {
		if _, err := ParseKubeconfig([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The k3s lab's API server is on the node's address on an internal Docker
// network, not on loopback; the caller names that one address.
func TestParseKubeconfigForAcceptsOnlyTheNamedLabNode(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	raw := strings.Join([]string{
		"apiVersion: v1",
		"clusters:",
		"- cluster:",
		"    certificate-authority-data: " + b64("CA PEM"),
		"    server: https://192.168.192.10:6443",
		"  name: default",
		"users:",
		"- name: default",
		"  user:",
		"    client-certificate-data: " + b64("CERT PEM"),
		"    client-key-data: " + b64("KEY PEM"),
		"",
	}, "\n")
	c, err := ParseKubeconfigFor([]byte(raw), "192.168.192.10")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://192.168.192.10:6443" || string(c.Key) != "KEY PEM" {
		t.Fatalf("parsed %+v", c)
	}
	for name, bad := range map[string]struct{ raw, host string }{
		"other node":   {raw, "192.168.192.11"},
		"no host":      {raw, ""},
		"loopback":     {strings.Replace(raw, "192.168.192.10", "127.0.0.1", 1), "192.168.192.10"},
		"plain http":   {strings.Replace(raw, "https://", "http://", 1), "192.168.192.10"},
		"two clusters": {raw + "- cluster:\n    server: https://192.168.192.10:1\n", "192.168.192.10"},
	} {
		if _, err := ParseKubeconfigFor([]byte(bad.raw), bad.host); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseKubeconfig([]byte(raw)); err == nil {
		t.Error("ParseKubeconfig accepted a non-loopback server")
	}
}

// The vanilla NetworkPolicy twin of policies/cilium/quarantine.yaml, for
// clusters whose CNI enforces NetworkPolicy but is not Cilium (kind's kindnet).
func TestQuarantineNetworkPolicyDeniesAllForTheLabel(t *testing.T) {
	raw, err := os.ReadFile(QuarantinePolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			PodSelector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"podSelector"`
			PolicyTypes []string          `json:"policyTypes"`
			Ingress     []json.RawMessage `json:"ingress"`
			Egress      []json.RawMessage `json:"egress"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.APIVersion != "networking.k8s.io/v1" || p.Kind != "NetworkPolicy" {
		t.Fatalf("kind %s/%s", p.APIVersion, p.Kind)
	}
	if len(p.Spec.PodSelector.MatchLabels) != 1 || p.Spec.PodSelector.MatchLabels[respond.QuarantineLabel] != "true" {
		t.Fatalf("selector %v, want only %s=true", p.Spec.PodSelector.MatchLabels, respond.QuarantineLabel)
	}
	if strings.Join(p.Spec.PolicyTypes, ",") != "Ingress,Egress" || len(p.Spec.Ingress) != 0 || len(p.Spec.Egress) != 0 {
		t.Fatalf("policy must select both directions with no allow rules: %s", raw)
	}
}
