package ciliumlab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// peerSelectors returns the selectors listed under every fromEndpoints: and
// toEndpoints: of a policy document, one string per list item.
func peerSelectors(doc string) []string {
	lines := strings.Split(doc, "\n")
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }
	var out []string
	for i, l := range lines {
		key, col := strings.TrimSpace(l), indent(l)
		if strings.HasPrefix(key, "- ") { // the key of a list item
			key, col = strings.TrimSpace(key[2:]), col+2
		}
		if key != "fromEndpoints:" && key != "toEndpoints:" {
			continue
		}
		var item []string
		for _, m := range lines[i+1:] {
			if strings.TrimSpace(m) == "" || strings.HasPrefix(strings.TrimSpace(m), "#") {
				continue
			}
			if indent(m) <= col {
				break
			}
			if strings.HasPrefix(strings.TrimSpace(m), "- ") && item != nil && indent(m) <= indent(item[0]) {
				out = append(out, strings.Join(item, "\n"))
				item = nil
			}
			item = append(item, m)
		}
		if item != nil {
			out = append(out, strings.Join(item, "\n"))
		}
	}
	return out
}

func TestPeerSelectorsSplitsTheListItems(t *testing.T) {
	doc := `spec:
  ingress:
    - fromEndpoints:
        - matchLabels:
            a: "1"
        # a comment
        - matchLabels:
            b: "2"
          matchExpressions:
            - key: c
              operator: Exists
      toPorts:
        - ports:
            - port: "1"
  egress:
    - toEndpoints:
        - matchLabels:
            d: "4"`
	got := peerSelectors(doc)
	if len(got) != 3 || !strings.Contains(got[0], `a: "1"`) || !strings.Contains(got[1], "key: c") ||
		strings.Contains(got[1], "port") || !strings.Contains(got[2], `d: "4"`) {
		t.Fatalf("selectors = %q", got)
	}
}

// In a CiliumNetworkPolicy, which is namespaced, a peer selector without a
// namespace label selects pods in the policy's own namespace only. The egress
// proxy's policy is in warden-system and sandboxes run in a namespace of their
// own, so a rule about sandboxes there has to name their namespaces (any, in
// egress-proxy.yaml); without that, the proxy refuses every sandbox
// (runs/04-task10 in docs/evidence/task-10/cilium-lab-20261112).
func TestNamespacedPoliciesSelectSandboxesOutsideTheirNamespace(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(policyDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no policies in %s: %v", policyDir, err)
	}
	sandboxRules := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(raw), "\n---\n") {
			if !strings.Contains(doc, "\nkind: CiliumNetworkPolicy\n") {
				continue
			}
			for _, sel := range peerSelectors(doc) {
				if !strings.Contains(sel, "warden.dev/sandbox") {
					continue
				}
				sandboxRules++
				if !strings.Contains(sel, "io.kubernetes.pod.namespace") {
					t.Errorf("%s: this selector of sandboxes matches only the policy's own namespace:\n%s", filepath.Base(f), sel)
				}
			}
		}
	}
	if sandboxRules == 0 {
		t.Error("no namespaced policy has a rule about sandboxes; egress-proxy.yaml's ingress rule is one")
	}
}

// IsolatePod works by a label: Cilium enforces quarantine.yaml on a pod only
// once the pod's endpoint has a new identity with that label. With Cilium's
// defaults that took 9.9-32.2 s on the lab (runs/08-task14): the agent waits
// a random delay of up to identity-max-jitter (30 s) before it allocates the
// identity and identity-change-grace-period (5 s) before the endpoint uses
// it. The lab's values set both to 0 (spikes/s5-s7 measured each step).
func TestLabCiliumTakesLabelChangesInAtOnce(t *testing.T) {
	raw, err := os.ReadFile("../../../runtimes/gvisor/lab/cilium/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	top, extra := map[string]string{}, map[string]string{}
	inExtra := false
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		v = strings.Trim(strings.TrimSpace(v), `"`)
		if !strings.HasPrefix(l, " ") {
			top[k], inExtra = v, k == "extraConfig"
		} else if inExtra {
			extra[k] = v
		}
	}
	if top["identityChangeGracePeriod"] != "0s" {
		t.Errorf("identityChangeGracePeriod = %q, want \"0s\"", top["identityChangeGracePeriod"])
	}
	if extra["identity-max-jitter"] != "0s" {
		t.Errorf("extraConfig identity-max-jitter = %q, want \"0s\"", extra["identity-max-jitter"])
	}
}
