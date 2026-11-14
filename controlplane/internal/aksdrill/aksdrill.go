// Package aksdrill holds Task 7's metadata check on the AKS drill's cluster
// (scripts/aks_drill.py, make test-aks): Azure CNI powered by Cilium
// enforcing policies/cilium/deny-metadata.yaml against the real Azure
// instance metadata service at 169.254.169.254, and the pod and policy
// helpers it uses, which make test covers offline.
//
// AKS has no gVisor, so the sandboxes here are ordinary pods with the label
// warden.dev/sandbox=true that the policy selects. They run a busybox image
// from MCR, pinned by digest, into which the test copies the conformance
// probe (runtimes/conformance/guest, "net" mode). The probe reads only the
// instance's region from IMDS; it cannot ask for a token.
//
// The live test skips unless WARDEN_LIVE_AKS=1.
package aksdrill

import (
	"encoding/json"
	"errors"
	"strings"
)

// Region is the drill cluster's region (AKS_REGION in scripts/azure_guard.py):
// what IMDS answers for the instance's location.
const Region = "swedencentral"

// IsRegion reports whether an IMDS location answer is Region. IMDS gives
// the display casing ("SwedenCentral"), so case does not count.
func IsRegion(body string) bool { return strings.EqualFold(strings.TrimSpace(body), Region) }

// IMDSLocationURL is the probe's only metadata request (imdsLocationURL in
// runtimes/conformance/guest/net.go).
const IMDSLocationURL = "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text"

// ProbePod is a test pod running image as nobody: no service account token,
// a read-only root, no capabilities, and an emptyDir at /work for the
// probe. It sleeps unless command says otherwise.
func ProbePod(name, namespace, image string, labels map[string]string, command ...string) map[string]any {
	l := map[string]string{"app": name, "warden.dev/test": "aks-drill"}
	for k, v := range labels {
		l[k] = v
	}
	if len(command) == 0 {
		command = []string{"sleep", "3600"}
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": namespace, "labels": l},
		"spec": map[string]any{
			"automountServiceAccountToken": false, "enableServiceLinks": false, "hostNetwork": false,
			"terminationGracePeriodSeconds": 1, "restartPolicy": "Never",
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65534, "runAsGroup": 65534,
				"seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			"containers": []map[string]any{{
				"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
				"resources": map[string]any{"requests": map[string]string{"cpu": "10m", "memory": "32Mi"},
					"limits": map[string]string{"cpu": "200m", "memory": "128Mi"}},
				"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
					"capabilities": map[string]any{"drop": []string{"ALL"}}},
				"volumeMounts": []map[string]any{{"name": "work", "mountPath": "/work"}},
			}},
			"volumes": []map[string]any{{"name": "work", "emptyDir": map[string]any{"sizeLimit": "64Mi"}}},
		},
	}
}

// DefaultDenyOff reports whether a CiliumClusterwideNetworkPolicy as the
// API server stored it (kubectl get -o json) still turns default deny off
// in both directions. A CRD schema that does not know enableDefaultDeny
// drops it, and then a deny-only policy puts its endpoints in default deny.
func DefaultDenyOff(raw []byte) (bool, error) {
	var p struct {
		Spec *struct {
			EnableDefaultDeny *struct {
				Egress  *bool `json:"egress"`
				Ingress *bool `json:"ingress"`
			} `json:"enableDefaultDeny"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return false, err
	}
	if p.Spec == nil {
		return false, errors.New("aksdrill: not a policy with a spec")
	}
	d := p.Spec.EnableDefaultDeny
	return d != nil && d.Egress != nil && !*d.Egress && d.Ingress != nil && !*d.Ingress, nil
}
