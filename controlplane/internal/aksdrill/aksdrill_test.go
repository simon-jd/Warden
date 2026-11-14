package aksdrill

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProbePodRunsAsNobodyWithNothingToSpare(t *testing.T) {
	p := ProbePod("md-a", "warden-lab", "mcr.microsoft.com/azurelinux/busybox@sha256:x", map[string]string{"warden.dev/sandbox": "true"})
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var pod struct {
		Metadata struct {
			Name, Namespace string
			Labels          map[string]string
		}
		Spec struct {
			AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
			HostNetwork                  bool  `json:"hostNetwork"`
			SecurityContext              struct {
				RunAsNonRoot *bool `json:"runAsNonRoot"`
				RunAsUser    int   `json:"runAsUser"`
			} `json:"securityContext"`
			Containers []struct {
				Image           string   `json:"image"`
				Command         []string `json:"command"`
				SecurityContext struct {
					AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation"`
					ReadOnlyRootFilesystem   bool  `json:"readOnlyRootFilesystem"`
					Capabilities             struct {
						Drop []string `json:"drop"`
					} `json:"capabilities"`
				} `json:"securityContext"`
				VolumeMounts []struct {
					Name      string `json:"name"`
					MountPath string `json:"mountPath"`
				} `json:"volumeMounts"`
			} `json:"containers"`
			Volumes []struct {
				Name     string          `json:"name"`
				EmptyDir json.RawMessage `json:"emptyDir"`
			} `json:"volumes"`
		}
	}
	if err := json.Unmarshal(b, &pod); err != nil {
		t.Fatal(err)
	}
	s, c := pod.Spec, pod.Spec.Containers
	if pod.Metadata.Name != "md-a" || pod.Metadata.Namespace != "warden-lab" || pod.Metadata.Labels["warden.dev/sandbox"] != "true" ||
		pod.Metadata.Labels["warden.dev/test"] != "aks-drill" {
		t.Fatalf("metadata %+v", pod.Metadata)
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken || s.HostNetwork ||
		s.SecurityContext.RunAsNonRoot == nil || !*s.SecurityContext.RunAsNonRoot || s.SecurityContext.RunAsUser != 65534 {
		t.Fatalf("pod security %s", b)
	}
	if len(c) != 1 || c[0].Image != "mcr.microsoft.com/azurelinux/busybox@sha256:x" || strings.Join(c[0].Command, " ") != "sleep 3600" ||
		c[0].SecurityContext.AllowPrivilegeEscalation == nil || *c[0].SecurityContext.AllowPrivilegeEscalation ||
		!c[0].SecurityContext.ReadOnlyRootFilesystem || strings.Join(c[0].SecurityContext.Capabilities.Drop, ",") != "ALL" {
		t.Fatalf("container %s", b)
	}
	if len(c[0].VolumeMounts) != 1 || c[0].VolumeMounts[0].MountPath != "/work" || len(s.Volumes) != 1 || s.Volumes[0].EmptyDir == nil {
		t.Fatalf("volumes %s", b)
	}
	origin := ProbePod("origin", "warden-lab", "img", nil, "httpd", "-f")
	ob, _ := json.Marshal(origin)
	if !strings.Contains(string(ob), `"command":["httpd","-f"]`) {
		t.Fatalf("command not used: %s", ob)
	}
}

func TestDefaultDenyOffReadsTheStoredPolicy(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"spec":{"enableDefaultDeny":{"egress":false,"ingress":false},"egressDeny":[{}]}}`: true,
		`{"spec":{"egressDeny":[{}]}}`:                                                     false, // dropped by an older CRD schema: Cilium defaults to deny
		`{"spec":{"enableDefaultDeny":{"egress":false},"egressDeny":[{}]}}`:                false,
		`{"spec":{"enableDefaultDeny":{"egress":true,"ingress":false},"egressDeny":[{}]}}`: false,
	} {
		got, err := DefaultDenyOff([]byte(raw))
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v; want %v", raw, got, err, want)
		}
	}
	if _, err := DefaultDenyOff([]byte(`[]`)); err == nil {
		t.Error("accepted a non-object")
	}
}

func TestIMDSLocationURLIsTheProbes(t *testing.T) {
	src, err := os.ReadFile("../../../runtimes/conformance/guest/net.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "const imdsLocationURL = \""+IMDSLocationURL+"\"") {
		t.Fatal("IMDSLocationURL differs from the probe's imdsLocationURL")
	}
}

func TestRegionIsTheGuardsAKSRegion(t *testing.T) {
	src, err := os.ReadFile("../../../scripts/azure_guard.py")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\nAKS_REGION = '"+Region+"'\n") {
		t.Fatalf("Region %q is not AKS_REGION in scripts/azure_guard.py", Region)
	}
}

// IMDS answers the location in its display casing ("SwedenCentral" on the
// drill, runs/01), not the ARM name.
func TestIsRegionIgnoresCase(t *testing.T) {
	for body, want := range map[string]bool{"SwedenCentral": true, "swedencentral\n": true, "westus2": false, "": false,
		"SwedenCentral extra": false} {
		if got := IsRegion(body); got != want {
			t.Errorf("IsRegion(%q) = %v, want %v", body, got, want)
		}
	}
}
