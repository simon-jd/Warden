package conformance

// Task 7: workload identity and metadata isolation. The offline tests run in
// make test. The live ones need WARDEN_LIVE_IDENTITY=1 and either the k3s
// lab of scripts/k3s_gvisor_lab.sh (make test-identity) or, with
// WARDEN_IDENTITY_TARGET=aks, the AKS drill's cluster (scripts/aks_drill.py,
// make test-aks), where the control plane's service account federates with
// a managed identity. IDENTITY_OUT=<file> keeps one JSON line per checked
// item. No token is ever written out: only its decoded claims, and on AKS
// only the claims that identify nothing (raw claims go to the drill's
// private directory, WARDEN_PRIVATE_OUT).
//
// TestSandboxCannotReachMetadata is in controlplane/internal/ciliumlab (the
// k3s lab's Cilium mode, make test-cilium) and controlplane/internal/aksdrill
// (the real Azure IMDS on the AKS drill): it needs a node that enforces
// policies/cilium/deny-metadata.yaml.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"warden/identity/workload"
	"warden/respond/kindlab"
)

const (
	// The namespace scripts/k3s_gvisor_lab.sh runs sandboxes in.
	sandboxNamespace     = "warden-lab"
	controlPlaneManifest = "../../identity/kubernetes/controlplane.json"
	denyMetadataPolicy   = "../../policies/cilium/deny-metadata.yaml"
	// Plan, Task 7: the control plane's tokens live at most an hour.
	maxTokenLifetime = 3600
	// The control plane image is not in the lab; its pod runs the lab's pause
	// binary with the manifest's pod spec otherwise unchanged.
	labStandInImage = "docker.io/warden-lab/pause:1"
)

// --- RBAC: who can act as a sandbox account -------------------------------

type rbacSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type rbacBinding struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace,omitempty"`
	} `json:"metadata"`
	RoleRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Subjects []rbacSubject `json:"subjects"`
}

// subjectReaches reports whether s names a service account of ns: one of
// them directly, by user name, or through the namespace or all-accounts
// groups. system:authenticated is left out on purpose: every identity has
// it and the cluster defaults bind it to discovery roles. What it grants is
// covered by the access reviews of TestSandboxSAHasNoBindings.
func subjectReaches(ns string, s rbacSubject) bool {
	switch s.Kind {
	case "ServiceAccount":
		return s.Namespace == ns
	case "User":
		return strings.HasPrefix(s.Name, "system:serviceaccount:"+ns+":")
	case "Group":
		return s.Name == "system:serviceaccounts" || s.Name == "system:serviceaccounts:"+ns
	}
	return false
}

type bindingMatch struct {
	Binding rbacBinding
	Subject rbacSubject
}

func (m bindingMatch) String() string {
	where := m.Binding.Metadata.Name
	if m.Binding.Metadata.Namespace != "" {
		where = m.Binding.Metadata.Namespace + "/" + where
	}
	return fmt.Sprintf("%s -> %s %s (%s %s/%s)", where, m.Binding.RoleRef.Kind, m.Binding.RoleRef.Name, m.Subject.Kind, m.Subject.Namespace, m.Subject.Name)
}

// bindingsReaching lists every binding subject that reaches a service
// account of ns.
func bindingsReaching(ns string, bindings []rbacBinding) []bindingMatch {
	var out []bindingMatch
	for _, b := range bindings {
		for _, s := range b.Subjects {
			if subjectReaches(ns, s) {
				out = append(out, bindingMatch{b, s})
			}
		}
	}
	return out
}

// Kubernetes' bootstrap policy binds this ClusterRole to every service
// account (Group system:serviceaccounts). Its role lets a caller GET the
// service account issuer's OIDC discovery document and public keys, which
// federation publishes anyway. It is the one binding accepted, and only
// while the role grants nothing else (issuerDiscoveryOnly, checked live).
const issuerDiscovery = "system:service-account-issuer-discovery"

var issuerDiscoveryURLs = map[string]bool{"/.well-known/openid-configuration": true, "/.well-known/openid-configuration/": true,
	"/openid/v1/jwks": true, "/openid/v1/jwks/": true}

func isIssuerDiscovery(m bindingMatch) bool {
	b := m.Binding
	return b.Metadata.Namespace == "" && b.Metadata.Name == issuerDiscovery && b.RoleRef.Kind == "ClusterRole" && b.RoleRef.Name == issuerDiscovery
}

type rbacRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
	Verbs           []string `json:"verbs"`
}

// issuerDiscoveryOnly reports whether rules grant at most GET on the
// issuer's discovery URLs.
func issuerDiscoveryOnly(rules []rbacRule) bool {
	for _, r := range rules {
		if len(r.APIGroups)+len(r.Resources)+len(r.ResourceNames) > 0 || len(r.Verbs) != 1 || r.Verbs[0] != "get" {
			return false
		}
		for _, u := range r.NonResourceURLs {
			if !issuerDiscoveryURLs[u] {
				return false
			}
		}
	}
	return true
}

// Annotation prefixes that tie a Kubernetes service account to a cloud
// identity: AKS workload identity, GKE workload identity, EKS IRSA. EKS Pod
// Identity associations are kept in AWS, not on the account.
var workloadIdentityPrefixes = []string{"azure.workload.identity/", "iam.gke.io/", "eks.amazonaws.com/"}

func workloadIdentityAnnotations(annotations map[string]string) []string {
	var out []string
	for k := range annotations {
		for _, p := range workloadIdentityPrefixes {
			if strings.HasPrefix(k, p) {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestBindingsReachingFindsEveryWayToNameASandboxAccount(t *testing.T) {
	bind := func(ns, name string, subjects ...rbacSubject) rbacBinding {
		var b rbacBinding
		b.Metadata.Name, b.Metadata.Namespace = name, ns
		b.RoleRef.Kind, b.RoleRef.Name = "ClusterRole", "view"
		b.Subjects = subjects
		return b
	}
	reach := []rbacBinding{
		bind(sandboxNamespace, "account", rbacSubject{"ServiceAccount", "default", sandboxNamespace}),
		// A RoleBinding elsewhere still grants the account rights there.
		bind("kube-system", "elsewhere", rbacSubject{"ServiceAccount", "runner", sandboxNamespace}),
		bind("", "by-user-name", rbacSubject{"User", "system:serviceaccount:" + sandboxNamespace + ":default", ""}),
		bind("", "namespace-group", rbacSubject{"Group", "system:serviceaccounts:" + sandboxNamespace, ""}),
		bind("", "all-accounts", rbacSubject{"Group", "system:serviceaccounts", ""}),
		bind("", "second-subject", rbacSubject{"User", "alice", ""}, rbacSubject{"ServiceAccount", "default", sandboxNamespace}),
	}
	miss := []rbacBinding{
		bind("", "other-namespace", rbacSubject{"ServiceAccount", "default", "warden-system"}),
		bind("", "longer-group", rbacSubject{"Group", "system:serviceaccounts:" + sandboxNamespace + "-x", ""}),
		bind("", "longer-user", rbacSubject{"User", "system:serviceaccount:" + sandboxNamespace + "x:default", ""}),
		bind("", "discovery", rbacSubject{"Group", "system:authenticated", ""}),
		bind("", "no-subjects"),
	}
	for _, b := range reach {
		if got := bindingsReaching(sandboxNamespace, []rbacBinding{b}); len(got) != 1 {
			t.Errorf("%s: got %q, want one match", b.Metadata.Name, got)
		}
	}
	for _, b := range miss {
		if got := bindingsReaching(sandboxNamespace, []rbacBinding{b}); len(got) != 0 {
			t.Errorf("%s: got %q, want none", b.Metadata.Name, got)
		}
	}
}

func TestIssuerDiscoveryIsAcceptedOnlyWhileItGrantsDiscovery(t *testing.T) {
	var b rbacBinding
	b.Metadata.Name, b.RoleRef.Kind, b.RoleRef.Name = issuerDiscovery, "ClusterRole", issuerDiscovery
	all := rbacSubject{"Group", "system:serviceaccounts", ""}
	if !isIssuerDiscovery(bindingMatch{b, all}) {
		t.Error("the default binding is not recognised")
	}
	other := b
	other.RoleRef.Name = "view"
	inNamespace := b
	inNamespace.Metadata.Namespace = sandboxNamespace
	for _, m := range []bindingMatch{{other, all}, {inNamespace, all}} {
		if isIssuerDiscovery(m) {
			t.Errorf("accepted %s", m)
		}
	}
	// The rules Kubernetes v1.36 ships (seen in the k3s lab).
	shipped := []rbacRule{{NonResourceURLs: []string{"/.well-known/openid-configuration", "/.well-known/openid-configuration/",
		"/openid/v1/jwks", "/openid/v1/jwks/"}, Verbs: []string{"get"}}}
	if !issuerDiscoveryOnly(shipped) {
		t.Error("the shipped rules are refused")
	}
	for name, rules := range map[string][]rbacRule{
		"resource":   {{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		"other url":  {{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
		"wildcard":   {{NonResourceURLs: []string{"*"}, Verbs: []string{"get"}}},
		"other verb": {{NonResourceURLs: []string{"/openid/v1/jwks"}, Verbs: []string{"*"}}},
		"extra rule": {shipped[0], {NonResourceURLs: []string{"/openid/v1/jwks"}, Verbs: []string{"get", "post"}}},
	} {
		if issuerDiscoveryOnly(rules) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWorkloadIdentityAnnotationsAreTheCloudBindings(t *testing.T) {
	got := workloadIdentityAnnotations(map[string]string{
		"azure.workload.identity/client-id": "x", "iam.gke.io/gcp-service-account": "y",
		"eks.amazonaws.com/role-arn": "z", "kubernetes.io/description": "not a binding",
	})
	want := []string{"azure.workload.identity/client-id", "eks.amazonaws.com/role-arn", "iam.gke.io/gcp-service-account"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// --- deny-metadata.yaml ---------------------------------------------------

// The metadata endpoints a sandbox must never reach: the IMDS address every
// cloud uses, the GKE metadata server, the EKS Pod Identity agent, Azure's
// WireServer, and the IPv6 forms on EC2. The hostname forms
// (metadata.google.internal, ...) resolve to these addresses.
var metadataCIDRs = []string{"169.254.169.254/32", "169.254.169.252/32", "169.254.170.23/32",
	"168.63.129.16/32", "fd00:ec2::254/128", "fd00:ec2::23/128"}

// The policy has one document for sandboxes and one for the egress proxy,
// which resolves and connects for them, so both the IP and the hostname form
// end at the deny list. Deny rules win over every allow (an allowlist entry
// cannot reopen them), and the documents allow nothing themselves. Nor do
// they deny anything else: Cilium puts every endpoint a policy with egress
// rules selects, deny rules included, into default deny unless the policy
// says enableDefaultDeny false. Without that, applying deny-metadata.yaml
// alone cut all the sandboxes' and the proxy's egress, DNS too (the Cilium
// lab's runs/06-task7 in docs/evidence/task-10/cilium-lab-20261112).
func TestDenyMetadataPolicyCoversSandboxesAndTheirProxy(t *testing.T) {
	raw, err := os.ReadFile(denyMetadataPolicy)
	if err != nil {
		t.Fatal(err)
	}
	selectors := map[string][]string{
		"sandbox": {`warden.dev/sandbox: "true"`},
		"proxy":   {`k8s:io.kubernetes.pod.namespace: warden-system`, `app.kubernetes.io/name: warden-egress`},
	}
	cidrList := regexp.MustCompile(`(?m)^\s*- toCIDR: \[([^\]]*)\]\s*$`)
	seen := map[string]bool{}
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		if !strings.Contains(doc, "kind: CiliumClusterwideNetworkPolicy") {
			t.Errorf("document is not a CiliumClusterwideNetworkPolicy:\n%s", doc)
			continue
		}
		if regexp.MustCompile(`(?m)^  (egress|ingress):`).MatchString(doc) {
			t.Errorf("document allows traffic; it must only deny:\n%s", doc)
		}
		if !strings.Contains(doc, "\n  enableDefaultDeny:\n    egress: false\n    ingress: false\n") {
			t.Errorf("document does not turn default deny off (enableDefaultDeny: egress: false, ingress: false):\n%s", doc)
		}
		sel, _, _ := strings.Cut(doc[strings.Index(doc, "endpointSelector:")+1:], "egressDeny:")
		which := ""
		for name, labels := range selectors {
			all := true
			for _, l := range labels {
				all = all && strings.Contains(sel, l)
			}
			if all {
				which = name
			}
		}
		if which == "" {
			t.Errorf("document selects neither sandboxes nor the egress proxy:\n%s", doc)
			continue
		}
		seen[which] = true
		var got []string
		for _, m := range cidrList.FindAllStringSubmatch(doc, -1) {
			for _, c := range strings.Split(m[1], ",") {
				got = append(got, strings.TrimSpace(c))
			}
		}
		sort.Strings(got)
		want := append([]string(nil), metadataCIDRs...)
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: denies %q, want %q", which, got, want)
		}
	}
	for name := range selectors {
		if !seen[name] {
			t.Errorf("no document for the %s", name)
		}
	}
}

// --- live: the k3s lab -----------------------------------------------------

// cluster is where the live tests run: the k3s lab, or the AKS drill.
type cluster struct {
	api  kindlab.API
	node string    // k3s: the node container, to read what kubelet mounted
	aks  *aksDrill // AKS: set by WARDEN_IDENTITY_TARGET=aks
}

// aksDrill is what scripts/aks_drill.py env passes: the cluster's
// kubeconfig, the image the test pods run, the managed identity the control
// plane's service account federates with, and the Azure CLI, which the
// tests use only to read.
type aksDrill struct {
	kubectl, kubeconfig, image            string
	clientID, principalID, tenant, issuer string
	az, subscription, private             string
}

func (c cluster) target() string {
	if c.aks != nil {
		return "aks"
	}
	return "k3s"
}

func liveCluster(t *testing.T) cluster {
	t.Helper()
	if os.Getenv("WARDEN_LIVE_IDENTITY") != "1" {
		t.Skip("live identity test: needs WARDEN_LIVE_IDENTITY=1 and the lab of scripts/k3s_gvisor_lab.sh (make test-identity) or the AKS drill (make test-aks)")
	}
	aks := os.Getenv("WARDEN_IDENTITY_TARGET") == "aks"
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			if aks {
				t.Fatalf("%s is not set: run through `scripts/aks_drill.py env`", k)
			}
			t.Fatalf("%s is not set: run through `scripts/k3s_gvisor_lab.sh env`", k)
		}
		return v
	}
	kubeconfig, host := "WARDEN_GVISOR_KUBECONFIG", "WARDEN_GVISOR_API_HOST"
	if aks {
		kubeconfig, host = "WARDEN_AKS_KUBECONFIG", "WARDEN_AKS_API_HOST"
	}
	raw, err := os.ReadFile(env(kubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	c, err := kindlab.ParseKubeconfigFor(raw, env(host))
	if err != nil {
		t.Fatal(err)
	}
	hc, err := c.HTTPClient(true)
	if err != nil {
		t.Fatal(err)
	}
	out := cluster{api: kindlab.API{Server: c.Server, HTTP: hc}}
	if !aks {
		out.node = env("WARDEN_GVISOR_NODE_CONTAINER")
		return out
	}
	stop, err := time.Parse(time.RFC3339, env("WARDEN_AKS_HARD_STOP"))
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(stop); left < 15*time.Minute {
		t.Fatalf("the AKS drill's hard stop is %s away: too close to start a test", left.Round(time.Second))
	}
	out.aks = &aksDrill{kubectl: env("WARDEN_KUBECTL"), kubeconfig: env(kubeconfig), image: env("WARDEN_AKS_CARRIER_IMAGE"),
		clientID: env("WARDEN_AKS_CLIENT_ID"), principalID: env("WARDEN_AKS_PRINCIPAL_ID"), tenant: env("WARDEN_AKS_TENANT_ID"),
		issuer: env("WARDEN_AKS_ISSUER"), az: env("WARDEN_AZ"), subscription: env("WARDEN_AZ_SUBSCRIPTION"),
		private: env("WARDEN_PRIVATE_OUT")}
	return out
}

// readToken returns the token kubelet mounted for s in the pod.
func (c cluster) readToken(ctx context.Context, ns, name string, p pod, s tokenSource) (string, error) {
	if c.aks == nil {
		file := "/var/lib/kubelet/pods/" + p.Metadata.UID + "/volumes/kubernetes.io~projected/" + s.Volume + "/" + s.Path
		out, err := exec.CommandContext(ctx, "docker", "exec", c.node, "cat", file).Output()
		return strings.TrimSpace(string(out)), err
	}
	container, dir := p.mount(s.Volume)
	if dir == "" {
		return "", fmt.Errorf("no container mounts volume %s", s.Volume)
	}
	out, err := c.aks.kube(ctx, "-n", ns, "exec", name, "-c", container, "--", "cat", strings.TrimRight(dir, "/")+"/"+s.Path)
	return strings.TrimSpace(string(out)), err
}

func (a *aksDrill) kube(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, a.kubectl, append([]string{"--kubeconfig", a.kubeconfig}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// azJSON runs a read-only Azure CLI command and decodes its answer. Graph
// commands (az ad ...) take no subscription.
func (a *aksDrill) azJSON(ctx context.Context, out any, args ...string) error {
	if args[0] != "ad" {
		args = append(args, "--subscription", a.subscription)
	}
	cmd := exec.CommandContext(ctx, a.az, append(args, "--output", "json", "--only-show-errors")...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		code := regexp.MustCompile(`\(([A-Za-z0-9]+)\)`).FindStringSubmatch(stderr.String())
		if len(code) == 2 {
			return fmt.Errorf("az %s: %s", strings.Join(args[:2], " "), code[1])
		}
		return fmt.Errorf("az %s: %v", strings.Join(args[:2], " "), err)
	}
	return json.Unmarshal(raw, out)
}

// private writes v (which may hold IDs, never a token) to the drill's
// private directory, outside the repository.
func (a *aksDrill) privateRecord(t *testing.T, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.private, name), append(b, '\n'), 0o600); err != nil {
		t.Error(err)
	}
}

// wellKnownAudiences identify nothing; any other audience (on AKS, the API
// server's FQDN) is kept in evidence only as a digest.
var wellKnownAudiences = map[string]bool{workload.FederationAudience: true, "https://management.azure.com/": true}

func publicAudience(aud []string) []string {
	out := make([]string, len(aud))
	for i, a := range aud {
		if wellKnownAudiences[a] {
			out[i] = a
			continue
		}
		sum := sha256.Sum256([]byte(a))
		out[i] = "sha256:" + hex.EncodeToString(sum[:8])
	}
	return out
}

// exchange trades a federated service account token for an Entra access
// token for Azure Resource Manager: a token that, with no role
// assignments, can do nothing.
func (a *aksDrill) exchange(ctx context.Context, assertion string) (workload.Token, error) {
	x := workload.Exchanger{HTTP: &http.Client{Timeout: 30 * time.Second}}
	return x.Exchange(ctx, a.tenant, a.clientID, assertion, "https://management.azure.com/.default")
}

// tokenRequest asks the API server for a token of a service account, with
// the federation audience and 10 minutes to live.
func (c cluster) tokenRequest(ctx context.Context, ns, sa string) (string, error) {
	rq := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{"audiences": []string{workload.FederationAudience}, "expirationSeconds": 600}}
	var out struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	err := c.api.Do(ctx, "POST", "/api/v1/namespaces/"+ns+"/serviceaccounts/"+sa+"/token", "", rq, &out)
	return out.Status.Token, err
}

func record(t *testing.T, v map[string]any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("result: %s", b)
	if path := os.Getenv("IDENTITY_OUT"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func poll(ctx context.Context, every time.Duration, f func() (bool, error)) error {
	for {
		done, err := f()
		if done || err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

// --- live: the control plane's token ---------------------------------------

type manifestList struct {
	Items []json.RawMessage `json:"items"`
}

type object struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace,omitempty"`
		UID         string            `json:"uid,omitempty"`
		Labels      map[string]string `json:"labels,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec map[string]any `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type tokenSource struct {
	Volume            string
	Path              string
	Audience          string
	ExpirationSeconds int64
}

type pod struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Name string `json:"name"`
			Env  []struct {
				Name string `json:"name"`
			} `json:"env"`
			VolumeMounts []struct {
				Name      string `json:"name"`
				MountPath string `json:"mountPath"`
			} `json:"volumeMounts"`
		} `json:"containers"`
		Volumes []struct {
			Name      string `json:"name"`
			Projected *struct {
				Sources []struct {
					ServiceAccountToken *struct {
						Audience          string `json:"audience"`
						ExpirationSeconds int64  `json:"expirationSeconds"`
						Path              string `json:"path"`
					} `json:"serviceAccountToken"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

// mount is the first container that mounts volume, and where.
func (p pod) mount(volume string) (container, dir string) {
	for _, c := range p.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == volume {
				return c.Name, m.MountPath
			}
		}
	}
	return "", ""
}

// envNames is every environment variable name the containers get, as the
// API server stored the spec (what a webhook added included).
func (p pod) envNames() []string {
	var out []string
	for _, c := range p.Spec.Containers {
		for _, e := range c.Env {
			out = append(out, c.Name+"/"+e.Name)
		}
	}
	sort.Strings(out)
	return out
}

// tokenSources is every service account token the pod gets, as the API
// server stored the spec (admission-injected volumes included).
func (p pod) tokenSources() []tokenSource {
	var out []tokenSource
	for _, v := range p.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, s := range v.Projected.Sources {
			if s.ServiceAccountToken != nil {
				out = append(out, tokenSource{v.Name, s.ServiceAccountToken.Path, s.ServiceAccountToken.Audience, s.ServiceAccountToken.ExpirationSeconds})
			}
		}
	}
	return out
}

type tokenClaims struct {
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud []string `json:"aud"`
	Exp int64    `json:"exp"`
	Iat int64    `json:"iat"`
	K8s struct {
		Pod struct {
			UID string `json:"uid"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

func decodeClaims(token string) (tokenClaims, error) {
	var c tokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("token has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(payload, &c)
}

func TestDecodeClaimsReadsTheServiceAccountFields(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://kubernetes.default.svc.cluster.local","sub":"system:serviceaccount:a:b",` +
		`"aud":["api://AzureADTokenExchange"],"exp":1700003600,"iat":1700000000,"kubernetes.io":{"pod":{"name":"p","uid":"u-1"}}}`))
	c, err := decodeClaims("e30." + payload + ".c2ln")
	if err != nil {
		t.Fatal(err)
	}
	if c.Exp-c.Iat != 3600 || c.Sub != "system:serviceaccount:a:b" || c.K8s.Pod.UID != "u-1" || len(c.Aud) != 1 {
		t.Fatalf("decoded %+v", c)
	}
	if _, err := decodeClaims("not-a-jwt"); err == nil {
		t.Fatal("accepted a non-JWT")
	}
}

// controlPlane is identity/kubernetes/controlplane.json taken apart.
type controlPlane struct {
	ns, sa   string
	nsItem   json.RawMessage
	accounts []json.RawMessage
	deploy   object
}

func readControlPlane(t *testing.T) controlPlane {
	t.Helper()
	raw, err := os.ReadFile(controlPlaneManifest)
	if err != nil {
		t.Fatal(err)
	}
	var list manifestList
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	var cp controlPlane
	var saNamespaces []string
	for _, item := range list.Items {
		var o object
		if err := json.Unmarshal(item, &o); err != nil {
			t.Fatal(err)
		}
		switch o.Kind {
		case "Namespace":
			cp.ns, cp.nsItem = o.Metadata.Name, item
		case "ServiceAccount":
			cp.sa = o.Metadata.Name
			saNamespaces = append(saNamespaces, o.Metadata.Namespace)
			cp.accounts = append(cp.accounts, item)
		case "Deployment":
			cp.deploy = o
		default:
			t.Fatalf("unexpected %s in the manifest", o.Kind)
		}
	}
	if cp.ns == "" || cp.sa == "" || cp.deploy.Spec.Template.Spec == nil {
		t.Fatal("manifest needs a Namespace, a ServiceAccount and a Deployment")
	}
	for _, n := range saNamespaces {
		if n != cp.ns {
			t.Fatalf("a ServiceAccount is in namespace %q, not the manifest's %s", n, cp.ns)
		}
	}
	return cp
}

// aksWorkloadIdentity is what AKS workload identity needs on top of the
// manifest: the service account names the managed identity's client ID.
// The pod label azure.workload.identity/use (added to the pod below) makes
// the AKS webhook inject its variables and token; the manifest already
// projects that token itself, and the test checks whatever the stored spec
// ends up with.
func aksWorkloadIdentity(t *testing.T, accounts []json.RawMessage, clientID string) []json.RawMessage {
	t.Helper()
	var out []json.RawMessage
	for _, item := range accounts {
		var sa map[string]any
		if err := json.Unmarshal(item, &sa); err != nil {
			t.Fatal(err)
		}
		meta := sa["metadata"].(map[string]any)
		annotations, _ := meta["annotations"].(map[string]any)
		if annotations == nil {
			annotations = map[string]any{}
		}
		annotations["azure.workload.identity/client-id"] = clientID
		meta["annotations"] = annotations
		b, err := json.Marshal(sa)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// TestControlPlaneTokenIsShortLived runs the control plane's pod spec from
// identity/kubernetes/controlplane.json and reads every service account
// token kubelet mounts for it. Each must live at most an hour, belong to
// the control plane's account, be bound to the pod, and be accepted by the
// API server. On AKS the federation token is also exchanged for an Entra
// access token (through the managed identity's federated credential), and
// that token must live at most an hour too.
func TestControlPlaneTokenIsShortLived(t *testing.T) {
	lab := liveCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cp := readControlPlane(t)
	ns, sa, deploy := cp.ns, cp.sa, cp.deploy
	accounts := cp.accounts
	if lab.aks != nil {
		accounts = aksWorkloadIdentity(t, accounts, lab.aks.clientID)
	}
	if err := createNamespace(ctx, t, lab.api, ns, cp.nsItem, accounts); err != nil {
		t.Fatal(err)
	}

	spec := deploy.Spec.Template.Spec
	containers, _ := spec["containers"].([]any)
	for _, c := range containers {
		if lab.aks == nil {
			c.(map[string]any)["image"] = labStandInImage
			c.(map[string]any)["imagePullPolicy"] = "Never"
		} else {
			c.(map[string]any)["image"] = lab.aks.image
			c.(map[string]any)["imagePullPolicy"] = "IfNotPresent"
			c.(map[string]any)["command"] = []string{"sleep", "3600"}
		}
	}
	labels := map[string]string{}
	for k, v := range deploy.Spec.Template.Metadata.Labels {
		labels[k] = v
	}
	if lab.aks != nil {
		labels["azure.workload.identity/use"] = "true"
	}
	name := deploy.Metadata.Name + "-token-check"
	body := map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": labels}, "spec": spec}
	podPath := "/api/v1/namespaces/" + ns + "/pods/" + name
	if err := lab.api.Do(ctx, "POST", "/api/v1/namespaces/"+ns+"/pods", "", body, nil); err != nil {
		t.Fatalf("create pod: %v", err)
	}
	var p pod
	if err := poll(ctx, 500*time.Millisecond, func() (bool, error) {
		err := lab.api.Do(ctx, "GET", podPath, "", nil, &p)
		return err == nil && p.Status.Phase == "Running", err
	}); err != nil {
		t.Fatalf("pod not Running (phase %q): %v", p.Status.Phase, err)
	}
	sources := p.tokenSources()
	if len(sources) == 0 {
		t.Fatal("the control plane pod gets no service account token; it needs one for the API server")
	}
	wantSub := "system:serviceaccount:" + ns + ":" + sa
	exchanged := 0
	for _, s := range sources {
		token, err := lab.readToken(ctx, ns, name, p, s)
		if err != nil {
			t.Fatalf("%s: read the mounted token: %v", s.Volume, err)
		}
		c, err := decodeClaims(token)
		if err != nil {
			t.Fatalf("%s: %v", s.Volume, err)
		}
		var review struct {
			Status struct {
				Authenticated bool `json:"authenticated"`
				User          struct {
					Username string `json:"username"`
				} `json:"user"`
			} `json:"status"`
		}
		rq := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
			"spec": map[string]any{"token": token, "audiences": c.Aud}}
		if err := lab.api.Do(ctx, "POST", "/apis/authentication.k8s.io/v1/tokenreviews", "", rq, &review); err != nil {
			t.Fatalf("%s: token review: %v", s.Volume, err)
		}
		lifetime := c.Exp - c.Iat
		result := map[string]any{"test": t.Name(), "target": lab.target(), "volume": s.Volume, "path": s.Path,
			"requested_audience": s.Audience, "requested_expiration_s": s.ExpirationSeconds,
			"iss": c.Iss, "aud": c.Aud, "sub": c.Sub, "lifetime_s": lifetime,
			"bound_to_pod": c.K8s.Pod.UID == p.Metadata.UID, "token_review_authenticated": review.Status.Authenticated,
			"token_review_user": review.Status.User.Username}
		if lifetime > maxTokenLifetime {
			t.Errorf("%s: token lives %d s (exp - iat), want <= %d", s.Volume, lifetime, maxTokenLifetime)
		}
		if c.Sub != wantSub {
			t.Errorf("%s: sub %q, want %q", s.Volume, c.Sub, wantSub)
		}
		if c.K8s.Pod.UID != p.Metadata.UID {
			t.Errorf("%s: token is not bound to the pod", s.Volume)
		}
		if !review.Status.Authenticated || review.Status.User.Username != wantSub {
			t.Errorf("%s: API server does not accept the token as %s", s.Volume, wantSub)
		}
		if lab.aks != nil {
			// The issuer URL names the tenant and the cluster; an audience
			// may be the API server's FQDN.
			result["iss"] = "<the cluster's OIDC issuer>"
			if strings.TrimRight(c.Iss, "/") != strings.TrimRight(lab.aks.issuer, "/") {
				result["iss"] = publicAudience([]string{c.Iss})[0] + " (not the cluster's issuer)"
			}
			result["aud"] = publicAudience(c.Aud)
			result["pod_env"] = p.envNames()
			if len(c.Aud) == 1 && c.Aud[0] == workload.FederationAudience {
				exchanged++
				entra(ctx, t, lab.aks, s.Volume, token, result)
			}
		}
		record(t, result)
	}
	if lab.aks != nil && exchanged == 0 {
		t.Errorf("no token with audience %s: nothing to exchange for an Entra token", workload.FederationAudience)
	}
}

// entra exchanges the federation token for an Entra access token and
// checks that token's lifetime too. Only public claims go into result; the
// raw claims (never the token) go to the private directory.
func entra(ctx context.Context, t *testing.T, a *aksDrill, volume, assertion string, result map[string]any) {
	t.Helper()
	tok, err := a.exchange(ctx, assertion)
	if err != nil {
		result["entra_error"] = err.Error()
		t.Errorf("%s: exchange for an Entra token: %v", volume, err)
		return
	}
	claims, err := workload.Claims(tok.Value())
	if err != nil {
		t.Errorf("%s: Entra access token: %v", volume, err)
		return
	}
	life, err := workload.Lifetime(claims)
	if err != nil {
		t.Errorf("%s: Entra access token: %v", volume, err)
		return
	}
	result["entra_lifetime_s"] = life
	result["entra_expires_in_s"] = tok.ExpiresIn
	result["entra_token_type"] = tok.Type
	pub := workload.Public(claims)
	if aud, ok := pub["aud"].(string); ok {
		pub["aud"] = publicAudience([]string{aud})[0]
	}
	result["entra_claims"] = pub
	a.privateRecord(t, "entra-claims-"+volume+".json", claims)
	if life > maxTokenLifetime {
		t.Errorf("%s: the Entra access token lives %d s (exp - iat), want <= %d", volume, life, maxTokenLifetime)
	}
}

// cleanups is the part of testing.TB that createNamespace needs.
type cleanups interface {
	Cleanup(func())
	Errorf(format string, args ...any)
}

// createNamespace creates the namespace name from nsItem and then the
// service accounts in it. The namespace's deletion is registered with tb
// before the first request, so a failure on the way leaves nothing behind.
// A namespace of that name that is already there was left by an earlier run
// (IDENTITY_REUSE=1 keeps the lab between runs, and a killed run skips its
// cleanups) or is still being deleted by one: it is deleted, and created
// again once it is gone, so the test sees only the manifest's objects.
func createNamespace(ctx context.Context, tb cleanups, api kindlab.API, name string, nsItem json.RawMessage, accounts []json.RawMessage) error {
	path := "/api/v1/namespaces/" + name
	remove := func(ctx context.Context) error {
		_ = api.Do(ctx, "DELETE", path, "", nil, nil)
		return poll(ctx, 500*time.Millisecond, func() (bool, error) {
			err := api.Do(ctx, "GET", path, "", nil, nil)
			return kindlab.IsStatus(err, 404), nil
		})
	}
	tb.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		if err := remove(cctx); err != nil {
			tb.Errorf("namespace %s still there: %v", name, err)
		}
	})
	err := api.Do(ctx, "POST", "/api/v1/namespaces", "", nsItem, nil)
	if kindlab.IsStatus(err, 409) {
		if err := remove(ctx); err != nil {
			return fmt.Errorf("namespace %s from an earlier run is still there: %w", name, err)
		}
		err = api.Do(ctx, "POST", "/api/v1/namespaces", "", nsItem, nil)
	}
	if err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}
	for _, item := range accounts {
		if err := api.Do(ctx, "POST", path+"/serviceaccounts", "", item, nil); err != nil {
			return fmt.Errorf("create service account: %w", err)
		}
	}
	return nil
}

// --- live: the sandbox namespace's accounts --------------------------------

type serviceAccount struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
}

// What a sandbox account must not be able to do. Each is a resource
// attribute of a SubjectAccessReview: namespace ("" for every namespace or
// a cluster resource), verb, group, resource, subresource.
var sensitiveAccess = [][5]string{
	{sandboxNamespace, "get", "", "secrets", ""},
	{sandboxNamespace, "list", "", "secrets", ""},
	{"", "list", "", "secrets", ""},
	{sandboxNamespace, "get", "", "configmaps", ""},
	{sandboxNamespace, "list", "", "pods", ""},
	{sandboxNamespace, "create", "", "pods", ""},
	{sandboxNamespace, "create", "", "pods", "exec"},
	{sandboxNamespace, "create", "", "serviceaccounts", "token"},
	{sandboxNamespace, "create", "batch", "jobs", ""},
	{sandboxNamespace, "create", "rbac.authorization.k8s.io", "rolebindings", ""},
	{"", "list", "", "nodes", ""},
	{"", "impersonate", "", "users", ""},
	{"", "create", "authentication.k8s.io", "tokenreviews", ""},
}

func (l cluster) allowed(ctx context.Context, account string, a [5]string) (bool, error) {
	rq := map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": map[string]any{
		"user":               "system:serviceaccount:" + sandboxNamespace + ":" + account,
		"groups":             []string{"system:serviceaccounts", "system:serviceaccounts:" + sandboxNamespace, "system:authenticated"},
		"resourceAttributes": map[string]string{"namespace": a[0], "verb": a[1], "group": a[2], "resource": a[3], "subresource": a[4]},
	}}
	var out struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	err := l.api.Do(ctx, "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", "", rq, &out)
	return out.Status.Allowed, err
}

func (l cluster) bindings(ctx context.Context) (all int, reaching []bindingMatch, err error) {
	for _, path := range []string{"/apis/rbac.authorization.k8s.io/v1/rolebindings", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"} {
		var list struct {
			Items []rbacBinding `json:"items"`
		}
		if err := l.api.Do(ctx, "GET", path, "", nil, &list); err != nil {
			return 0, nil, err
		}
		all += len(list.Items)
		reaching = append(reaching, bindingsReaching(sandboxNamespace, list.Items)...)
	}
	return all, reaching, nil
}

// TestSandboxSAHasNoBindings checks every service account of the sandbox
// namespace: no RBAC binding names it (or its groups), no annotation ties it
// to a cloud identity, it has no long-lived token Secret, and the API server
// denies it every sensitive access. A planted RoleBinding shows the checks
// see a binding, and is removed again. On AKS, also: no federated
// credential anywhere names a sandbox account, Entra refuses to exchange a
// sandbox account's token, and so no Azure role assignment can reach one
// (azureFederation).
func TestSandboxSAHasNoBindings(t *testing.T) {
	lab := liveCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	nsPath := "/api/v1/namespaces/" + sandboxNamespace
	var accounts []serviceAccount
	// The namespace controller adds "default" shortly after the namespace.
	if err := poll(ctx, 500*time.Millisecond, func() (bool, error) {
		var list struct {
			Items []serviceAccount `json:"items"`
		}
		err := lab.api.Do(ctx, "GET", nsPath+"/serviceaccounts", "", nil, &list)
		accounts = list.Items
		return err == nil && len(accounts) > 0, err
	}); err != nil {
		t.Fatalf("list service accounts: %v", err)
	}
	var names []string
	for _, sa := range accounts {
		names = append(names, sa.Metadata.Name)
		if wi := workloadIdentityAnnotations(sa.Metadata.Annotations); len(wi) > 0 {
			t.Errorf("%s: workload identity annotations %q", sa.Metadata.Name, wi)
		}
	}
	var secrets struct {
		Items []json.RawMessage `json:"items"`
	}
	sel := url.QueryEscape("type=kubernetes.io/service-account-token")
	if err := lab.api.Do(ctx, "GET", nsPath+"/secrets?fieldSelector="+sel, "", nil, &secrets); err != nil {
		t.Fatal(err)
	}
	if len(secrets.Items) > 0 {
		t.Errorf("%d long-lived service account token Secrets in %s", len(secrets.Items), sandboxNamespace)
	}
	scanned, reaching, err := lab.bindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var unexpected, accepted []string
	for _, m := range reaching {
		if !isIssuerDiscovery(m) {
			unexpected = append(unexpected, m.String())
			continue
		}
		var role struct {
			Rules []rbacRule `json:"rules"`
		}
		if err := lab.api.Do(ctx, "GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles/"+issuerDiscovery, "", nil, &role); err != nil {
			t.Fatal(err)
		}
		if !issuerDiscoveryOnly(role.Rules) {
			unexpected = append(unexpected, m.String()+" (role grants more than issuer discovery)")
			continue
		}
		accepted = append(accepted, m.String())
	}
	if len(unexpected) > 0 {
		t.Errorf("bindings reach the sandbox accounts: %q", unexpected)
	}
	var granted []string
	for _, sa := range names {
		for _, a := range sensitiveAccess {
			ok, err := lab.allowed(ctx, sa, a)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				granted = append(granted, sa+": "+strings.Join(a[:], " "))
			}
		}
	}
	if len(granted) > 0 {
		t.Errorf("sandbox accounts are allowed: %q", granted)
	}

	// Positive control: bind "view" to the first account, see both checks
	// report it, remove it, see both clear.
	control := names[0]
	listPods := [5]string{sandboxNamespace, "list", "", "pods", ""}
	rb := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "warden-identity-control", "namespace": sandboxNamespace},
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
		"subjects": []map[string]any{{"kind": "ServiceAccount", "name": control, "namespace": sandboxNamespace}}}
	rbPath := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + sandboxNamespace + "/rolebindings"
	if err := lab.api.Do(ctx, "POST", rbPath, "", rb, nil); err != nil {
		t.Fatal(err)
	}
	removed := false
	t.Cleanup(func() {
		if !removed {
			_ = lab.api.Do(context.Background(), "DELETE", rbPath+"/warden-identity-control", "", nil, nil)
		}
	})
	seen := func(want bool) (time.Duration, error) {
		start := time.Now()
		err := poll(ctx, 100*time.Millisecond, func() (bool, error) {
			_, r, err := lab.bindings(ctx)
			if err != nil {
				return false, err
			}
			listed := false
			for _, m := range r {
				listed = listed || (m.Binding.Metadata.Namespace == sandboxNamespace && m.Binding.Metadata.Name == "warden-identity-control")
			}
			ok, err := lab.allowed(ctx, control, listPods)
			return listed == want && ok == want, err
		})
		return time.Since(start), err
	}
	visible, err := seen(true)
	if err != nil {
		t.Fatalf("planted binding not reported by both checks: %v", err)
	}
	if err := lab.api.Do(ctx, "DELETE", rbPath+"/warden-identity-control", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	removed = true
	cleared, err := seen(false)
	if err != nil {
		t.Fatalf("checks still report the removed binding: %v", err)
	}
	result := map[string]any{"test": t.Name(), "target": lab.target(), "namespace": sandboxNamespace, "service_accounts": names,
		"bindings_scanned": scanned, "bindings_unexpected": unexpected, "bindings_accepted": accepted, "sensitive_checks": len(names) * len(sensitiveAccess),
		"sensitive_allowed": len(granted), "token_secrets": len(secrets.Items),
		"control_binding_seen_ms": visible.Milliseconds(), "control_binding_cleared_ms": cleared.Milliseconds()}
	if lab.aks != nil {
		result["azure"] = azureFederation(ctx, t, lab, names)
	}
	record(t, result)
}

type federatedCredential struct {
	Name      string   `json:"name"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Audiences []string `json:"audiences"`
}

// azureFederation is the Azure side of "no bindings" on AKS. A Kubernetes
// service account gets to Azure only through a federated credential that
// names its cluster's issuer and its subject, and Azure roles are granted to
// the identity that credential belongs to. So:
//
//  1. No federated credential with this cluster's issuer names a sandbox
//     account. The scan reads every user-assigned identity in the
//     subscription and every app registration the signed-in user owns (read
//     only); it must find the control plane's credential (positive control).
//  2. Entra refuses to exchange each sandbox account's token for the
//     managed identity (AADSTS70021 or 700213, no matching federated
//     identity record), and exchanges the control plane's (positive control).
//  3. Role assignments: the managed identity's are counted (the drill gives
//     it none), and any identity a sandbox credential named would be listed.
func azureFederation(ctx context.Context, t *testing.T, lab cluster, sandboxAccounts []string) map[string]any {
	t.Helper()
	a := lab.aks
	issuer := strings.TrimRight(a.issuer, "/")
	cp := readControlPlane(t)
	controlSubject := "system:serviceaccount:" + cp.ns + ":" + cp.sa
	sandboxPrefix := "system:serviceaccount:" + sandboxNamespace + ":"
	out := map[string]any{}
	private := map[string]any{}

	var identities []struct {
		Name          string `json:"name"`
		ResourceGroup string `json:"resourceGroup"`
		ClientID      string `json:"clientId"`
		PrincipalID   string `json:"principalId"`
	}
	if err := a.azJSON(ctx, &identities, "identity", "list"); err != nil {
		t.Fatal(err)
	}
	var withIssuer, sandboxCreds, sandboxPrincipals []string
	control, scanned := 0, 0
	check := func(owner string, fics []federatedCredential, principal string, ours bool) {
		scanned += len(fics)
		for _, f := range fics {
			if strings.TrimRight(f.Issuer, "/") != issuer {
				continue
			}
			where := owner + "/" + f.Name + " -> " + f.Subject
			withIssuer = append(withIssuer, where)
			switch {
			case strings.HasPrefix(f.Subject, sandboxPrefix):
				sandboxCreds = append(sandboxCreds, where)
				if principal != "" {
					sandboxPrincipals = append(sandboxPrincipals, principal)
				}
			case f.Subject == controlSubject && ours && len(f.Audiences) == 1 && f.Audiences[0] == workload.FederationAudience:
				control++
			}
		}
	}
	for _, id := range identities {
		var fics []federatedCredential
		if err := a.azJSON(ctx, &fics, "identity", "federated-credential", "list", "--identity-name", id.Name,
			"--resource-group", id.ResourceGroup); err != nil {
			t.Fatal(err)
		}
		check("identity "+id.Name, fics, id.PrincipalID, id.ClientID == a.clientID)
		private["identity "+id.ResourceGroup+"/"+id.Name] = fics
	}
	var apps []struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if err := a.azJSON(ctx, &apps, "ad", "app", "list", "--show-mine", "--all"); err != nil {
		t.Fatal(err)
	}
	for _, app := range apps {
		var fics []federatedCredential
		if err := a.azJSON(ctx, &fics, "ad", "app", "federated-credential", "list", "--id", app.ID); err != nil {
			t.Fatal(err)
		}
		check("app "+app.DisplayName, fics, "", false)
		private["app "+app.ID] = fics
	}
	out["identities_scanned"], out["apps_scanned"], out["federated_credentials_scanned"] = len(identities), len(apps), scanned
	out["credentials_with_this_issuer"], out["sandbox_credentials"] = withIssuer, sandboxCreds
	out["control_plane_credential_found"] = control
	if len(sandboxCreds) > 0 {
		t.Errorf("federated credentials name sandbox accounts: %q", sandboxCreds)
	}
	if control != 1 {
		t.Errorf("positive control: the scan found %d credentials for %s on the managed identity, want 1", control, controlSubject)
	}

	var refused []string
	for _, sa := range sandboxAccounts {
		tok, err := lab.tokenRequest(ctx, sandboxNamespace, sa)
		if err != nil {
			t.Fatalf("token request for %s: %v", sa, err)
		}
		_, err = a.exchange(ctx, tok)
		var e *workload.Error
		switch {
		case err == nil:
			t.Errorf("Entra exchanged the token of sandbox account %s for the managed identity", sa)
		case errors.As(err, &e) && (e.Has(70021) || e.Has(700213)):
			refused = append(refused, sa+": "+e.Error())
		default:
			t.Errorf("%s: the exchange failed, but not for want of a federated credential: %v", sa, err)
		}
	}
	out["sandbox_exchange_refused"] = refused
	if err := createNamespace(ctx, t, lab.api, cp.ns, cp.nsItem, aksWorkloadIdentity(t, cp.accounts, a.clientID)); err != nil {
		t.Fatal(err)
	}
	tok, err := lab.tokenRequest(ctx, cp.ns, cp.sa)
	if err != nil {
		t.Fatalf("token request for %s: %v", controlSubject, err)
	}
	if _, err := a.exchange(ctx, tok); err != nil {
		out["control_plane_exchange"] = err.Error()
		t.Errorf("positive control: Entra refused the control plane's token: %v", err)
	} else {
		out["control_plane_exchange"] = "ok"
	}

	var assignments []json.RawMessage
	if err := a.azJSON(ctx, &assignments, "role", "assignment", "list", "--assignee", a.principalID, "--all"); err != nil {
		t.Fatal(err)
	}
	out["managed_identity_role_assignments"] = len(assignments)
	private["managed identity role assignments"] = assignments
	sandboxAssignments := 0
	for _, principal := range sandboxPrincipals {
		var list []json.RawMessage
		if err := a.azJSON(ctx, &list, "role", "assignment", "list", "--assignee", principal, "--all"); err != nil {
			t.Fatal(err)
		}
		sandboxAssignments += len(list)
	}
	out["sandbox_identity_role_assignments"] = sandboxAssignments
	if sandboxAssignments > 0 {
		t.Errorf("identities federated with sandbox accounts hold %d role assignments", sandboxAssignments)
	}
	a.privateRecord(t, "federation-scan.json", private)
	return out
}

func TestAKSWorkloadIdentityNamesTheClientOnEveryAccount(t *testing.T) {
	cp := readControlPlane(t)
	out := aksWorkloadIdentity(t, cp.accounts, "client-1")
	if len(out) != len(cp.accounts) || len(out) == 0 {
		t.Fatalf("%d accounts in, %d out", len(cp.accounts), len(out))
	}
	for _, item := range out {
		var sa serviceAccount
		if err := json.Unmarshal(item, &sa); err != nil {
			t.Fatal(err)
		}
		if got := workloadIdentityAnnotations(sa.Metadata.Annotations); len(got) != 1 || sa.Metadata.Annotations[got[0]] != "client-1" {
			t.Fatalf("annotations %v", sa.Metadata.Annotations)
		}
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			t.Fatal("the account lost automountServiceAccountToken: false")
		}
	}
	// The manifest itself names no cloud identity: only the drill adds it.
	for _, item := range cp.accounts {
		var sa serviceAccount
		if err := json.Unmarshal(item, &sa); err != nil {
			t.Fatal(err)
		}
		if len(workloadIdentityAnnotations(sa.Metadata.Annotations)) != 0 {
			t.Fatal("identity/kubernetes/controlplane.json names a cloud identity")
		}
	}
}

func TestPodMountAndEnvNamesReadTheStoredSpec(t *testing.T) {
	var p pod
	raw := `{"spec":{"containers":[{"name":"c","env":[{"name":"B","value":"secret-ish"},{"name":"A"}],
		"volumeMounts":[{"name":"kube-api-token","mountPath":"/var/run/secrets/kubernetes.io/serviceaccount"},
		{"name":"azure-identity-token","mountPath":"/var/run/secrets/azure/tokens/"}]}]}}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if c, dir := p.mount("azure-identity-token"); c != "c" || dir != "/var/run/secrets/azure/tokens/" {
		t.Fatalf("mount: %q %q", c, dir)
	}
	if c, dir := p.mount("missing"); c != "" || dir != "" {
		t.Fatalf("mount of a missing volume: %q %q", c, dir)
	}
	if got := strings.Join(p.envNames(), " "); got != "c/A c/B" {
		t.Fatalf("envNames: %q", got)
	}
}

// On AKS the API server's audience is its FQDN, and the issuer names the
// tenant and the cluster: evidence keeps only the well-known audiences.
func TestPublicAudienceKeepsOnlyTheWellKnownAudiences(t *testing.T) {
	in := []string{"api://AzureADTokenExchange", "https://warden-lab-aks-x.hcp.swedencentral.azmk8s.io",
		`"warden-lab-aks-x.hcp.swedencentral.azmk8s.io"`, "https://management.azure.com/"}
	got := publicAudience(in)
	if len(got) != 4 || got[0] != in[0] || got[3] != in[3] {
		t.Fatalf("got %q", got)
	}
	for _, g := range got[1:3] {
		if !regexp.MustCompile(`^sha256:[0-9a-f]{16}$`).MatchString(g) || strings.Contains(g, "azmk8s") {
			t.Fatalf("not hidden: %q", g)
		}
	}
	if got[1] == got[2] || publicAudience(in[1:2])[0] != got[1] {
		t.Fatal("the digest is not a stable function of the audience")
	}
}
