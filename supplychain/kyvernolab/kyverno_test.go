package kyvernolab

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	githubIssuer = "https://token.actions.githubusercontent.com"
	slsaBuilder  = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
	slsaType     = "https://slsa.dev/provenance/v0.2"
	sbomType     = "https://cyclonedx.org/bom"
	scanType     = "https://warden.dev/attestations/grype-complete/v1"
	cisaSource   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	trustedRepo  = "warden-lab/warden"
	namespace    = "warden-sandbox"
)

func workflowFor(repo string) string {
	return "https://github.com/" + repo + "/.github/workflows/build.yml@refs/heads/main"
}

func provenance(repo string) map[string]any {
	return map[string]any{
		"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
		"builder":   map[string]any{"id": slsaBuilder},
		"invocation": map[string]any{"configSource": map[string]any{
			"uri":        "git+https://github.com/" + repo + "@refs/heads/main.git",
			"entryPoint": ".github/workflows/build.yml",
			"digest":     map[string]string{"sha1": "0123456789abcdef0123456789abcdef01234567"},
		}},
	}
}

// scanPredicate has the fields scripts/supplychain.py assess signs.
func scanPredicate(image, digest string, kev []string) map[string]any {
	return map[string]any{
		"schemaVersion": 1, "scanComplete": true, "scanner": "grype/0.121.0",
		"imageRepository": image, "imageDigest": digest, "dbValid": true,
		"kevCatalogSource": cisaSource, "kevCatalogCount": 1758,
		"fixableCritical": []string{}, "kevCves": kev,
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// trustLocalRoot swaps Fulcio/Rekor/CT for the test CA in every keyless
// attestor and returns how many it changed. Subject, issuer, conditions and
// digest binding are left exactly as rendered.
func trustLocalRoot(v any, rootPEM string) int {
	n := 0
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if keyless, ok := child.(map[string]any); ok && k == "keyless" {
				keyless["roots"] = rootPEM
				rekor, _ := keyless["rekor"].(map[string]any)
				if rekor == nil {
					rekor = map[string]any{}
				}
				rekor["ignoreTlog"] = true
				keyless["rekor"] = rekor
				keyless["ctlog"] = map[string]any{"ignoreSCT": true}
				n++
				continue
			}
			n += trustLocalRoot(child, rootPEM)
		}
	case []any:
		for _, child := range x {
			n += trustLocalRoot(child, rootPEM)
		}
	}
	return n
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestKyvernoAdmission runs the real Kyverno CLI against policies rendered by
// scripts/supplychain.py for four images in a loopback registry: unsigned,
// signed and clean, signed with a KEV in its scan, and signed by another
// repository's workflow. Expected per-rule results are in
// policies/kyverno/tests/*/kyverno-test.yaml.
func TestKyvernoAdmission(t *testing.T) {
	kyverno := os.Getenv("WARDEN_KYVERNO")
	if kyverno == "" {
		t.Skip("WARDEN_KYVERNO not set (make test-go sets it to .tools/kyverno/kyverno)")
	}
	root := repoRoot(t)
	reg := NewRegistry()
	srv := httptest.NewServer(reg)
	defer srv.Close()
	image := strings.TrimPrefix(srv.URL, "http://") + "/warden/api"

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	issue := func(subject string) *Identity {
		id, err := ca.Issue(subject, githubIssuer)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	trusted, slsa, other := issue(workflowFor(trustedRepo)), issue(slsaBuilder), issue(workflowFor("attacker/warden"))
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	publish := func(name string, signer *Identity, repo string, kev []string) string {
		digest, err := reg.PushImage(image, "/app/"+name, name+"\n")
		must(err)
		if signer == nil {
			return digest
		}
		must(reg.Attest(image, digest, slsa, slsaType, provenance(repo)))
		must(reg.Attest(image, digest, signer, sbomType, map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []any{}}))
		must(reg.Attest(image, digest, signer, scanType, scanPredicate(image, digest, kev)))
		must(reg.Sign(image, digest, signer))
		return digest
	}
	digests := map[string]string{
		"unsigned":       publish("unsigned", nil, "", nil),
		"signed-clean":   publish("signed-clean", trusted, trustedRepo, []string{}),
		"signed-kev":     publish("signed-kev", trusted, trustedRepo, []string{"CVE-2021-44228"}),
		"wrong-identity": publish("wrong-identity", other, "attacker/warden", []string{}),
	}

	work := t.TempDir()
	tests := filepath.Join(work, "kyverno")
	copyTree(t, filepath.Join(root, "policies", "kyverno"), tests)
	for name, digest := range digests {
		dir := filepath.Join(tests, "tests", name)
		// Each image gets the policy CI would render for its own digest.
		binding := filepath.Join(work, name+"-binding.json")
		writeJSON(t, binding, map[string]string{
			"repository": trustedRepo, "ref": "refs/heads/main", "image_repository": image,
			"image_digest": digest, "namespace": namespace,
			"slsa_subject": slsaBuilder, "slsa_builder_id": slsaBuilder,
		})
		rendered := filepath.Join(work, name+"-rendered")
		cmd := exec.Command("python3", "-I", filepath.Join(root, "scripts", "supplychain.py"),
			"render", "--binding", binding, "--output-dir", rendered)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("render %s: %v\n%s", name, err, out)
		}
		changed := 0
		for _, file := range []string{"verify-images.yaml", "block-kev.yaml"} {
			b, err := os.ReadFile(filepath.Join(rendered, file))
			must(err)
			var doc any
			must(json.Unmarshal(b, &doc))
			changed += trustLocalRoot(doc, ca.PEM)
			writeJSON(t, filepath.Join(dir, file), doc)
		}
		if changed != 4 {
			t.Fatalf("%s: expected 4 keyless attestors (signature, SLSA, SBOM, scan), rewrote %d", name, changed)
		}
		writeJSON(t, filepath.Join(dir, "resources.yaml"), map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": name, "namespace": namespace},
			"spec": map[string]any{"containers": []any{map[string]any{
				"name": "app", "image": image + "@" + digest}}},
		})
	}

	// Isolated HOME, docker config and TUF cache: no host registry
	// credentials, and an empty TUF dir shows no Sigstore root was fetched.
	home := filepath.Join(work, "home")
	must(os.MkdirAll(filepath.Join(home, "docker"), 0o700))
	must(os.WriteFile(filepath.Join(home, "docker", "config.json"), []byte("{}\n"), 0o600))
	cmd := exec.Command(kyverno, "test", filepath.Join(tests, "tests"),
		"--registry", "--require-tests", "--remove-color", "--detailed-results")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home,
		"DOCKER_CONFIG=" + filepath.Join(home, "docker"), "TUF_ROOT=" + filepath.Join(home, "tuf")}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	if dst := os.Getenv("KYVERNO_OUT"); dst != "" {
		must(os.WriteFile(dst, out.Bytes(), 0o644))
	}
	if runErr != nil {
		t.Fatalf("kyverno test failed: %v\n%s", runErr, out.String())
	}
	// 6 rows in the unbound default-deny test, plus 4 rules x 4 images, each
	// reported twice by Kyverno 1.19.2 (the verifyImages response and the
	// "unverified image" validate response).
	summary := regexp.MustCompile(`Test Summary: (\d+) tests passed and (\d+) tests failed`).FindStringSubmatch(out.String())
	if summary == nil || summary[1] != "38" || summary[2] != "0" {
		t.Fatalf("want 38 passed / 0 failed, got %v\n%s", summary, out.String())
	}
	if _, err := os.Stat(filepath.Join(home, "tuf")); err == nil {
		t.Fatalf("kyverno initialised a TUF cache; verification was not offline-only")
	}
	t.Logf("%s", out.String())
}
