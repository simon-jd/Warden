package gvisor_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"warden/runtimes"
	"warden/runtimes/gate"
	"warden/runtimes/gvisor"
)

// These are runtime-boundary code tests. No Kubernetes server or runsc is used.
type boundaryDriver struct {
	starts, reaps int
	startError    error
}

func (d *boundaryDriver) Start(context.Context, runtimes.Spec) (runtimes.Handle, error) {
	d.starts++
	if d.startError != nil {
		return nil, d.startError
	}
	return boundaryHandle{}, nil
}
func (d *boundaryDriver) Reap(context.Context, string) error { d.reaps++; return nil }

type boundaryHandle struct{}

func (boundaryHandle) Wait(context.Context) (runtimes.Exit, error) { return runtimes.Exit{}, nil }
func (boundaryHandle) Kill() error                                 { return nil }
func (boundaryHandle) Logs() io.ReadCloser                         { return io.NopCloser(strings.NewReader("")) }

const runID = "AAAAAAAAAAAAAAAAAAAAAAAAAA"

func identity() gvisor.BackendIdentity {
	return gvisor.BackendIdentity{
		APIServer: "https://127.0.0.1:6443", CASHA256: strings.Repeat("a", 64),
		ClusterUID: "cluster-incarnation-1", Namespace: "warden-lab", NamespaceUID: "namespace-incarnation-1",
		NodeName: "warden-lab-node", NodeUID: "node-incarnation-1", NodeConfigSHA256: strings.Repeat("b", 64),
	}
}
func dir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

// Break caught: an operator reopens consumed authority against a replacement backend.
func TestBackendReplacementRejectedBeforeRuntimeOperations(t *testing.T) {
	changes := map[string]func(*gvisor.BackendIdentity){
		"server":        func(i *gvisor.BackendIdentity) { i.APIServer = "https://127.0.0.2:6443" },
		"CA":            func(i *gvisor.BackendIdentity) { i.CASHA256 = strings.Repeat("c", 64) },
		"cluster":       func(i *gvisor.BackendIdentity) { i.ClusterUID = "cluster-incarnation-2" },
		"namespace UID": func(i *gvisor.BackendIdentity) { i.NamespaceUID = "namespace-incarnation-2" },
		"node name":     func(i *gvisor.BackendIdentity) { i.NodeName = "warden-lab-node-2" },
		"node UID":      func(i *gvisor.BackendIdentity) { i.NodeUID = "node-incarnation-2" },
		"node config":   func(i *gvisor.BackendIdentity) { i.NodeConfigSHA256 = strings.Repeat("c", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := dir(t)
			original := &boundaryDriver{}
			g, err := gvisor.Bind(p, "home-ubuntu", identity(), original)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.Start(context.Background(), runtimes.Spec{RunID: runID}); err != nil {
				t.Fatal(err)
			}
			i := identity()
			change(&i)
			replacement := &boundaryDriver{}
			if _, err = gvisor.Bind(p, "home-ubuntu", i, replacement); err == nil {
				t.Fatal("replacement acquired existing authority")
			}
			if replacement.starts != 0 || replacement.reaps != 0 {
				t.Fatal("replacement runtime contacted")
			}
			reopened, err := gvisor.Bind(p, "home-ubuntu", identity(), original)
			if err != nil {
				t.Fatal(err)
			}
			if reopened.Authority() != g.Authority() {
				t.Fatal("same backend lost authority")
			}
			if _, err = reopened.Start(context.Background(), runtimes.Spec{RunID: runID}); !errors.Is(err, gate.ErrConsumed) {
				t.Fatalf("relaunched consumed ID: %v", err)
			}
			if err = reopened.Reap(context.Background(), runID); err != nil {
				t.Fatal(err)
			}
			if original.starts != 1 || original.reaps != 1 {
				t.Fatal("original launch/recovery not preserved")
			}
		})
	}
}

// Break caught: a legacy/unknown record adopts a backend after a crash or migration.
func TestBindingRefusesLegacyUnknownAndOrphanedState(t *testing.T) {
	for _, kind := range []string{"legacy unused", "legacy consumed", "unknown", "orphaned"} {
		t.Run(kind, func(t *testing.T) {
			p := dir(t)
			switch kind {
			case "legacy unused", "legacy consumed":
				g, err := gate.New(p, "home-ubuntu", &boundaryDriver{})
				if err != nil {
					t.Fatal(err)
				}
				if kind == "legacy consumed" {
					if err = g.Reap(context.Background(), runID); err != nil {
						t.Fatal(err)
					}
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(p, "node"), []byte("home-ubuntu/0123456789abcdef0123456789abcdef\nbackend-v999:unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "orphaned":
				if err := os.WriteFile(filepath.Join(p, runID), []byte("launching\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := gvisor.Bind(p, "home-ubuntu", identity(), &boundaryDriver{}); err == nil {
				t.Fatal("adopted unbound existing state")
			}
		})
	}
	p := dir(t)
	if _, err := gvisor.Bind(p, "home-ubuntu", identity(), &boundaryDriver{}); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.New(p, "home-ubuntu", &boundaryDriver{}); err == nil {
		t.Fatal("legacy constructor bypassed required binding")
	}
}

// Break caught: adding identity persistence weakens existing ambiguous-launch tombstones.
func TestBoundGatePreservesAmbiguityAcrossReopen(t *testing.T) {
	p := dir(t)
	d := &boundaryDriver{startError: errors.New("response lost; server may create later")}
	g, err := gvisor.Bind(p, "home-ubuntu", identity(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.Start(context.Background(), runtimes.Spec{RunID: runID}); err == nil {
		t.Fatal("expected transport error")
	}
	for range 2 {
		g, err = gvisor.Bind(p, "home-ubuntu", identity(), d)
		if err != nil {
			t.Fatal(err)
		}
		if err = g.Reap(context.Background(), runID); !errors.Is(err, gate.ErrAmbiguous) {
			t.Fatalf("not-found cleared ambiguity: %v", err)
		}
		if _, err = g.Start(context.Background(), runtimes.Spec{RunID: runID}); !errors.Is(err, gate.ErrConsumed) {
			t.Fatalf("retried ambiguous launch: %v", err)
		}
	}
	if d.starts != 1 {
		t.Fatal("duplicate runtime Start")
	}
}

// Break caught: incomplete, credential-bearing or ambiguous identities create authority.
func TestBindingRejectsInvalidIdentityWithoutState(t *testing.T) {
	for name, change := range map[string]func(*gvisor.BackendIdentity){
		"HTTP":                func(i *gvisor.BackendIdentity) { i.APIServer = "http://localhost:6443" },
		"credentials":         func(i *gvisor.BackendIdentity) { i.APIServer = "https://user:secret@localhost:6443" },
		"query":               func(i *gvisor.BackendIdentity) { i.APIServer += "?token=secret" },
		"path":                func(i *gvisor.BackendIdentity) { i.APIServer += "/api" },
		"fragment":            func(i *gvisor.BackendIdentity) { i.APIServer += "#context" },
		"invalid port":        func(i *gvisor.BackendIdentity) { i.APIServer = "https://127.0.0.1:99999" },
		"zero port":           func(i *gvisor.BackendIdentity) { i.APIServer = "https://127.0.0.1:0" },
		"empty port":          func(i *gvisor.BackendIdentity) { i.APIServer = "https://127.0.0.1:" },
		"invalid host":        func(i *gvisor.BackendIdentity) { i.APIServer = "https://bad_host:6443" },
		"empty CA":            func(i *gvisor.BackendIdentity) { i.CASHA256 = "" },
		"bad hash":            func(i *gvisor.BackendIdentity) { i.NodeConfigSHA256 = strings.Repeat("z", 64) },
		"empty cluster":       func(i *gvisor.BackendIdentity) { i.ClusterUID = "" },
		"other namespace":     func(i *gvisor.BackendIdentity) { i.Namespace = "default" },
		"empty namespace UID": func(i *gvisor.BackendIdentity) { i.NamespaceUID = "" },
		"empty node UID":      func(i *gvisor.BackendIdentity) { i.NodeUID = "" },
		"invalid node name":   func(i *gvisor.BackendIdentity) { i.NodeName = "../../node" },
		"empty node label":    func(i *gvisor.BackendIdentity) { i.NodeName = "node..invalid" },
		"bad node label":      func(i *gvisor.BackendIdentity) { i.NodeName = "node.-invalid" },
		"control character":   func(i *gvisor.BackendIdentity) { i.ClusterUID = "cluster\nsecond" },
	} {
		t.Run(name, func(t *testing.T) {
			p := dir(t)
			i := identity()
			change(&i)
			if _, err := gvisor.Bind(p, "home-ubuntu", i, &boundaryDriver{}); err == nil {
				t.Fatal("invalid identity accepted")
			}
			entries, err := os.ReadDir(p)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid identity wrote gate state")
			}
		})
	}
}

// Break caught: binding exists only in process memory instead of fsynced gate state.
func TestBackendBindingAcrossProcess(t *testing.T) {
	p := dir(t)
	g, err := gvisor.Bind(p, "home-ubuntu", identity(), &boundaryDriver{})
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Reap(context.Background(), runID); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{false, true} {
		i := identity()
		if changed {
			i.NamespaceUID = "replacement"
		}
		raw, _ := json.Marshal(i)
		cmd := exec.Command(os.Args[0], "-test.run=^TestBackendBindingChild$")
		cmd.Env = append(os.Environ(), "WARDEN_BINDING_CHILD="+p, "WARDEN_BINDING_IDENTITY="+string(raw))
		out, err := cmd.CombinedOutput()
		if changed && err == nil {
			t.Fatal("child accepted changed backend")
		}
		if !changed && err != nil {
			t.Fatalf("child failed reopening binding: %v %s", err, out)
		}
		if changed && !strings.Contains(string(out), "BINDING_REJECTED") {
			t.Fatalf("child failed for wrong reason: %v %s", err, out)
		}
	}
}
func TestBackendBindingChild(t *testing.T) {
	p := os.Getenv("WARDEN_BINDING_CHILD")
	if p == "" {
		return
	}
	var i gvisor.BackendIdentity
	if err := json.Unmarshal([]byte(os.Getenv("WARDEN_BINDING_IDENTITY")), &i); err != nil {
		t.Fatal(err)
	}
	g, err := gvisor.Bind(p, "home-ubuntu", i, &boundaryDriver{})
	if err != nil {
		t.Fatalf("BINDING_REJECTED: %v", err)
	}
	if _, err = g.Start(context.Background(), runtimes.Spec{RunID: runID}); !errors.Is(err, gate.ErrConsumed) {
		t.Fatalf("lost tombstone: %v", err)
	}
}
