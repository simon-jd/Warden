package firecracker

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJailerLaunchKeepsForegroundOwnerAndUniqueHostID(t *testing.T) {
	p, e := Normalize(spec(), false)
	if e != nil {
		t.Fatal(e)
	}
	args, e := jailerArgs(p, 2000000001)
	if e != nil {
		t.Fatal(e)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, bad := range []string{"--daemonize", "--new-pid-ns", "--no-seccomp", "--netns", "/dev/net/tun"} {
		if strings.Contains(joined, bad) {
			t.Fatal("unsafe jailer option", bad)
		}
	}
	for _, want := range []string{" --uid 2000000001 ", " --gid 2000000001 ", " --cgroup-version 2 ", " --parent-cgroup warden-lab/vms/warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ ", " --api-sock /api.sock "} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing isolation boundary %s", want)
		}
	}
	if _, e = jailerArgs(p, 65534); e == nil {
		t.Fatal("shared host UID accepted")
	}
}
func TestImmutableArtifactHashModeAndAliasValidation(t *testing.T) {
	p := private(t)
	data := []byte("immutable")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	file := filepath.Join(p, "kernel")
	os.WriteFile(file, data, 0444)
	r, e := os.OpenRoot(p)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	f, e := verifiedArtifact(r, "kernel", hash, 10)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = verifiedArtifact(r, "kernel", strings.Repeat("1", 64), 10); e == nil {
		t.Fatal("hash drift accepted")
	}
	os.Chmod(file, 0644)
	if f, e = verifiedArtifact(r, "kernel", hash, 10); e == nil {
		f.Close()
		t.Fatal("writable shared asset accepted")
	}
	os.Remove(file)
	os.Symlink("/etc/passwd", file)
	if f, e = verifiedArtifact(r, "kernel", hash, 10000); e == nil {
		f.Close()
		t.Fatal("redirected input accepted")
	}
}
