package firecracker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExt4BuilderCreatesBoundedReadOnlyProbeDisk(t *testing.T) {
	source := private(t)
	if e := os.WriteFile(filepath.Join(source, "write-probe"), nil, 0666); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(filepath.Join(source, "write-probe"), 0666); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(private(t), "payload.ext4")
	if e := BuildExt4(source, destination); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(destination)
	if e != nil || st.Size() != 32<<20 || st.Mode().Perm() != 0400 {
		t.Fatalf("disk size/mode %v %v", st, e)
	}
	output, e := exec.Command("/sbin/debugfs", "-R", "stat /", destination).CombinedOutput()
	if e != nil || !strings.Contains(string(output), "0755") || !strings.Contains(string(output), "User:     0") {
		t.Fatalf("root traversal/owner %s %v", output, e)
	}
	if e := BuildExt4(source, destination); e == nil {
		t.Fatal("immutable disk overwritten")
	}
}
