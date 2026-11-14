package firecracker

import (
	"golang.org/x/sys/unix"
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

// 2026-11-10: the project tree had gained a default ACL (other::---), staging
// files inherited it and mke2fs -d copied it into the guest images. The
// payload root then denied UID 65534 traversal, so every probe failed with
// "permission denied". Host ACLs must never reach a guest disk.
func TestExt4BuilderDropsHostACLs(t *testing.T) {
	source := private(t)
	probe := filepath.Join(source, "warden-probe")
	if e := os.WriteFile(probe, []byte("x"), 0555); e != nil {
		t.Fatal(e)
	}
	// POSIX ACL xattr v2: user::rwx group::r-x mask::--- other::---
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 4, 0, 5, 0, 255, 255, 255, 255, 0x10, 0, 0, 0, 255, 255, 255, 255, 0x20, 0, 0, 0, 255, 255, 255, 255}
	for _, path := range []string{source, probe} {
		if e := unix.Setxattr(path, "system.posix_acl_access", acl, 0); e != nil {
			t.Skipf("filesystem without POSIX ACLs: %v", e)
		}
	}
	if e := unix.Setxattr(source, "system.posix_acl_default", acl, 0); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(private(t), "payload.ext4")
	if e := BuildExt4(source, destination); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/", "/warden-probe"} {
		output, e := exec.Command("/sbin/debugfs", "-R", "ea_list "+path, destination).CombinedOutput()
		if e != nil || strings.Contains(string(output), "posix_acl") {
			t.Fatalf("host ACL copied into guest %s: %s %v", path, output, e)
		}
	}
	if e := unix.Setxattr(probe, "user.warden", []byte("1"), 0); e != nil {
		t.Skipf("filesystem without user xattrs: %v", e)
	}
	if e := BuildExt4(source, filepath.Join(private(t), "payload.ext4")); e == nil {
		t.Fatal("unexpected host xattr admitted into a guest image")
	}
}
