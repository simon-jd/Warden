package guest

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"testing"
)

// Installs a filter only on an ordinary-UID child in the capless code-test
// container. No guest probe, mount, KVM or privileged execution is involved.
func TestPayloadFilterDeniesControlSocketsAndPrivilegeSyscalls(t *testing.T) {
	if os.Getenv("WARDEN_FILTER_CHILD") == "1" {
		if e := InstallFilter(); e != nil {
			t.Fatal(e)
		}
		if fd, e := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0); !errors.Is(e, unix.EPERM) {
			unix.Close(fd)
			t.Fatalf("vsock=%v", e)
		}
		if _, _, e := unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0); !errors.Is(e, unix.EPERM) {
			t.Fatalf("ptrace=%v", e)
		}
		if e := unix.Unshare(unix.CLONE_NEWNS); !errors.Is(e, unix.EPERM) {
			t.Fatalf("unshare=%v", e)
		}
		if fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); e != nil {
			t.Fatal(e)
		} else {
			unix.Close(fd)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPayloadFilterDeniesControlSocketsAndPrivilegeSyscalls$")
	cmd.Env = append(os.Environ(), "WARDEN_FILTER_CHILD=1")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("filter child %v %s", e, b)
	}
}
