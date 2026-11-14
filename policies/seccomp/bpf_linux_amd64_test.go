package seccomp

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestCompileDefaultCoversEveryAllowedName(t *testing.T) {
	prog, err := Compile(Default)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) < 4 || len(prog) > maxInstructions {
		t.Fatalf("program length %d", len(prog))
	}
	allowed := map[uint32]bool{}
	for i := 0; i+1 < len(prog); i++ {
		if prog[i].Code == unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K && prog[i].Jt == 0 && prog[i+1].Code == unix.BPF_RET|unix.BPF_K && prog[i+1].K == unix.SECCOMP_RET_ALLOW {
			allowed[prog[i].K] = true
		}
	}
	for _, nr := range []uintptr{unix.SYS_READ, unix.SYS_EXECVE, unix.SYS_EXIT_GROUP, unix.SYS_FUTEX} {
		if !allowed[uint32(nr)] {
			t.Errorf("syscall %d not allowed by compiled default", nr)
		}
	}
	for _, nr := range []uintptr{unix.SYS_MOUNT, unix.SYS_PTRACE, unix.SYS_UNSHARE, unix.SYS_BPF, unix.SYS_KEXEC_LOAD} {
		if allowed[uint32(nr)] {
			t.Errorf("syscall %d must not be allowed", nr)
		}
	}
}

func TestCompileRejectsWhatItCannotExpress(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown name":       `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["no_such_call"],"action":"SCMP_ACT_ALLOW"}]}`,
		"duplicate name":     `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"},{"names":["read"],"action":"SCMP_ACT_ERRNO"}]}`,
		"unsupported op":     `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":1,"op":"SCMP_CMP_GT"}]}]}`,
		"arg index":          `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":6,"value":1,"op":"SCMP_CMP_MASKED_EQ"}]}]}`,
		"unsupported act":    `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_TRACE"}]}`,
		"allow by default":   `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["mount"],"action":"SCMP_ACT_ERRNO"}]}`,
		"unknown field":      `{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],"syscalls":[]}`,
		"errno out of range": `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":70000,"syscalls":[]}`,
	} {
		if _, err := Compile([]byte(raw)); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

// The child installs the compiled default policy and checks real kernel
// answers; the parent only runs it. No privilege is needed (no_new_privs).
func TestInstalledDefaultPolicyBehaves(t *testing.T) {
	if os.Getenv("WARDEN_SECCOMP_CHILD") == "1" {
		prog, err := Compile(Default)
		if err != nil {
			t.Fatal(err)
		}
		if err := Install(prog); err != nil {
			t.Fatal(err)
		}
		status, err := os.ReadFile("/proc/self/status")
		if err != nil || !strings.Contains(string(status), "Seccomp:\t2") {
			t.Fatalf("filter not reported: %v", err)
		}
		if os.Getpid() <= 0 {
			t.Fatal("getpid")
		}
		src, dst, fs := []byte("none\x00"), []byte("/\x00"), []byte("tmpfs\x00")
		if _, _, e := unix.RawSyscall6(unix.SYS_MOUNT, ptr(src), ptr(dst), ptr(fs), 0, 0, 0); e != unix.EPERM {
			t.Fatalf("mount: %v", e)
		}
		if _, _, e := unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0); e != unix.EPERM {
			t.Fatalf("ptrace: %v", e)
		}
		if e := unix.Unshare(unix.CLONE_NEWNS); !errors.Is(e, unix.EPERM) {
			t.Fatalf("unshare: %v", e)
		}
		if _, _, e := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0); e != unix.ENOSYS {
			t.Fatalf("clone3: %v", e)
		}
		// CLONE_NEWUSER|CLONE_FS is EINVAL in the kernel, so a broken filter
		// fails this check without creating a process.
		if _, _, e := unix.RawSyscall(unix.SYS_CLONE, unix.CLONE_NEWUSER|unix.CLONE_FS, 0, 0); e != unix.EPERM {
			t.Fatalf("clone with namespace flag: %v", e)
		}
		if out, err := exec.Command("/bin/sh", "-c", "echo ok").Output(); err != nil || string(out) != "ok\n" {
			t.Fatalf("plain fork+exec under the filter: %v %q", err, out)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstalledDefaultPolicyBehaves$", "-test.count=1")
	cmd.Env = append(os.Environ(), "WARDEN_SECCOMP_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filtered child: %v\n%s", err, out)
	}
}

func ptr(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }
