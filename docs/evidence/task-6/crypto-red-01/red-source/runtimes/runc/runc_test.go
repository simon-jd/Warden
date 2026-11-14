package runc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/runtimes"
)

func validSpec() runtimes.Spec {
	return runtimes.Spec{RunID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", ImageDigest: "sha256:" + strings.Repeat("a", 64), Cmd: []string{"/warden-probe", "uid"}, Limits: runtimes.Limits{CPU: 1, MemoryMiB: 512, Pids: 128, TimeoutS: 1}}
}

// Removing the validation branch must allow an unsafe spec and fail these tests.
func TestRejectsUnsafeLaunchBeforeConnecting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*runtimes.Spec)
	}{
		{"mutable-image", func(s *runtimes.Spec) { s.ImageDigest = "busybox:latest" }},
		{"traversal-id", func(s *runtimes.Spec) { s.RunID = "../other" }},
		{"allowlist-unimplemented", func(s *runtimes.Spec) { s.Network = "allowlist"; s.AllowDomains = []string{"example.com"} }},
		{"none-with-domains", func(s *runtimes.Spec) { s.AllowDomains = []string{"example.com"} }},
		{"zero-memory", func(s *runtimes.Spec) { s.Limits.MemoryMiB = 0 }},
		{"empty-cmd", func(s *runtimes.Spec) { s.Cmd = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec()
			tc.mutate(&s)
			_, err := BuildSpec(s, "/warden-lab/warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err == nil {
				t.Fatal("unsafe launch accepted")
			}
		})
	}
}
func TestOCISecurityAndResourceEnforcement(t *testing.T) {
	s, err := BuildSpec(validSpec(), "/warden-lab/warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if err != nil {
		t.Fatal(err)
	}
	if s.Root == nil || s.Process == nil || s.Linux == nil {
		t.Fatal("security spec missing")
	}
	if !s.Root.Readonly || s.Process.User.UID != 65534 || s.Process.User.GID != 65534 || !s.Process.NoNewPrivileges {
		t.Fatal("missing process security defaults")
	}
	if len(s.Process.Capabilities.Bounding)+len(s.Process.Capabilities.Effective)+len(s.Process.Capabilities.Permitted)+len(s.Process.Capabilities.Inheritable)+len(s.Process.Capabilities.Ambient) != 0 {
		t.Fatal("capabilities retained")
	}
	if *s.Linux.Resources.Memory.Limit != 536870912 || *s.Linux.Resources.Pids.Limit != 128 || *s.Linux.Resources.CPU.Quota != 100000 {
		t.Fatal("limits not enforced")
	}
	if s.Linux.Seccomp == nil || string(s.Linux.Seccomp.DefaultAction) != "SCMP_ACT_ERRNO" {
		t.Fatal("seccomp must default deny")
	}
	for _, rule := range s.Linux.Seccomp.Syscalls {
		for _, name := range rule.Names {
			if name == "mount" || name == "ptrace" || name == "bpf" || name == "kexec_load" {
				t.Fatalf("dangerous syscall allowed: %s", name)
			}
		}
	}
	ns := map[string]bool{}
	for _, n := range s.Linux.Namespaces {
		if n.Path != "" {
			t.Fatal("host namespace reused")
		}
		ns[string(n.Type)] = true
	}
	for _, n := range []string{"pid", "ipc", "uts", "mount", "network"} {
		if !ns[n] {
			t.Fatalf("missing namespace %s", n)
		}
	}
	for _, m := range s.Mounts {
		if m.Destination == "/sys" {
			for _, o := range m.Options {
				if o == "rw" {
					t.Fatal("writable sysfs")
				}
			}
		}
	}
}
func TestBoundedLogsDiscardOverflowWithoutBlocking(t *testing.T) {
	b := newLogBuffer(8)
	if n, e := b.Write([]byte("123456789abc")); n != 12 || e != nil {
		t.Fatalf("writer failed: %d %v", n, e)
	}
	out, e := io.ReadAll(b.reader())
	if e != nil || string(out) != "12345678" {
		t.Fatalf("unbounded or missing logs %q %v", out, e)
	}
}
func TestCgroupRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "warden-lab")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(t.TempDir(), filepath.Join(root, "warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")); e != nil {
		t.Fatal(e)
	}
	_, e := openCgroup(root, "warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if e == nil {
		t.Fatal("symlink cgroup accepted")
	}
}
func TestKillWaitsForEntireSubtree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "warden-lab")
	path := filepath.Join(root, "warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if e := os.MkdirAll(path, 0700); e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string]string{"cgroup.events": "populated 1\nfrozen 0\n", "cgroup.procs": "", "cgroup.kill": ""} {
		if e := os.WriteFile(filepath.Join(path, name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	cg, e := openCgroup(root, "warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if e != nil {
		t.Fatal(e)
	}
	defer cg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e = killCgroup(ctx, cg); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("claimed cleanup while descendant still populated: %v", e)
	}
	data, _ := os.ReadFile(filepath.Join(path, "cgroup.kill"))
	if string(data) != "1" {
		t.Fatalf("cgroup.kill not used: %q", data)
	}
	if e = os.WriteFile(filepath.Join(path, "cgroup.events"), []byte("populated 0\nfrozen 0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = killCgroup(context.Background(), cg); e != nil {
		t.Fatal(e)
	}
}

// A caller abandoning Wait must not abandon timeout enforcement or cleanup.
func TestWaitCancellationDoesNotCancelLifecycle(t *testing.T) {
	exits := make(chan processExit, 1)
	cleaned := make(chan struct{})
	h := newHandle(time.Hour, newLogBuffer(8), exits, func(context.Context) (bool, error) { close(cleaned); return true, nil }, func(context.Context) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := h.Wait(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("Wait: %v", e)
	}
	exits <- processExit{code: 7}
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("cleanup abandoned")
	}
	out, e := h.Wait(context.Background())
	if e != nil || out.Code != 7 || !out.CgroupEmpty {
		t.Fatalf("exit: %+v %v", out, e)
	}
}
func TestTimeoutKillsAndReportsCleanupFailure(t *testing.T) {
	exits := make(chan processExit, 1)
	h := newHandle(time.Millisecond, newLogBuffer(8), exits, func(context.Context) (bool, error) { return false, errors.New("cleanup denied") }, func(context.Context) error { exits <- processExit{code: 137}; return nil })
	out, e := h.Wait(context.Background())
	if !out.TimedOut || out.CgroupEmpty || e == nil || !strings.Contains(e.Error(), "cleanup denied") {
		t.Fatalf("timeout/cleanup lost: %+v %v", out, e)
	}
}
func TestNaturalExitKillsResidualProcesses(t *testing.T) {
	exits := make(chan processExit, 1)
	killed := make(chan struct{}, 1)
	h := newHandle(time.Hour, newLogBuffer(8), exits, func(context.Context) (bool, error) {
		select {
		case <-killed:
			return true, nil
		default:
			return false, errors.New("descendants not killed")
		}
	}, func(context.Context) error { killed <- struct{}{}; return nil })
	exits <- processExit{}
	out, e := h.Wait(context.Background())
	if e != nil || !out.CgroupEmpty {
		t.Fatalf("residual cleanup omitted: %+v %v", out, e)
	}
}

func TestRejectsSharedDaemonConfiguration(t *testing.T) {
	for _, socket := range []string{"/run/containerd/containerd.sock", "relative/warden-lab/containerd.sock", "/run/warden-lab/../containerd.sock"} {
		if _, e := New(Config{Socket: socket, CgroupRoot: "/sys/fs/cgroup/warden-lab"}); e == nil {
			t.Fatalf("unsafe socket accepted %q", socket)
		}
	}
	if _, e := New(Config{Socket: "/run/warden-lab/containerd.sock", CgroupRoot: "/sys/fs/cgroup"}); e == nil {
		t.Fatal("shared cgroup root accepted")
	}
}
func TestStartHonorsCanceledSetupWithoutConnecting(t *testing.T) {
	name, _ := temporarySocket(t)
	d, e := New(socketConfig(name))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = d.Start(ctx, validSpec())
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("canceled setup attempted external launch: %v", e)
	}
}
func TestCgroupMalformedEventsFailClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "warden-lab")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	r, e := os.OpenRoot(p)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = os.WriteFile(filepath.Join(p, "cgroup.events"), []byte("frozen 0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = populated(r); e == nil {
		t.Fatal("malformed events claimed empty")
	}
}

func TestOCIDevicePolicyDeniesHostDevices(t *testing.T) {
	s, e := BuildSpec(validSpec(), "/warden-lab/warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if e != nil {
		t.Fatal(e)
	}
	denied := false
	for _, d := range s.Linux.Resources.Devices {
		if !d.Allow && d.Type == "" && d.Access == "rwm" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("resource limits erased default device deny policy")
	}
}

func TestReapRejectsUncontrolledRunIDBeforeConnecting(t *testing.T) {
	name, _ := temporarySocket(t)
	d, e := New(socketConfig(name))
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Reap(context.Background(), "../../another-project"); e == nil {
		t.Fatal("uncontrolled recovery ID accepted")
	}
}

func TestClosedExitChannelNeverReportsSuccess(t *testing.T) {
	exits := make(chan processExit)
	close(exits)
	h := newHandle(time.Second, newLogBuffer(8), exits, func(context.Context) (bool, error) { return true, nil }, func(context.Context) error { return nil })
	if _, e := h.Wait(context.Background()); e == nil {
		t.Fatal("closed task status channel falsely reported success")
	}
}
