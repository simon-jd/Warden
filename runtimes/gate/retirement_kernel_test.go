package gate

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Break caught: a pidfd's existence (or a still-running process) is treated as
// proof of exit. This observes a real harmless child without cgroup privileges.
func TestPidfdRequiresActualOriginalProcessExit(t *testing.T) {
	cmd := exec.Command("/bin/cat")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); cmd.Process.Kill(); cmd.Wait() }()
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if dead, err := pidExited(fd); err != nil || dead {
		t.Fatalf("live process accepted as exited: %v %v", dead, err)
	}
	if err = input.Close(); err != nil {
		t.Fatal(err)
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err = unix.Poll(fds, 1000); err != nil {
		t.Fatal(err)
	}
	if reaped, err := pidReaped(fd); err != nil || reaped {
		t.Fatalf("unreaped process accepted: %v %v", reaped, err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if reaped, err := pidReaped(fd); err != nil || !reaped {
		t.Fatalf("actual parent reap unobserved: %v %v", reaped, err)
	}
	if dead, err := pidExited(fd); err != nil || !dead {
		t.Fatalf("reaped original identity not observable: %v %v", dead, err)
	}
}

// Break caught: inode/path absence alone (or a caller boolean) is sufficient
// although original state still exists, a replacement appeared, or identity changed.
func TestDiskProofRequiresOriginalDirectoriesRemovedWithoutReplacement(t *testing.T) {
	parent := t.TempDir()
	session, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	r := &Retirement{session: int(session.Fd())}
	for _, name := range []string{"root", "state", "io"} {
		if err = os.Mkdir(filepath.Join(parent, name), 0700); err != nil {
			t.Fatal(err)
		}
		f, e := os.Open(filepath.Join(parent, name))
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		var st unix.Stat_t
		if e = unix.Fstat(int(f.Fd()), &st); e != nil {
			t.Fatal(e)
		}
		r.data = append(r.data, int(f.Fd()))
		r.record.Data = append(r.record.Data, directoryIdentity{Device: st.Dev, Inode: st.Ino})
	}
	if err = r.verifyDiskCleanup(); err == nil {
		t.Fatal("existing original state accepted")
	}
	for _, name := range []string{"root", "state", "io"} {
		if err = os.Remove(filepath.Join(parent, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.verifyDiskCleanup(); err != nil {
		t.Fatal("actual fd-bound cleanup rejected", err)
	}
	if err = os.Mkdir(filepath.Join(parent, "root"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = r.verifyDiskCleanup(); err == nil {
		t.Fatal("replacement daemon state accepted")
	}
	if err = os.Remove(filepath.Join(parent, "root")); err != nil {
		t.Fatal(err)
	}
	r.record.Data[0].Inode++
	if err = r.verifyDiskCleanup(); err == nil {
		t.Fatal("wrong original identity accepted")
	}
}
