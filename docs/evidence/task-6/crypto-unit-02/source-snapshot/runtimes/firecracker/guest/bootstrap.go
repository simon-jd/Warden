package guest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"warden/runtimes"
	fc "warden/runtimes/firecracker"
)

// Boot is only the fixed init entrypoint of the SHA-bound guest image. The
// marker prevents accidental use in a host/container; it is not attestation.
func Boot() error {
	if os.Getpid() != 1 || os.Geteuid() != 0 || os.Getenv("WARDEN_FC_GUEST") != "1" {
		return errors.New("dedicated Firecracker guest PID1 required")
	}
	debug.SetMemoryLimit(40 << 20)
	if e := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return e
	}
	cmdline, e := os.ReadFile("/proc/cmdline")
	if e != nil || !strings.Contains(" "+strings.TrimSpace(string(cmdline))+" ", " WARDEN_FC_GUEST=1 ") {
		return errors.New("guest kernel marker missing")
	}
	for _, m := range []struct {
		source, target, kind, data string
		flags                      uintptr
	}{
		{"sysfs", "/sys", "sysfs", "", unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NOEXEC},
		{"tmpfs", "/run", "tmpfs", "size=16777216,mode=0700", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"tmpfs", "/tmp", "tmpfs", "size=16777216,mode=1777", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"/dev/vdb", "/payload", "ext4", "noload", unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV},
	} {
		if e := unix.Mount(m.source, m.target, m.kind, m.flags, m.data); e != nil {
			return fmt.Errorf("guest mount %s: %w", m.target, e)
		}
	}
	const cg = "/sys/fs/cgroup/"
	if e = os.Mkdir(cg+"agent", 0700); e != nil {
		return e
	}
	for _, v := range [][2]string{{"agent/cgroup.procs", "1"}, {"cgroup.subtree_control", "+memory +pids +cpu"}, {"agent/memory.max", "67108864"}, {"agent/memory.swap.max", "0"}, {"agent/pids.max", "64"}} {
		if e = os.WriteFile(cg+v[0], []byte(v[1]), 0600); e != nil {
			return e
		}
	}
	raw, e := os.ReadFile("/agent")
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	raw = nil
	s := session{hash: hex.EncodeToString(sum[:]), execute: executePayload}
	fd, e := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 52}); e != nil {
		return e
	}
	if e = unix.Listen(fd, 1); e != nil {
		return e
	}
	for {
		accepted, _, e := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if e != nil {
			return e
		}
		if e = unix.SetNonblock(accepted, true); e != nil {
			unix.Close(accepted)
			return e
		}
		conn := os.NewFile(uintptr(accepted), "guest-control")
		// Before BIND, permit a read-only baseline handshake to disconnect.
		conn.SetDeadline(time.Now().Add(330 * time.Second))
		e = s.serve(conn)
		conn.Close()
		if s.consumed {
			return e
		}
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
	}
}

func executePayload(p fc.Profile, started func() error, stdout, stderr io.Writer) (runtimes.Exit, error) {
	var result runtimes.Exit
	if os.Getpid() != 1 || os.Geteuid() != 0 || os.Getenv("WARDEN_FC_GUEST") != "1" {
		return result, errors.New("guest-only executor")
	}
	const path = "/sys/fs/cgroup/workload"
	if e := os.Mkdir(path, 0700); e != nil {
		return result, e
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return result, e
	}
	defer root.Close()
	fd, e := root.Open(".")
	if e != nil {
		return result, e
	}
	defer fd.Close()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(fd.Fd()), &fs); e != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return result, errors.New("real guest cgroup2 required")
	}
	write := func(name, value string) error {
		f, e := root.OpenFile(name, os.O_WRONLY, 0)
		if e != nil {
			return e
		}
		_, e = f.WriteString(value)
		return errors.Join(e, f.Close())
	}
	for _, v := range [][2]string{{"memory.max", strconv.Itoa(p.Spec.Limits.MemoryMiB * 1048576)}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", strconv.Itoa(p.Spec.Limits.Pids)}, {"cpu.max", fmt.Sprintf("%d 100000", int64(p.Spec.Limits.CPU*100000))}} {
		if e = write(v[0], v[1]); e != nil {
			return result, e
		}
	}
	cmd := exec.Command("/agent", "payload", p.Spec.Cmd[1])
	cmd.Env = []string{"WARDEN_FC_GUEST=1", "GOMAXPROCS=1", "GOMEMLIMIT=32MiB"}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP, UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if e = cmd.Start(); e != nil {
		return result, e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if e = started(); e != nil {
		write("cgroup.kill", "1")
		<-done
		return result, e
	}
	timer := time.NewTimer(time.Duration(p.Spec.Limits.TimeoutS)*time.Second - 100*time.Millisecond)
	defer timer.Stop()
	select {
	case e = <-done:
	case <-timer.C:
		result.TimedOut = true
		if killErr := write("cgroup.kill", "1"); killErr != nil {
			return result, killErr
		}
		e = <-done
	}
	if e != nil {
		var exited *exec.ExitError
		if !errors.As(e, &exited) {
			return result, e
		}
		result.Code = uint32(exited.ExitCode())
		if exited.ExitCode() < 0 {
			result.Code = 137
		}
	}
	if e = write("cgroup.kill", "1"); e != nil {
		return result, e
	}
	read := func(name string) (string, error) {
		f, e := root.Open(name)
		if e != nil {
			return "", e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		return string(b), e
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, e := read("cgroup.events")
		if e != nil {
			return result, e
		}
		pop, e := fc.Counter(raw, "populated")
		if e != nil {
			return result, e
		}
		if pop == 0 {
			break
		}
		if pop != 1 || time.Now().After(deadline) {
			return result, errors.New("guest tree not empty")
		}
		time.Sleep(time.Millisecond)
	}
	for _, item := range []struct {
		file, key string
		dest      *uint64
	}{{"pids.events", "max", &result.PidsMaxEvents}} {
		raw, e := read(item.file)
		if e != nil {
			return result, e
		}
		n, e := fc.Counter(raw, item.key)
		if e != nil {
			return result, e
		}
		*item.dest = n
	}
	raw, e := read("pids.peak")
	if e != nil {
		return result, e
	}
	result.PeakPids, e = strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if e != nil {
		return result, e
	}
	raw, e = read("memory.events")
	if e != nil {
		return result, e
	}
	oom, e := fc.Counter(raw, "oom_kill")
	if e != nil {
		return result, e
	}
	result.OOMKilled = oom > 0
	if e = os.Remove(path); e != nil {
		return result, e
	}
	result.CgroupEmpty = true
	return result, nil
}

// Payload is the fixed re-exec trampoline, running as PID1 in a fresh guest
// child namespace already placed in the workload cgroup by clone3.
func Payload(mode string) error {
	if os.Getpid() != 1 || os.Geteuid() != 0 || os.Getenv("WARDEN_FC_GUEST") != "1" {
		return errors.New("guest payload trampoline only")
	}
	runtime.LockOSThread()
	switch mode {
	case "fork", "readonly", "network", "uid", "timeout", "oom", "seccomp":
	default:
		return errors.New("unsupported probe")
	}
	if e := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); e != nil {
		return e
	}
	if e := unix.Mount("proc", "/payload/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return e
	}
	if e := unix.Mount("tmpfs", "/payload/dev", "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "size=1048576,mode=0755"); e != nil {
		return e
	}
	if e := unix.Mount("sysfs", "/payload/sys", "sysfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return e
	}
	if e := unix.Chroot("/payload"); e != nil {
		return e
	}
	if e := os.Chdir("/"); e != nil {
		return e
	}
	for cap := 0; cap <= 40; cap++ {
		if e := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); e != nil {
			return e
		}
	}
	if e := syscall.Setgroups([]int{}); e != nil {
		return e
	}
	if e := syscall.Setgid(65534); e != nil {
		return e
	}
	if e := syscall.Setuid(65534); e != nil {
		return e
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if e := unix.Capset(&header, &caps[0]); e != nil {
		return e
	}
	if e := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 1024, Max: 1024}); e != nil {
		return e
	}
	if e := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); e != nil {
		return e
	}
	if e := InstallFilter(); e != nil {
		return e
	}
	return unix.Exec("/warden-probe", []string{"/warden-probe", mode}, []string{"GOMAXPROCS=1", "GOMEMLIMIT=32MiB"})
}
