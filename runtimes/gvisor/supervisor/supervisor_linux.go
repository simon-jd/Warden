package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"warden/policies/seccomp"
)

const (
	cgroupDir  = "/sys/fs/cgroup"
	payloadArg = "payload"
	payloadEnv = "WARDEN_GVISOR_PAYLOAD"
	// Exit codes when the supervisor itself fails (as in sh/env):
	// 125 setup, 126 payload setup, 127 payload exec.
	codeSetup, codePayloadSetup, codeExec = 125, 126, 127
)

// Main runs warden-gvisor-init and returns its exit code. The payload
// trampoline (argv[1] == "payload") only returns on failure.
func Main(args []string) int {
	if len(args) > 1 && args[1] == payloadArg {
		return payload(args[2:])
	}
	r := Report{Version: 1, InitUnixNano: time.Now().UnixNano()}
	if cfg, err := Parse(args[1:]); err != nil {
		r.Code, r.Error = codeSetup, "arguments: "+err.Error()
	} else {
		r = run(cfg, r)
	}
	if b, err := r.Encode(); err == nil {
		// The pod status is the only channel; if this fails there is no other.
		_ = os.WriteFile(TerminationLog, b, 0)
	}
	return int(r.Code)
}

func run(cfg Config, r Report) Report {
	fail := func(stage string, err error) Report {
		r.Code, r.Error = codeSetup, stage+": "+err.Error()
		return r
	}
	if os.Getpid() != 1 || os.Geteuid() != 0 || os.Getenv(MarkerEnv) != "1" {
		return fail("guard", errors.New("must be PID 1 and sandbox root of a Warden gVisor run"))
	}
	// kubelet sends SIGTERM when the pod is deleted; the workload is killed
	// and the report still written.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT)
	// runsc mounts the in-sandbox cgroup2 read-only for the container.
	if err := unix.Mount("", cgroupDir, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fail("remount cgroupfs read-write", err)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupDir, &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return fail("cgroupfs", fmt.Errorf("%s is not cgroup2 (%v)", cgroupDir, err))
	}
	root, err := os.OpenRoot(cgroupDir)
	if err != nil {
		return fail("open cgroupfs", err)
	}
	defer root.Close()
	w, err := prepare(root, cfg.Pids)
	if err != nil {
		return fail("prepare workload cgroup", err)
	}
	defer w.Close()

	status, statusW, err := os.Pipe()
	if err != nil {
		return fail("status pipe", err)
	}
	cmd := exec.Command("/proc/self/exe", append([]string{payloadArg, "--"}, cfg.Cmd...)...)
	cmd.Env = []string{payloadEnv + "=1"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{statusW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: unix.SIGKILL}
	if err := cmd.Start(); err != nil {
		return fail("start payload", err)
	}
	statusW.Close()
	timer := time.NewTimer(time.Duration(cfg.TimeoutS) * time.Second)
	defer timer.Stop()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitErr := await(&r, status, done, timer.C, sigs, func() error { return kill(w) })
	status.Close()
	r.Code = exitCode(cmd, waitErr)
	// Descendants the payload left behind are killed too; as PID 1 the
	// supervisor reaps the orphans until the cgroup is empty.
	if err := kill(w); err != nil {
		return fail("kill workload", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		for {
			if pid, _ := unix.Wait4(-1, nil, unix.WNOHANG, nil); pid <= 0 {
				break
			}
		}
		pop, err := populated(w)
		if err != nil {
			return fail("cgroup.events", err)
		}
		if !pop {
			break
		}
		if time.Now().After(deadline) {
			return fail("drain", errors.New("workload cgroup still populated 5 s after cgroup.kill"))
		}
		time.Sleep(time.Millisecond)
	}
	if err := collect(w, &r); err != nil {
		return fail("collect counters", err)
	}
	w.Close()
	if err := root.Remove(Workload); err != nil {
		return fail("remove workload cgroup", err)
	}
	r.CgroupEmpty = true
	return r
}

// execStatus is what the status pipe gave: nothing (EOF, so execve worked)
// or the trampoline's error message, and when the read ended.
type execStatus struct {
	msg []byte
	at  int64
}

// statusGrace bounds the read of the exec status after the payload exited.
// The pipe's only writer was the trampoline, so the read ends at once.
const statusGrace = 5 * time.Second

// await follows the payload until it exits and returns cmd.Wait's error.
// Meanwhile it records the exec status (EOF on the status pipe once execve
// worked, the trampoline's error message otherwise), enforces the timeout
// and handles a SIGTERM or SIGINT for the supervisor.
//
// The exit and the end of the status come together when setup fails or the
// payload is short, and select picks either. So the status is always read
// to its end, after the exit if need be, and timed where the read ended.
func await(r *Report, status io.Reader, done <-chan error, timeout <-chan time.Time, sigs <-chan os.Signal, kill func() error) error {
	execd := make(chan execStatus, 1)
	go func() {
		msg, _ := io.ReadAll(io.LimitReader(status, 2048))
		execd <- execStatus{msg, time.Now().UnixNano()}
	}()
	record := func(s execStatus) {
		if len(s.msg) == 0 {
			r.ExecUnixNano = s.at
		} else {
			r.Error = "payload setup: " + string(s.msg)
		}
	}
	for {
		select {
		case s := <-execd:
			record(s)
			execd = nil
		case <-timeout:
			r.TimedOut = true
			if err := kill(); err != nil {
				r.Error = "timeout kill: " + err.Error()
			}
		case s := <-sigs:
			r.Error = signalled + s.String()
			_ = kill()
		case err := <-done:
			if execd != nil {
				select {
				case s := <-execd:
					record(s)
				case <-time.After(statusGrace):
					r.Error = "exec status pipe still open after the payload exited"
				}
			}
			return err
		}
	}
}

func exitCode(cmd *exec.Cmd, err error) uint32 {
	if cmd.ProcessState == nil {
		return codeSetup
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	switch {
	case !ok:
		return codeSetup
	case ws.Signaled():
		return 128 + uint32(ws.Signal())
	}
	return uint32(ws.ExitStatus())
}

// payload is the trampoline between fork and the payload's execve, still
// root in a private mount namespace: join the workload cgroup, make cgroupfs
// read-only again, hide the termination log, drop every privilege, install
// the seccomp policy, exec.
// Fd 3 is close-on-exec; the supervisor reads EOF there when execve worked
// and an error message otherwise.
func payload(args []string) int {
	// The bounding set and capset are per thread, and execve runs on
	// whichever thread the goroutine is on: keep it on one thread from the
	// first drop to the exec (never unlocked; the process execs or exits).
	runtime.LockOSThread()
	statusFD := os.NewFile(3, "exec-status")
	failed := func(code int, stage string, err error) int {
		fmt.Fprintf(statusFD, "%s: %v", stage, err)
		return code
	}
	if os.Getenv(payloadEnv) != "1" || os.Geteuid() != 0 || len(args) < 2 || args[0] != "--" {
		return failed(codePayloadSetup, "guard", errors.New("not started by the supervisor"))
	}
	cmd := args[1:]
	if err := os.WriteFile(cgroupDir+"/"+Workload+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return failed(codePayloadSetup, "join workload cgroup", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return failed(codePayloadSetup, "private mounts", err)
	}
	if err := unix.Mount("", cgroupDir, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return failed(codePayloadSetup, "cgroupfs read-only", err)
	}
	// kubelet makes the termination log 0666. Only the supervisor may
	// write the report, so the payload's namespace does not see the file.
	if err := unix.Unmount(TerminationLog, unix.MNT_DETACH); err != nil {
		return failed(codePayloadSetup, "hide termination log", err)
	}
	for c := 0; c < 64; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			if errors.Is(err, unix.EINVAL) && c > 0 {
				break // past the last capability
			}
			return failed(codePayloadSetup, "drop bounding set", err)
		}
	}
	if err := syscall.Setgroups(nil); err != nil {
		return failed(codePayloadSetup, "setgroups", err)
	}
	if err := syscall.Setgid(PayloadUID); err != nil {
		return failed(codePayloadSetup, "setgid", err)
	}
	if err := syscall.Setuid(PayloadUID); err != nil {
		return failed(codePayloadSetup, "setuid", err)
	}
	var none [2]unix.CapUserData
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &none[0]); err != nil {
		return failed(codePayloadSetup, "capset", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 1024, Max: 1024}); err != nil {
		return failed(codePayloadSetup, "rlimit", err)
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return failed(codePayloadSetup, "close-on-exec", err)
	}
	if err := os.Chdir("/"); err != nil {
		return failed(codePayloadSetup, "chdir", err)
	}
	prog, err := seccomp.Compile(seccomp.Default)
	if err != nil {
		return failed(codePayloadSetup, "seccomp compile", err)
	}
	if err := seccomp.Install(prog); err != nil {
		return failed(codePayloadSetup, "seccomp install", err)
	}
	err = unix.Exec(cmd[0], cmd, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
	return failed(codeExec, "exec "+cmd[0], err)
}
