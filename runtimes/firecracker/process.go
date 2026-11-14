package firecracker

import (
	"errors"
	"golang.org/x/sys/unix"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type ownedProcess struct {
	mu                            sync.Mutex
	cmd                           *exec.Cmd
	pidfd                         int
	done                          chan struct{}
	waitErr                       error
	closed                        bool
	cleanupSeen, cleanupAttempted bool
	killSignalResult              string
}

func startOwned(cmd *exec.Cmd) (*ownedProcess, error) {
	if cmd == nil || cmd.Process != nil {
		return nil, errors.New("fresh owned child required")
	}
	p := &ownedProcess{cmd: cmd, pidfd: -1, done: make(chan struct{})}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.PidFD = &p.pidfd
	if e := cmd.Start(); e != nil {
		if p.pidfd >= 0 {
			unix.Close(p.pidfd)
		}
		return nil, e
	}
	if p.pidfd < 0 {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, errors.New("atomic original pidfd unavailable")
	}
	go func() { p.waitErr = cmd.Wait(); close(p.done) }()
	return p, nil
}

// Stop proves reaping of this original child, not cgroup/data/FD retirement of
// an entire runtime node. The caller must independently verify the full scope.
func (p *ownedProcess) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.noteCleanupLocked()
	e := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0)
	p.killSignalResult = "sent"
	if errors.Is(e, unix.ESRCH) {
		p.killSignalResult = "already_absent"
	} else if e != nil {
		p.killSignalResult = "error"
		return e
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		return errors.New("original child reap pending")
	}
	if p.waitErr != nil {
		var exit *exec.ExitError
		if !errors.As(p.waitErr, &exit) {
			return p.waitErr
		}
	}
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	if _, e := unix.Poll(fds, 0); e != nil {
		return e
	}
	if fds[0].Revents&unix.POLLHUP == 0 {
		return errors.New("original child not reaped")
	}
	if e := unix.Close(p.pidfd); e != nil {
		return e
	}
	p.closed = true
	return nil
}

// Mark before any cgroup kill as well as before the original pidfd signal. A
// request racing a natural exit is only possible cleanup involvement, not cause.
func (p *ownedProcess) noteCleanupLocked() {
	p.cleanupSeen = true
	select {
	case <-p.done:
	default:
		p.cleanupAttempted = true
	}
}

func (p *ownedProcess) noteCleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.noteCleanupLocked()
}

func (p *ownedProcess) observation() originalProcessObservation {
	result := originalProcessObservation{Origin: "unavailable", State: "unknown", Signal: "unknown",
		KillSignalResult: "not_attempted", Context: "unknown_owner"}
	if p == nil {
		return result
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result.Origin = "original_child"
	result.Context = "no_cleanup_observed"
	result.CleanupAttempted = p.cleanupAttempted
	if p.cleanupAttempted {
		result.Context = "cleanup_may_have_terminated"
	} else if p.cleanupSeen {
		result.Context = "completed_before_cleanup"
	}
	if p.killSignalResult != "" {
		result.KillSignalResult = p.killSignalResult
	}
	select {
	case <-p.done:
		result.WaitComplete = true
	default:
		result.State = "pending"
		return result
	}
	// done is closed only after the original cmd.Wait and its copy goroutines.
	// A non-exit Wait error cannot establish successful I/O or an exit-zero.
	if p.waitErr != nil {
		var exit *exec.ExitError
		if !errors.As(p.waitErr, &exit) {
			return result
		}
	}
	if p.cmd == nil || p.cmd.ProcessState == nil {
		return result
	}
	status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return result
	}
	result.IOComplete = true
	if status.Exited() {
		result.State = "exited"
		code := status.ExitStatus()
		result.ExitCode = &code
	} else if status.Signaled() {
		result.State = "signaled"
		switch status.Signal() {
		case syscall.SIGKILL:
			result.Signal = "sigkill"
		case syscall.SIGTERM:
			result.Signal = "sigterm"
		case syscall.SIGABRT:
			result.Signal = "sigabrt"
		case syscall.SIGSEGV:
			result.Signal = "sigsegv"
		case syscall.SIGSYS:
			result.Signal = "sigsys"
		case syscall.SIGBUS:
			result.Signal = "sigbus"
		case syscall.SIGILL:
			result.Signal = "sigill"
		}
	}
	return result
}
