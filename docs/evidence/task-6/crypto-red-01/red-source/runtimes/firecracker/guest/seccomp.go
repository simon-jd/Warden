// Package guest contains the trusted guest-only payload boundary. Host runtime
// code never calls these namespace, credential or filter installation routines.
package guest

import (
	"fmt"
	"golang.org/x/sys/unix"
	"runtime"
	"unsafe"
)

// The reviewed fixed static Go probe needs only these calls. Namespace creation,
// mounts, ptrace, BPF, keyrings, module/device operations and io_uring default to
// EPERM. Socket filtering separately excludes the trusted vsock control channel.
func InstallFilter() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jeq := func(k uint32, t, f uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: t, Jf: f}
	}
	errno := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	f := []unix.SockFilter{stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), jeq(unix.AUDIT_ARCH_X86_64, 1, 0), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0)}
	for _, call := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		f = append(f, jeq(call, 0, 4), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 16), jeq(unix.AF_VSOCK, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, errno), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0))
	}
	f = append(f, jeq(unix.SYS_CLONE, 0, 5), stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 16), stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, 2114060288), jeq(0, 1, 0), stmt(unix.BPF_RET|unix.BPF_K, errno), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW), jeq(unix.SYS_CLONE3, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)))
	for _, call := range []uint32{
		unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_CLOSE, unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_FSTAT, unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STATX, unix.SYS_LSEEK, unix.SYS_PREAD64, unix.SYS_PWRITE64, unix.SYS_ACCESS, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2, unix.SYS_READLINK, unix.SYS_READLINKAT, unix.SYS_GETDENTS64,
		unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_BRK, unix.SYS_MADVISE, unix.SYS_MREMAP, unix.SYS_MSYNC, unix.SYS_MINCORE,
		unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGSUSPEND, unix.SYS_RT_SIGPENDING, unix.SYS_SIGALTSTACK, unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETTID, unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_GETGROUPS, unix.SYS_SET_TID_ADDRESS, unix.SYS_SET_ROBUST_LIST, unix.SYS_GET_ROBUST_LIST, unix.SYS_FUTEX, unix.SYS_FUTEX_WAITV, unix.SYS_RSEQ,
		unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES, unix.SYS_GETTIMEOFDAY, unix.SYS_GETRUSAGE, unix.SYS_PRLIMIT64, unix.SYS_GETRLIMIT, unix.SYS_UNAME, unix.SYS_SYSINFO, unix.SYS_ARCH_PRCTL, unix.SYS_PRCTL, unix.SYS_GETRANDOM, unix.SYS_GETCWD, unix.SYS_CHDIR, unix.SYS_UMASK,
		unix.SYS_FCNTL, unix.SYS_IOCTL, unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3, unix.SYS_PIPE, unix.SYS_PIPE2, unix.SYS_POLL, unix.SYS_PPOLL, unix.SYS_SELECT, unix.SYS_PSELECT6, unix.SYS_EPOLL_CREATE, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_WAIT, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2, unix.SYS_EVENTFD, unix.SYS_EVENTFD2,
		unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_CONNECT, unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_GETSOCKOPT, unix.SYS_SETSOCKOPT, unix.SYS_SENDTO, unix.SYS_RECVFROM, unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_SHUTDOWN,
		unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_WAIT4, unix.SYS_WAITID, unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_RESTART_SYSCALL, unix.SYS_PAUSE,
	} {
		f = append(f, jeq(call, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
	}
	f = append(f, stmt(unix.BPF_RET|unix.BPF_K, errno))
	program := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	n, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(f)
	if e != 0 {
		return e
	}
	if n != 0 {
		return fmt.Errorf("seccomp thread synchronization failed for %d", n)
	}
	return nil
}
