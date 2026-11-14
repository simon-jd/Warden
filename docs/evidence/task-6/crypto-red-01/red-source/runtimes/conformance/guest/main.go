// warden-probe is an attack fixture. Run only inside a dedicated lab sandbox.
package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

func main() {
	runtime.GOMAXPROCS(1)
	if len(os.Args) != 2 {
		fail(errors.New("mode required"))
	}
	mode := os.Args[1]
	switch mode {
	case "uid":
		if os.Getuid() == 0 || os.Getgid() == 0 {
			fail(errors.New("guest runs as root"))
		}
	case "readonly":
		fd, e := unix.Open("/write-probe", unix.O_WRONLY, 0)
		if e == nil {
			unix.Close(fd)
			fail(errors.New("rootfs writable"))
		}
		if !errors.Is(e, unix.EROFS) {
			fail(fmt.Errorf("expected EROFS: %w", e))
		}
	case "network":
		interfaces, e := net.Interfaces()
		if e != nil {
			fail(e)
		}
		for _, i := range interfaces {
			if i.Flags&net.FlagLoopback == 0 {
				fail(fmt.Errorf("unexpected network interface %s", i.Name))
			}
		}
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
		if e != nil {
			fail(e)
		}
		defer unix.Close(fd)
		if e = unix.Connect(fd, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{198, 18, 0, 1}}); !errors.Is(e, unix.ENETUNREACH) {
			fail(fmt.Errorf("unexpected route/connect result %v", e))
		}
	case "seccomp":
		status, e := os.ReadFile("/proc/self/status")
		if e != nil {
			fail(e)
		}
		if !strings.Contains(string(status), "Seccomp:\t2") {
			fail(errors.New("seccomp filter absent"))
		}
		source := []byte("none\x00")
		target := []byte("/dev/shm\x00")
		fs := []byte("tmpfs\x00")
		_, _, errno := unix.RawSyscall6(unix.SYS_MOUNT, uintptr(unsafe.Pointer(&source[0])), uintptr(unsafe.Pointer(&target[0])), uintptr(unsafe.Pointer(&fs[0])), 0, 0, 0)
		if errno != unix.EPERM {
			fail(fmt.Errorf("mount returned %v", errno))
		}
		_, _, errno = unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
		if errno != unix.EPERM {
			fail(fmt.Errorf("ptrace returned %v", errno))
		}
	case "fork":
		// Child processes remain alive. EAGAIN proves the actual pids controller is
		// reached, rather than merely inspecting the OCI configuration.
		hit := false
		children := []int{}
		defer func() {
			for _, p := range children {
				unix.Kill(p, unix.SIGKILL)
				unix.Wait4(p, nil, 0, nil)
			}
		}()
		for i := 0; i < 64; i++ {
			pid, errno := forkHold()
			if errno == uintptr(unix.EAGAIN) {
				hit = true
				break
			}
			if errno != 0 {
				fail(unix.Errno(errno))
			}
			children = append(children, int(pid))
		}
		if !hit || len(children) < 16 || len(children) >= 32 {
			fail(fmt.Errorf("pids limit not reached safely: children=%d EAGAIN=%v", len(children), hit))
		}
	case "timeout":
		if _, e := os.StartProcess("/warden-probe", []string{"/warden-probe", "hold"}, &os.ProcAttr{Env: []string{"GOMAXPROCS=1"}, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}}); e != nil {
			fail(e)
		}
		fmt.Println("READY timeout")
		for {
			time.Sleep(time.Hour)
		}
	case "oom":
		fmt.Println("READY oom")
		for {
			b, e := unix.Mmap(-1, 0, 16<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
			if e != nil {
				fail(e)
			}
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
		}
	case "hold":
		for {
			time.Sleep(time.Hour)
		}
	default:
		fail(errors.New("unknown mode"))
	}
	fmt.Println("PASS " + mode)
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
