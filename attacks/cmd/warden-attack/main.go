// warden-attack is a bounded attack probe. Run only in the dedicated sandbox lab.
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"
)

func result(id string, ok bool, detail string) {
	if ok {
		fmt.Printf("WARDEN_SUCCESS %s %s\n", id, detail)
		fmt.Printf("WARDEN_%s\n", strings.ReplaceAll(id, "-", "_"))
		return
	}
	fmt.Printf("WARDEN_DENIED %s %s\n", id, detail)
}
func guard() error {
	if os.Getuid() != 65534 || os.Getgid() != 65534 {
		return fmt.Errorf("dedicated nonroot sandbox required")
	}
	if _, e := os.Stat("/warden-probe"); e != nil {
		return fmt.Errorf("sandbox image marker missing: %w", e)
	}
	if f, e := os.OpenFile("/write-probe", os.O_WRONLY, 0); e == nil {
		f.Close()
		return fmt.Errorf("rootfs unexpectedly writable")
	}
	return nil
}
func probe(id string) (bool, string) {
	switch id {
	case "fork-bomb":
		children := []*os.Process{}
		defer func() {
			for _, p := range children {
				p.Kill()
				p.Wait()
			}
		}()
		for i := 0; i < 160; i++ {
			p, e := os.StartProcess("/warden-attack", []string{"/warden-attack", "hold"}, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
			if e != nil {
				return false, fmt.Sprintf("fork stopped at %d: %v", i, e)
			}
			children = append(children, p)
		}
		return true, "160 children launched"
	case "memory-exhaustion":
		blocks := make([][]byte, 0, 40)
		for i := 0; i < 36; i++ {
			b, e := unix.Mmap(-1, 0, 16<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
			if e != nil {
				return false, fmt.Sprintf("mmap stopped at %d MiB: %v", i*16, e)
			}
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			blocks = append(blocks, b)
		}
		for _, b := range blocks {
			unix.Munmap(b)
		}
		return true, "576 MiB touched"
	case "disk-fill":
		f, e := os.OpenFile("/dev/shm/warden-attack-fill", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return false, e.Error()
		}
		defer os.Remove(f.Name())
		defer f.Close()
		block := make([]byte, 1<<20)
		for i := 0; i < 80; i++ {
			if _, e = f.Write(block); e != nil {
				return false, fmt.Sprintf("tmpfs quota at %d MiB: %v", i, e)
			}
		}
		return true, "80 MiB written to bounded tmpfs"
	case "proc-leak":
		b, e := os.ReadFile("/proc/1/environ")
		if e != nil {
			return false, e.Error()
		}
		if len(b) > 0 {
			return true, fmt.Sprintf("PID1 environment readable (%d bytes, contents withheld)", len(b))
		}
		return false, "PID1 environment empty"
	case "sys-leak":
		b, e := os.ReadFile("/sys/devices/system/cpu/online")
		if e != nil {
			return false, e.Error()
		}
		if len(b) > 0 {
			return true, fmt.Sprintf("CPU topology readable (%d bytes, contents withheld)", len(b))
		}
		return false, "CPU topology empty"
	case "metadata-ip":
		c, e := net.DialTimeout("tcp", "169.254.169.254:80", time.Second)
		if e != nil {
			return false, e.Error()
		}
		c.Close()
		return true, "metadata IP connection opened"
	case "metadata-host":
		c, e := net.DialTimeout("tcp", "metadata.google.internal:80", time.Second)
		if e != nil {
			return false, e.Error()
		}
		c.Close()
		return true, "metadata hostname connection opened"
	case "raw-socket":
		fd, e := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if e != nil {
			return false, e.Error()
		}
		unix.Close(fd)
		return true, "AF_PACKET raw socket opened"
	case "arp-spoof":
		fd, e := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int((unix.ETH_P_ARP<<8)&0xff00|(unix.ETH_P_ARP>>8)))
		if e != nil {
			return false, e.Error()
		}
		defer unix.Close(fd)
		return true, "ARP raw socket opened (no peer target in network-none lab)"
	case "ptrace":
		_, _, errno := unix.RawSyscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_ATTACH), 1, 0, 0, 0, 0)
		if errno != 0 {
			return false, errno.Error()
		}
		unix.PtraceDetach(1)
		return true, "attached to PID1"
	case "mount-unshare":
		e1 := unix.Unshare(unix.CLONE_NEWNS)
		if e1 == nil {
			return true, "mount namespace unshared"
		}
		e2 := unix.Mount("tmpfs", "/dev/shm", "tmpfs", 0, "size=1m")
		if e2 == nil {
			unix.Unmount("/dev/shm", 0)
			return true, "tmpfs mounted"
		}
		return false, fmt.Sprintf("unshare=%v mount=%v", e1, e2)
	case "kernel-module":
		// Invalid bytes deliberately test the privilege gate without a loadable module.
		b := []byte{0}
		_, _, errno := unix.RawSyscall(unix.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		if errno == unix.EPERM {
			return false, "init_module denied EPERM"
		}
		return false, fmt.Sprintf("no valid module attempted; init_module result=%v", errno)
	case "dns-exfil":
		_, e := net.LookupTXT(strings.Repeat("a", 48) + ".invalid")
		if e != nil {
			return false, e.Error()
		}
		return true, "TXT response received (no external collector)"
	case "reverse-shell":
		c, e := net.DialTimeout("tcp", "192.0.2.1:4444", time.Second)
		if e != nil {
			return false, e.Error()
		}
		c.Close()
		return true, "TEST-NET listener connected (no shell sent)"
	default:
		return false, "unknown probe"
	}
}
func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	if os.Args[1] == "hold" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if e := guard(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	ok, detail := probe(os.Args[1])
	// These probes lack a separate in-lab target or positive control.
	// Their transport result cannot prove the intended isolation objective.
	switch os.Args[1] {
	case "proc-leak", "sys-leak", "disk-fill", "dns-exfil", "reverse-shell":
		fmt.Println("WARDEN_INCONCLUSIVE " + os.Args[1] + " " + detail)
		os.Exit(3)
	}
	if os.Args[1] == "kernel-module" && strings.HasPrefix(detail, "no valid module attempted") {
		fmt.Println("WARDEN_INCONCLUSIVE kernel-module " + detail)
		os.Exit(3)
	}
	result(os.Args[1], ok, detail)
}
