// Command warden-node-init is PID 1 of the k3s lab node in Cilium mode
// (scripts/k3s_gvisor_lab.sh up --cilium). The node container is privileged,
// so its /proc/sys is writable and reaches the host's global sysctls, and
// Cilium's agent writes some of them at start (kernel.timer_migration and
// kernel.unprivileged_bpf_disabled; the second, once 1, cannot be undone
// without a reboot). Before it starts k3s, warden-node-init:
//
//  1. makes every mount shared, as kind's node entrypoint does: Cilium mounts
//     bpffs with Bidirectional propagation, which kubelet refuses on a private
//     /sys. Docker made the node's mounts private, so this creates new peer
//     groups inside the node; nothing propagates to or from the host;
//  2. makes /proc/sys read-only, except /proc/sys/net, which belongs to the
//     node's own network namespace. Pods that mount /proc/sys/kernel or
//     /proc/sys/net from the node (Cilium's agent does) get the same view.
//
// It refuses to start k3s if /proc/sys/kernel is still writable or
// /proc/sys/net is not.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type step struct {
	src, dst string
	flags    uintptr
}

// Keep /proc/sys/net a separate (writable) mount, copy the tree onto itself,
// then make the top of the copy read-only. MS_REMOUNT|MS_BIND changes only
// that one mount, so the net submount stays writable.
var steps = []step{
	{"", "/", unix.MS_REC | unix.MS_SHARED},
	{"/proc/sys/net", "/proc/sys/net", unix.MS_BIND},
	{"/proc/sys", "/proc/sys", unix.MS_BIND | unix.MS_REC},
	{"", "/proc/sys", unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
}

// Global sysctls that must be read-only once the steps ran (the two Cilium
// writes and one kubelet's protect-kernel-defaults checks), and one sysctl of
// the node's own network namespace that must stay writable.
var (
	readOnly = []string{"/proc/sys/kernel/timer_migration", "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/vm/overcommit_memory"}
	writable = "/proc/sys/net/ipv4/conf/all/forwarding"
)

type mountFunc func(src, dst, fstype string, flags uintptr, data string) error
type accessFunc func(path string, mode uint32) error

func setup(mount mountFunc, access accessFunc) error {
	for _, s := range steps {
		if err := mount(s.src, s.dst, "", s.flags, ""); err != nil {
			return fmt.Errorf("mount %s (flags %#x): %w", s.dst, s.flags, err)
		}
	}
	for _, p := range readOnly {
		if err := access(p, unix.W_OK); err != unix.EROFS {
			return fmt.Errorf("%s is not read-only (access: %v)", p, err)
		}
	}
	if err := access(writable, unix.W_OK); err != nil {
		return fmt.Errorf("/proc/sys/net is not writable (%s: %v)", writable, err)
	}
	return nil
}

// argv is k3s with the node's arguments (the container's CMD).
func argv(args []string) []string {
	return append([]string{"/bin/k3s"}, args[1:]...)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warden-node-init: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if err := setup(unix.Mount, unix.Access); err != nil {
		fail("%v", err)
	}
	a := argv(os.Args)
	fail("exec %s: %v", a[0], unix.Exec(a[0], a, os.Environ()))
}
