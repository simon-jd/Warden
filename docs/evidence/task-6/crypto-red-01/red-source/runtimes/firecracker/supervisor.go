package firecracker

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Docker requests remain nominal; this local lab accepts only their unique
// page-floor kernel readback, never an arbitrary smaller memory allowance.
func outerMemoryMax(mode string) (string, error) {
	var requested int64 = 4000000000
	switch mode {
	case "boot", "conformance", "snapshot", "device-policy":
	case "capacity-default", "capacity-benchmark":
		requested = 15000000000
	default:
		return "", errors.New("fixed actual mode required")
	}
	page := int64(os.Getpagesize())
	return strconv.FormatInt(requested/page*page, 10), nil
}
func validateOuterLimits(mode, memory, swap, pids, cpu string) error {
	want, e := outerMemoryMax(mode)
	if e != nil {
		return e
	}
	if memory != want || swap != "0" || pids != "512" || cpu != "200000 100000" {
		return errors.New("outer memory/swap/pids/CPU differs from sealed profile")
	}
	return nil
}

// Supervise is the immutable outer image PID1 entrypoint. No command, device,
// directory, or cgroup name is supplied by a workload or caller.
func Supervise(mode string) error {
	if os.Getpid() != 1 || os.Geteuid() != 0 || os.Getenv("WARDEN_FC_REVIEWED") != "controller-reviewed" {
		return errors.New("reviewed private outer PID1 required")
	}
	host := os.Getenv("WARDEN_FC_HOST_CGROUP_NS")
	ns, e := os.Readlink("/proc/self/ns/cgroup")
	membership, e2 := os.ReadFile("/proc/self/cgroup")
	if e != nil || e2 != nil || !regexp.MustCompile(`^cgroup:\[[0-9]+\]$`).MatchString(host) || host == ns || strings.TrimSpace(string(membership)) != "0::/" {
		return errors.New("private owned cgroup namespace root required")
	}
	if _, e = outerMemoryMax(mode); e != nil {
		return e
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	required := uint64(1<<unix.CAP_CHOWN | 1<<unix.CAP_DAC_OVERRIDE | 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID | 1<<unix.CAP_SYS_CHROOT | 1<<unix.CAP_MKNOD | 1<<unix.CAP_SYS_ADMIN | 1<<unix.CAP_KILL)
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		a, b, ok := strings.Cut(line, ":")
		if ok {
			fields[a] = strings.TrimSpace(b)
		}
	}
	caps, e := strconv.ParseUint(fields["CapEff"], 16, 64)
	if e != nil || caps != required || fields["NoNewPrivs"] != "1" {
		return errors.New("exact eight-capability NNP profile required")
	}
	for _, path := range []string{"/", "/proc/sys"} {
		var fs unix.Statfs_t
		if e = unix.Statfs(path, &fs); e != nil || fs.Flags&unix.ST_RDONLY == 0 {
			return errors.New("outer root and proc/sys must remain read-only")
		}
	}
	// Authenticate the initial RO bind before any device/cgroup/session mutation.
	session, _, e := openVerifiedSession(false)
	if e != nil {
		return e
	}
	defer session.Close()
	var device unix.Stat_t
	if e = unix.Lstat("/dev/kvm", &device); e != nil || device.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(device.Rdev)) != 10 || unix.Minor(uint64(device.Rdev)) != 232 {
		return errors.New("exact KVM character device required")
	}
	// Replace Docker's RO cgroup view with a new mount rooted at this already
	// authenticated private namespace. No host cgroup bind is accepted.
	if e = unix.Unmount("/sys/fs/cgroup", unix.MNT_DETACH); e != nil {
		return e
	}
	if e = unix.Mount("none", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		return e
	}
	mounts, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return e
	}
	matched := 0
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == "/sys/fs/cgroup" && strings.Contains(line, " - cgroup2 ") {
			if f[3] != "/" {
				return errors.New("cgroup mount not private root")
			}
			matched++
		}
	}
	if matched != 1 {
		return errors.New("unique private cgroup2 mount required")
	}
	cg, e := os.OpenRoot("/sys/fs/cgroup")
	if e != nil {
		return e
	}
	defer cg.Close()
	read := func(name string) (string, error) {
		raw, e := cg.ReadFile(name)
		return strings.TrimSpace(string(raw)), e
	}
	limits := []string{}
	for _, name := range []string{"memory.max", "memory.swap.max", "pids.max", "cpu.max"} {
		s, e := read(name)
		if e != nil {
			return e
		}
		limits = append(limits, s)
	}
	if e = validateOuterLimits(mode, limits[0], limits[1], limits[2], limits[3]); e != nil {
		return e
	}
	procs, e := read("cgroup.procs")
	if e != nil || procs != "1" {
		return errors.New("unexpected private-root process")
	}
	// Query/load only after the fixed root, actual limits and PID1 membership
	// have been authenticated. The original policy is never replaced/detached.
	target, e := cg.Open(".")
	if e != nil {
		return e
	}
	defer target.Close()
	receipt, checkTarget, e := authenticatedDeviceTarget(target)
	if e != nil {
		return e
	}
	if e = emitDeviceReceipt(receipt); e != nil {
		return e
	}
	if e = awaitDeviceACK(os.Stdin, 10*time.Second); e != nil {
		return e
	}
	program, policyID, e := sealDevicePolicy(kernelDevicePolicy{target: target, check: checkTarget})
	if e != nil {
		return e
	}
	defer program.Close()
	if e = checkTarget(); e != nil {
		return e
	}
	if e = proveDeviceBoundary(); e != nil {
		return e
	}
	fmt.Printf("device policy verified: version=%s sha256=%s program_id=%d; TUN rw EPERM, basics and KVM API12; no VM from probe\n", devicePolicyVersion, devicePolicySHA(), policyID)
	if mode == "device-policy" {
		return nil
	}
	writable, _, e := openVerifiedSession(true)
	if e != nil {
		return e
	}
	defer writable.Close()
	session = writable

	write := func(name, value string) error {
		f, e := cg.OpenFile(name, os.O_WRONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		_, e = f.WriteString(value)
		return errors.Join(e, f.Close())
	}
	if e = cg.Mkdir("supervisor", 0700); e != nil {
		return e
	}
	if e = write("supervisor/cgroup.procs", "1"); e != nil {
		return e
	}
	if e = write("cgroup.subtree_control", "+memory +pids +cpu"); e != nil {
		return e
	}
	for _, name := range []string{"warden-lab", "warden-lab/service", "warden-lab/vms"} {
		if e = cg.Mkdir(name, 0700); e != nil {
			return e
		}
		if name != "warden-lab/service" {
			if e = write(name+"/cgroup.subtree_control", "+memory +pids +cpu"); e != nil {
				return e
			}
		}
	}
	// Claim only the fresh bind directory, never shared material or old nodes.
	st, e := session.Stat()
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != 1000 {
		return errors.New("fresh ordinary-owned session required")
	}
	entries, e := session.ReadDir(-1)
	if e != nil || len(entries) != 0 {
		return errors.New("live session bind must start empty")
	}
	if e = session.Chown(0, 0); e != nil {
		return e
	}
	tests := map[string]string{"boot": "TestFirecrackerBoot", "conformance": "TestFirecrackerConformance", "snapshot": "TestSnapshotRestoreFasterThanBoot", "capacity-default": "TestFirecrackerCapacity", "capacity-benchmark": "TestFirecrackerCapacity"}
	test, ok := tests[mode]
	if !ok {
		return errors.New("unknown fixed mode")
	}
	service, e := cg.Open("warden-lab/service")
	if e != nil {
		return e
	}
	defer service.Close()
	cmd := exec.Command(inputPath+"/firecracker.test", "-test.v", "-test.count=1", "-test.timeout=600s", "-test.run=^"+test+"$")
	cmd.Env = []string{"WARDEN_FC_REVIEWED=controller-reviewed", "WARDEN_FC_HOST_CGROUP_NS=" + host, "WARDEN_FC_MODE=" + mode, "GOMAXPROCS=2", "GOMEMLIMIT=256MiB"}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(service.Fd())}
	child, e := startOwned(cmd)
	if e != nil {
		return e
	}
	select {
	case <-child.done:
	case <-time.After(610 * time.Second):
	}
	if e = write("warden-lab/cgroup.kill", "1"); e != nil {
		return e
	}
	if e = child.Stop(); e != nil {
		return errors.Join(e, ErrCleanupPending)
	}
	for _, path := range []string{"warden-lab", "warden-lab/vms", "warden-lab/service"} {
		raw, e := read(path + "/cgroup.events")
		if e != nil {
			return e
		}
		n, e := Counter(raw, "populated")
		if e != nil || n != 0 {
			return ErrCleanupPending
		}
	}
	// A valid worker writes this only after all Gate.Reap operations, original
	// VMM reaping and descriptor retirement. Worker death alone is insufficient.
	root, e := privateRoot(sessionPath)
	if e != nil {
		return e
	}
	defer root.Close()
	retired, e := root.ReadFile("node/retired")
	if e != nil || string(retired) != "known-owner-retired\n" {
		return ErrCleanupPending
	}
	for _, path := range []string{"node/assets", "node/snapshots", "jails"} {
		if e = root.RemoveAll(path); e != nil {
			return e
		}
	}
	if e = releaseMetadata(root, "."); e != nil {
		return e
	}
	if e = session.Chown(1000, 1000); e != nil {
		return e
	}
	if e = session.Sync(); e != nil {
		return e
	}
	fmt.Println("known-owner VMM/worker pidfds reaped; cgroup populated=0; owned data and FDs retired; metadata released")
	if child.waitErr != nil {
		return child.waitErr
	}
	return nil
}
func releaseMetadata(root *os.Root, path string) error {
	f, e := root.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	raw := st.Sys().(*syscall.Stat_t)
	if raw.Uid != 0 || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe metadata owner")
	}
	if st.IsDir() {
		if st.Mode().Perm() != 0700 {
			return errors.New("unsafe metadata directory mode")
		}
		entries, e := f.ReadDir(-1)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if e = releaseMetadata(root, filepath.Join(path, entry.Name())); e != nil {
				return e
			}
		}
	} else if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || raw.Nlink != 1 || st.Size() > 65536 {
		return errors.New("unsafe retained metadata inode")
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return f.Chown(1000, 1000)
}
