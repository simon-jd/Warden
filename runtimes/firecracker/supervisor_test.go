package firecracker

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestSupervisorRefusesOrdinaryProcessBeforeDeviceOrMount(t *testing.T) {
	if e := Supervise("boot"); e == nil {
		t.Fatal("ordinary process admitted as privileged supervisor")
	}
}
func TestOuterLimitsMustMatchFixedMode(t *testing.T) {
	for _, mode := range []string{"boot", "conformance", "snapshot"} {
		if e := validateOuterLimits(mode, "3999997952", "0", "512", "200000 100000"); e != nil {
			t.Fatal(e)
		}
		if e := validateOuterLimits(mode, "max", "0", "512", "200000 100000"); e == nil {
			t.Fatal("unbounded outer admitted")
		}
	}
	if e := validateOuterLimits("capacity-default", "14999998464", "0", "512", "200000 100000"); e != nil {
		t.Fatal(e)
	}
	if e := validateOuterLimits("capacity-default", "16000000000", "0", "512", "200000 100000"); e == nil {
		t.Fatal("host allowance consumed")
	}
}

// The fixed amd64 lab's 4KiB page readback was observed on this host in Task3.
// Arbitrary lower values are not equivalent to the fixed Docker request.
func TestOuterLimitsOnlyCanonicalPageFloor(t *testing.T) {
	if os.Getpagesize() != 4096 {
		t.Fatal("fixed lab requires observed 4KiB pages")
	}
	for _, tc := range []struct {
		mode     string
		readback int64
	}{{"boot", 3999997952}, {"capacity-default", 14999998464}, {"capacity-benchmark", 14999998464}, {"capacity-pressure", 14999998464}} {
		memory := fmt.Sprint(tc.readback)
		pids := "512"
		if tc.mode == "capacity-pressure" {
			pids = "1024"
		}
		if e := validateOuterLimits(tc.mode, memory, "0", pids, "200000 100000"); e != nil {
			t.Errorf("canonical %s: %v", tc.mode, e)
		}
		for _, bad := range []string{fmt.Sprint(tc.readback - 4096), fmt.Sprint(tc.readback - 1), fmt.Sprint(tc.readback + 1), fmt.Sprint(tc.readback + 4096), "4000000000", "15000000000", "0", "max", "+" + memory, "0" + memory} {
			if e := validateOuterLimits(tc.mode, bad, "0", pids, "200000 100000"); e == nil {
				t.Errorf("noncanonical %s memory %s accepted", tc.mode, bad)
			}
		}
		for _, v := range [][3]string{{"1", pids, "200000 100000"}, {"0", "511", "200000 100000"}, {"0", pids, "199999 100000"}} {
			if e := validateOuterLimits(tc.mode, memory, v[0], v[1], v[2]); e == nil {
				t.Errorf("nonmemory limits changed: %v", v)
			}
		}
	}
	for _, mode := range []string{"", "capacity-other", "shell"} {
		if e := validateOuterLimits(mode, "3999997952", "0", "512", "200000 100000"); e == nil {
			t.Errorf("unknown mode %q", mode)
		}
	}
}

// Only capacity-pressure's outer gets 1024 pids. On 2026-11-10 its 101st VM
// did not start while 508 of the 512 were in use (about five per VM); the
// other modes keep 512.
func TestOuterPidsRaisedForCapacityPressureOnly(t *testing.T) {
	for _, mode := range []string{"boot", "conformance", "snapshot", "device-policy", "capacity-default", "capacity-benchmark", "capacity-pressure"} {
		memory, e := outerMemoryMax(mode)
		if e != nil {
			t.Fatal(e)
		}
		want, other := "512", "1024"
		if mode == "capacity-pressure" {
			want, other = "1024", "512"
		}
		if e := validateOuterLimits(mode, memory, "0", want, "200000 100000"); e != nil {
			t.Errorf("%s with pids.max %s: %v", mode, want, e)
		}
		for _, bad := range []string{other, "max", "0", "513", "1023", "1025", "2048", "+" + want, "0" + want} {
			if e := validateOuterLimits(mode, memory, "0", bad, "200000 100000"); e == nil {
				t.Errorf("%s accepted pids.max %s", mode, bad)
			}
		}
	}
}

// A failed run used to leave the session root-owned (2026-10-24), and the host
// has no sudo to remove it. Once the node cgroup is empty, the failure path
// drops the per-VM data and returns every remaining inode to the operator.
//
// The test runs unprivileged, so it cannot make root-owned files. It hands
// the session to one of its supplementary groups instead: every kept inode
// starts with the primary group, so only a Lchown walk that reaches all of
// them (directories and the symlink itself included) passes.
func TestReleaseFailedSessionDropsVMDataAndReturnsOwnership(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	groups, e := os.Getgroups()
	if e != nil {
		t.Fatal(e)
	}
	target := -1
	for _, g := range groups {
		if g != gid {
			target = g
			break
		}
	}
	if target < 0 {
		t.Skip("needs a supplementary group to tell a chown walk from no walk")
	}
	dir := t.TempDir()
	for _, p := range []string{"jails/firecracker/warden-X/root/dev", "node/assets", "node/snapshots/k", "node/gate", "node/runs", "node/console"} {
		if e := os.MkdirAll(dir+"/"+p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{"jails/firecracker/warden-X/root/kernel", "node/assets/kernel", "node/snapshots/k/memory", "node/gate/node", "node/runs/R", "node/console/R.log", "node/owner"} {
		if e := os.WriteFile(dir+"/"+p, []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink("/etc/passwd", dir+"/node/runs/link"); e != nil {
		t.Fatal(e)
	}
	kept := []string{".", "node", "node/gate", "node/gate/node", "node/runs", "node/runs/R", "node/runs/link", "node/console", "node/console/R.log", "node/owner"}
	for _, p := range kept {
		st, e := os.Lstat(dir + "/" + p)
		if e != nil {
			t.Fatal(e)
		}
		if int(st.Sys().(*syscall.Stat_t).Gid) == target {
			t.Fatalf("%s already has group %d before the release", p, target)
		}
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = releaseFailedSession(root, uid, target); e != nil {
		t.Fatal(e)
	}
	for _, gone := range []string{"jails", "node/assets", "node/snapshots"} {
		if _, e := os.Lstat(dir + "/" + gone); !os.IsNotExist(e) {
			t.Fatalf("%s kept after failure release: %v", gone, e)
		}
	}
	for _, p := range kept {
		st, e := os.Lstat(dir + "/" + p)
		if e != nil {
			t.Fatalf("evidence %s removed: %v", p, e)
		}
		if s := st.Sys().(*syscall.Stat_t); int(s.Uid) != uid || int(s.Gid) != target {
			t.Errorf("%s is %d:%d, not handed to %d:%d", p, s.Uid, s.Gid, uid, target)
		}
	}
	if link, e := os.Readlink(dir + "/node/runs/link"); e != nil || link != "/etc/passwd" {
		t.Fatalf("symlink must not be followed or rewritten: %q %v", link, e)
	}
}
