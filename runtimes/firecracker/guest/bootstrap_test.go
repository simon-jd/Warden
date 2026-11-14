package guest

import "testing"

func TestBootstrapRefusesOrdinaryCodeProcessBeforeAnyMount(t *testing.T) {
	if e := Boot(); e == nil {
		t.Fatal("guest bootstrap admitted a host/code process")
	}
}

// The Firecracker CI guest kernel has CONFIG_DEVTMPFS_MOUNT=y: devtmpfs is
// already on /dev when PID1 starts, and mounting it again returned EBUSY,
// which made the agent exit and the kernel panic before Ready (2026-11-10
// serial log). PID1 must harden the existing mount instead of remounting it.
func TestDevMountReusesKernelDevtmpfs(t *testing.T) {
	const kernelMounted = "21 1 254:0 / / ro,relatime - ext4 /dev/vda ro\n" +
		"22 21 0:5 / /dev rw,relatime - devtmpfs devtmpfs rw,size=322436k,nr_inodes=80609,mode=755\n" +
		"23 21 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
	remount, e := devMount(kernelMounted)
	if e != nil || !remount {
		t.Fatalf("kernel devtmpfs on /dev must be hardened in place: remount=%v err=%v", remount, e)
	}
	remount, e = devMount("21 1 254:0 / / ro,relatime - ext4 /dev/vda ro\n23 21 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
	if e != nil || remount {
		t.Fatalf("without a kernel mount PID1 mounts devtmpfs itself: remount=%v err=%v", remount, e)
	}
	for _, bad := range []string{
		"21 1 254:0 / / ro,relatime - ext4 /dev/vda ro\n22 21 0:5 / /dev rw,relatime - tmpfs tmpfs rw\n",
		"22 21 0:5 / /dev rw,relatime devtmpfs devtmpfs rw\n",
	} {
		if _, e = devMount(bad); e == nil {
			t.Fatalf("accepted unexpected /dev mount: %q", bad)
		}
	}
}

func TestPayloadCommandSelectsFixedCorpusShell(t *testing.T) {
	path, args, e := payloadCommand("exec /warden-attack fork-bomb")
	if e != nil || path != "/bin/sh" || len(args) != 3 || args[1] != "-c" || args[2] != "exec /warden-attack fork-bomb" {
		t.Fatalf("corpus dispatch: %q %v %v", path, args, e)
	}
	if _, _, e = payloadCommand("exec /warden-attack fork-bomb; id"); e == nil {
		t.Fatal("shell suffix admitted")
	}
	path, args, e = payloadCommand("uid")
	if e != nil || path != "/warden-probe" || len(args) != 2 || args[1] != "uid" {
		t.Fatalf("conformance dispatch: %q %v %v", path, args, e)
	}
}
