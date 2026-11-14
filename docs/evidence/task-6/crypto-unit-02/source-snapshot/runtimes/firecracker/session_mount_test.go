package firecracker

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func sessionMetadata(t *testing.T) (unix.Stat_t, string, string) {
	t.Helper()
	p := private(t)
	f, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &st); e != nil {
		t.Fatal(e)
	}
	expected := fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, st.Uid)
	mount := fmt.Sprintf("123 99 %d:%d /owned/live %s ro,nosuid,nodev,relatime - ext4 /dev/sda rw,errors=remount-ro\n", unix.Major(st.Dev), unix.Minor(st.Dev), sessionPath)
	return st, expected, mount
}
func TestSessionMountMetadataAndOnlyROTransition(t *testing.T) {
	st, id, raw := sessionMetadata(t)
	before, e := verifySessionMount(st, id, "mnt:[1]", "mnt:[2]", raw, true)
	if e != nil {
		t.Fatal(e)
	}
	if before.ID != 123 || before.Flags != unix.MS_NOSUID|unix.MS_NODEV|unix.MS_RELATIME {
		t.Fatalf("VFS/super options conflated: %+v", before)
	}
	after, e := verifySessionMount(st, id, "mnt:[1]", "mnt:[2]", strings.Replace(raw, "ro,nosuid", "rw,nosuid", 1), false)
	if e != nil {
		t.Fatal(e)
	}
	if e = sameSessionMount(before, after); e != nil {
		t.Fatal(e)
	}
	changed := after
	changed.ID++
	if sameSessionMount(before, changed) == nil {
		t.Fatal("mount identity replacement accepted")
	}
	changed = after
	changed.Flags |= unix.MS_NOEXEC
	if sameSessionMount(before, changed) == nil {
		t.Fatal("extra remount flag change accepted")
	}
}
func TestSessionMountRejectsWrongMetadataAndUnsafeMounts(t *testing.T) {
	st, id, raw := sessionMetadata(t)
	for _, kind := range []string{"device", "inode", "uid", "mode", "identity", "namespace", "missing", "duplicate", "submount", "shared", "master", "unknownflag", "rw", "device-field", "malformed", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			observed := st
			expected := id
			host, current := "mnt:[1]", "mnt:[2]"
			mount := raw
			switch kind {
			case "device":
				observed.Dev++
			case "inode":
				observed.Ino++
			case "uid":
				observed.Uid++
			case "mode":
				observed.Mode |= 0020
			case "identity":
				expected = "1:2:root"
			case "namespace":
				current = host
			case "missing":
				mount = ""
			case "duplicate":
				mount += raw
			case "submount":
				mount += strings.Replace(raw, sessionPath, sessionPath+"/child", 1)
			case "shared":
				mount = strings.Replace(raw, " - ext4", " shared:9 - ext4", 1)
			case "master":
				mount = strings.Replace(raw, " - ext4", " master:9 - ext4", 1)
			case "unknownflag":
				mount = strings.Replace(raw, "ro,nosuid", "ro,unknown,nosuid", 1)
			case "rw":
				mount = strings.Replace(raw, "ro,nosuid", "rw,nosuid", 1)
			case "device-field":
				mount = strings.Replace(raw, fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)), "0:1", 1)
			case "malformed":
				mount = "123 99 0:1 / " + sessionPath + " ro"
			case "oversized":
				mount += strings.Repeat("x", 256*1024)
			}
			if _, e := verifySessionMount(observed, expected, host, current, mount, true); e == nil {
				t.Fatal("unsafe identity or mount accepted")
			}
		})
	}
}

func TestMountSmokeRefusesOrdinaryProcess(t *testing.T) {
	if e := MountSmoke(); e == nil {
		t.Fatal("ordinary process entered mounted session handshake")
	}
}
