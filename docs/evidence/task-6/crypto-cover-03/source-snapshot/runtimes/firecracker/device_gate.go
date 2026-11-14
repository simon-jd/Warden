package firecracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const deviceACK = "WARDEN_DEVICE_RECEIPT_OK\n"

func awaitDeviceACK(input io.ReadCloser, timeout time.Duration) error {
	defer input.Close()
	done := make(chan error, 1)
	go func() {
		raw, e := io.ReadAll(io.LimitReader(input, int64(len(deviceACK)+1)))
		if e == nil && string(raw) != deviceACK {
			e = errors.New("exact single device receipt ACK required")
		}
		done <- e
	}()
	select {
	case e := <-done:
		return e
	case <-time.After(timeout):
		return errors.New("device receipt ACK deadline")
	}
}

type deviceReceipt struct {
	Kind          string `json:"kind"`
	PID           int    `json:"pid"`
	CgroupNS      string `json:"cgroup_ns"`
	MountNS       string `json:"mount_ns"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	MountID       uint64 `json:"mount_id"`
	PolicyVersion string `json:"policy_version"`
	PolicySHA     string `json:"policy_sha256"`
}

func authenticatedDeviceTarget(target *os.File) (deviceReceipt, func() error, error) {
	flags, e := unix.FcntlInt(target.Fd(), unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		return deviceReceipt{}, nil, errors.New("cgroup FD must be CLOEXEC")
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if e := unix.Fstat(int(target.Fd()), &st); e != nil {
		return deviceReceipt{}, nil, e
	}
	if e := unix.Fstatfs(int(target.Fd()), &fs); e != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Uid != 0 || st.Mode&0022 != 0 {
		return deviceReceipt{}, nil, errors.New("owned cgroup2 FD required")
	}
	ns, e := os.Readlink("/proc/self/ns/cgroup")
	if e != nil {
		return deviceReceipt{}, nil, e
	}
	mnt, e := os.Readlink("/proc/self/ns/mnt")
	if e != nil {
		return deviceReceipt{}, nil, e
	}
	raw, e := boundedMountinfo()
	if e != nil {
		return deviceReceipt{}, nil, e
	}
	var id uint64
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		if strings.HasPrefix(f[4], "/sys/fs/cgroup/") {
			return deviceReceipt{}, nil, errors.New("unexpected cgroup submount")
		}
		if f[4] != "/sys/fs/cgroup" {
			continue
		}
		count++
		if len(f) != 10 || f[3] != "/" || f[6] != "-" || f[7] != "cgroup2" || f[2] != fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)) {
			return deviceReceipt{}, nil, errors.New("private root cgroup mount required")
		}
		id, e = strconv.ParseUint(f[0], 10, 64)
		if e != nil || id == 0 {
			return deviceReceipt{}, nil, errors.New("invalid cgroup mount ID")
		}
	}
	if count != 1 {
		return deviceReceipt{}, nil, errors.New("unique cgroup2 mount required")
	}
	receipt := deviceReceipt{"warden-device-receipt-v1", 1, ns, mnt, st.Dev, st.Ino, id, devicePolicyVersion, devicePolicySHA()}
	check := func() error {
		var now, path unix.Stat_t
		if e := unix.Fstat(int(target.Fd()), &now); e != nil {
			return e
		}
		if e := unix.Lstat("/sys/fs/cgroup", &path); e != nil {
			return e
		}
		current, e := os.Readlink("/proc/self/ns/cgroup")
		if e != nil {
			return e
		}
		currentMount, e := os.Readlink("/proc/self/ns/mnt")
		if e != nil {
			return e
		}
		membership, e := os.ReadFile("/proc/self/cgroup")
		if e != nil {
			return e
		}
		if now.Dev != st.Dev || now.Ino != st.Ino || path.Dev != st.Dev || path.Ino != st.Ino || current != ns || currentMount != mnt || strings.TrimSpace(string(membership)) != "0::/" {
			return errors.New("owned cgroup identity changed")
		}
		return nil
	}
	return receipt, check, check()
}
func proveDeviceBoundary() error {
	// New aliases are private tmpfs inodes. A path or DAC refusal is not proof.
	for _, path := range []string{"/dev/warden-denied-tun", "/dev/warden-denied-tun-alias"} {
		if e := unix.Mknod(path, unix.S_IFCHR|0600, int(unix.Mkdev(10, 200))); e != nil {
			return e
		}
		anchor, e := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(anchor, &st)
		if e != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != unix.Mkdev(10, 200) {
			unix.Close(anchor)
			return errors.New("TUN alias identity differs")
		}
		for _, mode := range []int{unix.O_RDONLY, unix.O_WRONLY, unix.O_RDWR} {
			var current unix.Stat_t
			if e = unix.Lstat(path, &current); e != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Rdev != st.Rdev {
				unix.Close(anchor)
				return errors.New("TUN alias replaced")
			}
			fd, err := unix.Open(path, mode|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err == nil {
				unix.Close(fd)
				unix.Close(anchor)
				return errors.New("TUN unexpectedly opened")
			}
			if !errors.Is(err, unix.EPERM) {
				unix.Close(anchor)
				return fmt.Errorf("TUN denial was not EPERM: %w", err)
			}
		}
		unix.Close(anchor)
		if e = unix.Unlink(path); e != nil {
			return e
		}
	}
	for _, dev := range []struct {
		path         string
		major, minor uint32
		mode         int
	}{{"/dev/null", 1, 3, unix.O_RDWR}, {"/dev/urandom", 1, 9, unix.O_RDONLY}, {"/dev/kvm", 10, 232, unix.O_RDWR}} {
		fd, e := unix.Open(dev.path, dev.mode|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		if e != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != unix.Mkdev(dev.major, dev.minor) {
			unix.Close(fd)
			return errors.New("allowed device identity mismatch")
		}
		switch dev.path {
		case "/dev/null":
			_, e = unix.Write(fd, []byte{0})
			if e == nil {
				var b [1]byte
				var n int
				n, e = unix.Read(fd, b[:])
				if e == nil && n != 0 {
					e = errors.New("null read not EOF")
				}
			}
		case "/dev/urandom":
			var b [16]byte
			var n int
			n, e = unix.Read(fd, b[:])
			if e == nil && n != len(b) {
				e = errors.New("short random read")
			}
		case "/dev/kvm":
			var version uintptr
			var errno unix.Errno
			version, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0xae00, 0)
			if errno != 0 || version != 12 {
				e = errors.New("KVM API version differs")
			}
		}
		unix.Close(fd)
		if e != nil {
			return e
		}
	}
	return nil
}
func emitDeviceReceipt(r deviceReceipt) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(raw)+1 > 4096 {
		return errors.New("receipt overflow")
	}
	_, e = fmt.Println(string(raw))
	return e
}
