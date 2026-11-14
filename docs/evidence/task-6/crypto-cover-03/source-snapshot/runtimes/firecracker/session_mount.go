package firecracker

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type sessionMount struct {
	ID    uint64
	Flags uintptr
}

var sessionVFSFlags = map[string]uintptr{
	"nosuid": unix.MS_NOSUID, "nodev": unix.MS_NODEV, "noexec": unix.MS_NOEXEC,
	"nosymfollow": unix.MS_NOSYMFOLLOW, "noatime": unix.MS_NOATIME, "nodiratime": unix.MS_NODIRATIME,
	"relatime": unix.MS_RELATIME, "strictatime": unix.MS_STRICTATIME, "lazytime": unix.MS_LAZYTIME,
}

// Only metadata is consumed here. Superblock options after the separator are
// deliberately not remount flags; the VFS mount must be private and unique.
func verifySessionMount(st unix.Stat_t, expected, hostNS, currentNS, raw string, readonly bool) (sessionMount, error) {
	var result sessionMount
	identity := fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, st.Uid)
	nsPattern := regexp.MustCompile(`^mnt:\[[1-9][0-9]*\]$`)
	if identity != expected || st.Dev == 0 || st.Ino == 0 || st.Uid != 1000 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || !nsPattern.MatchString(hostNS) || !nsPattern.MatchString(currentNS) || hostNS == currentNS || len(raw) > 256*1024 {
		return result, errors.New("session identity/private namespace mismatch")
	}
	matches := 0
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		if strings.HasPrefix(f[4], sessionPath+"/") {
			return result, errors.New("session submount forbidden")
		}
		if f[4] != sessionPath {
			continue
		}
		matches++
		if len(f) != 10 || f[6] != "-" || f[2] != fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)) {
			return result, errors.New("unique private session mount metadata required")
		}
		id, e := strconv.ParseUint(f[0], 10, 64)
		if e != nil || id == 0 {
			return result, errors.New("invalid session mount ID")
		}
		result.ID = id
		if _, e = strconv.ParseUint(f[1], 10, 64); e != nil {
			return result, errors.New("invalid parent mount ID")
		}
		seen := map[string]bool{}
		for _, option := range strings.Split(f[5], ",") {
			if seen[option] {
				return result, errors.New("duplicate VFS option")
			}
			seen[option] = true
			if option == "ro" || option == "rw" {
				continue
			}
			flag, ok := sessionVFSFlags[option]
			if !ok {
				return result, errors.New("unknown session VFS flag")
			}
			result.Flags |= flag
		}
		if seen["ro"] != readonly || seen["rw"] == readonly {
			return result, errors.New("session readonly state mismatch")
		}
	}
	if matches != 1 {
		return result, errors.New("unique session mount required")
	}
	return result, nil
}
func sameSessionMount(a, b sessionMount) error {
	if a != b {
		return errors.New("remount changed mount identity or other flags")
	}
	return nil
}
func boundedMountinfo() (string, error) {
	f, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return "", e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 256*1024+1))
	if e != nil || len(raw) > 256*1024 {
		return "", errors.New("mountinfo unavailable or oversized")
	}
	return string(raw), nil
}

// Fixed trusted entrypoint only: open the mountpoint without following a link,
// verify metadata before any session content access, and retain this exact FD.
func openVerifiedSession(writable bool) (*os.File, sessionMount, error) {
	var before sessionMount
	current, e := os.Readlink("/proc/self/ns/mnt")
	if e != nil {
		return nil, before, e
	}
	host := os.Getenv("WARDEN_FC_HOST_MOUNT_NS")
	expected := os.Getenv("WARDEN_FC_SESSION_IDENTITY")
	if !regexp.MustCompile(`^[1-9][0-9]*:[1-9][0-9]*:1000$`).MatchString(expected) || host == current {
		return nil, before, errors.New("held host session identity required")
	}
	fd, e := unix.Open(sessionPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, before, e
	}
	file := os.NewFile(uintptr(fd), sessionPath)
	success := false
	defer func() {
		if !success {
			file.Close()
		}
	}()
	check := func(readonly bool) (sessionMount, error) {
		var st, path unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			return sessionMount{}, e
		}
		if e := unix.Lstat(sessionPath, &path); e != nil {
			return sessionMount{}, e
		}
		if st.Dev != path.Dev || st.Ino != path.Ino || st.Uid != path.Uid || st.Mode != path.Mode {
			return sessionMount{}, errors.New("session path no longer matches original FD")
		}
		raw, e := boundedMountinfo()
		if e != nil {
			return sessionMount{}, e
		}
		return verifySessionMount(st, expected, host, current, raw, readonly)
	}
	before, e = check(true)
	if e != nil {
		return nil, before, e
	}
	if writable {
		if e = unix.Mount("", fmt.Sprintf("/proc/self/fd/%d", fd), "", unix.MS_BIND|unix.MS_REMOUNT|before.Flags, ""); e != nil {
			return nil, before, e
		}
		after, e := check(false)
		if e != nil {
			return nil, before, e
		}
		if e = sameSessionMount(before, after); e != nil {
			return nil, before, e
		}
	}
	success = true
	return file, before, nil
}

// MountSmoke validates only the initial RO bind. No mounted contents, remount,
// cgroups, device probes, ownership changes, Gate or VMM operations occur here.
func MountSmoke() error {
	if os.Getpid() != 1 || os.Geteuid() != 1000 || os.Getenv("WARDEN_FC_MOUNT_SMOKE") != "controller-reviewed-ro-only" || os.Getenv("WARDEN_FC_REVIEWED") != "" {
		return errors.New("fixed capless mount-smoke PID1 required")
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		a, b, ok := strings.Cut(line, ":")
		if ok {
			fields[a] = strings.TrimSpace(b)
		}
	}
	for _, name := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
		n, e := strconv.ParseUint(fields[name], 16, 64)
		if e != nil || n != 0 {
			return errors.New("mount-smoke requires zero capabilities")
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("mount-smoke NNP required")
	}
	for _, path := range []string{"/", "/proc/sys"} {
		var fs unix.Statfs_t
		if e = unix.Statfs(path, &fs); e != nil || fs.Flags&unix.ST_RDONLY == 0 {
			return errors.New("mount-smoke readonly root/proc-sys required")
		}
	}
	session, mount, e := openVerifiedSession(false)
	if e != nil {
		return e
	}
	defer session.Close()
	fmt.Printf("RO-only session metadata verified: identity=%s mount_id=%d preserved_vfs_flags=%d; no content access/remount/cgroup/device/VM\n", os.Getenv("WARDEN_FC_SESSION_IDENTITY"), mount.ID, mount.Flags)
	return nil
}
