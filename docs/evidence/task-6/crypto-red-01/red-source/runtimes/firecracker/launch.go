package firecracker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"regexp"
	"strconv"
	"syscall"
)

const inputPath = "/opt/warden/input"
const sessionPath = "/opt/warden/session"

func jailerArgs(p Profile, uid uint32) ([]string, error) {
	if uid < 2000000001 || uid > 2001000000 || !runPattern.MatchString(p.Spec.RunID) || p.VMMemoryMiB < 128 || p.VMMemoryMiB > 640 {
		return nil, errors.New("reviewed profile and allocated host identity required")
	}
	identity := strconv.FormatUint(uint64(uid), 10)
	return []string{"--id", "warden-" + p.Spec.RunID, "--exec-file", inputPath + "/firecracker", "--uid", identity, "--gid", identity, "--cgroup-version", "2", "--parent-cgroup", "warden-lab/vms/warden-" + p.Spec.RunID, "--chroot-base-dir", sessionPath + "/jails", "--resource-limit", "no-file=1024", "--resource-limit", fmt.Sprintf("fsize=%d", int64(p.VMMemoryMiB+16)*1048576), "--", "--api-sock", "/api.sock"}, nil
}
func verifiedArtifact(root *os.Root, name, hash string, limit int64) (*os.File, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) || limit <= 0 {
		return nil, errors.New("invalid fixed artifact")
	}
	f, e := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0222 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Size() <= 0 || st.Size() > limit {
		return nil, errors.New("immutable artifact owner/type/size/mode mismatch")
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, limit+1)); e != nil {
		return nil, e
	}
	if hex.EncodeToString(h.Sum(nil)) != hash {
		return nil, errors.New("immutable artifact hash mismatch")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return nil, e
	}
	ok = true
	return f, nil
}
