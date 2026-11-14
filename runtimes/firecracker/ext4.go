package firecracker

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// BuildExt4 uses only the pinned build image's fixed e2fsprogs, under its hard
// 2GB capless build limit. It never mounts or executes the exported payload.
func BuildExt4(source, destination string) error {
	root, e := privateRoot(source)
	if e != nil {
		return e
	}
	defer root.Close()
	parent, e := privateRoot(filepath.Dir(destination))
	if e != nil {
		return e
	}
	defer parent.Close()
	if filepath.Base(destination) != "agent.ext4" && filepath.Base(destination) != "payload.ext4" {
		return errors.New("fixed disk filename required")
	}
	file, e := checkedFile(parent, filepath.Base(destination), os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	if e = file.Truncate(32 << 20); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = dropHostXattrs(source); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-m", "0", "-O", "^has_journal", "-E", "lazy_itable_init=0,root_owner=0:0", "-d", source, destination, "8192")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if raw, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("fixed ext4 builder: %w %.1024s", e, raw)
	}
	cmd = exec.CommandContext(ctx, "/sbin/debugfs", "-w", "-R", "set_inode_field / mode 040755", destination)
	cmd.Env = []string{"LC_ALL=C"}
	if raw, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("fixed ext4 root mode: %w %.1024s", e, raw)
	}
	file, e = checkedFile(parent, filepath.Base(destination), os.O_RDONLY)
	if e != nil {
		return e
	}
	st, e := file.Stat()
	if e != nil || st.Size() != 32<<20 {
		file.Close()
		return errors.New("ext4 size exceeded fixed disk bound")
	}
	return errors.Join(file.Chmod(0400), file.Sync(), file.Close(), syncRoot(parent))
}

// dropHostXattrs removes POSIX ACLs that staging inherited from the host
// directory (mke2fs -d copies every xattr into the image) and refuses any
// other extended attribute. Links are never followed.
func dropHostXattrs(source string) error {
	return filepath.WalkDir(source, func(path string, _ fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
			if e := unix.Lremovexattr(path, name); e != nil && !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.EOPNOTSUPP) {
				return fmt.Errorf("drop host ACL %s: %w", path, e)
			}
		}
		var names [1024]byte
		n, e := unix.Llistxattr(path, names[:])
		if e != nil && !errors.Is(e, unix.EOPNOTSUPP) {
			return e
		}
		if n > 0 {
			return fmt.Errorf("host extended attribute would enter the guest image: %s", path)
		}
		return nil
	})
}
