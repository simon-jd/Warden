package gate

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func (g *Gate) admissionSeal() string { return "admission-sealed-v1\n" + g.authority + "\n" }

// admissionSealed is called only while the original admission lock is held.
// Absence is the only unsealed state; partial or foreign seals fail closed.
func (g *Gate) admissionSealed(directory *os.File) (bool, error) {
	fd, e := unix.Openat(int(directory.Fd()), "admission-sealed", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	f := os.NewFile(uintptr(fd), "admission-sealed")
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return false, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		return false, errors.New("unsafe admission seal")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil {
		return false, e
	}
	if string(raw) != g.admissionSeal() {
		return false, errors.New("malformed or foreign admission seal")
	}
	return true, nil
}

// SealAdmission permanently denies future Gate.Start calls across instances and
// reopen. It serializes with creation of launch markers, not with the driver
// callback: callers must still Reap every admitted run under its bounded lock.
// This deny-only fence never writes retirement proof/binding or supplies a
// Reconciliation. Ambiguous runs remain ambiguous; there is no unseal operation.
func (g *Gate) SealAdmission(ctx context.Context) error {
	admission, e := g.lock(ctx, "admission")
	if e != nil {
		return e
	}
	defer unlock(admission)
	sealed, e := g.admissionSealed(admission.directory)
	if e != nil || sealed {
		return e
	}
	f, e := g.lock(ctx, "admission-sealed")
	if e != nil {
		return e
	}
	defer unlock(f)
	return g.mark(f, g.admissionSeal())
}
