package firecracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var runPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)
var authorityPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}/[0-9a-f]{32}$`)

// Allocator never reuses an ID within an authority. Failed allocations may burn
// IDs. Its directory is durable node state and must not be cloned or reset.
type Allocator struct {
	root      *os.Root
	authority string
}
type allocationState struct {
	Authority string
	Next      uint32
}

func privateRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute clean private path required")
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return nil, errors.New("symlink or missing private directory")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		s := st.Sys().(*syscall.Stat_t)
		// A root-owned sticky ancestor (e.g. /tmp) does not grant authority to
		// replace an owned private descendant. Other writable ancestors fail.
		if s.Uid != 0 && s.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("untrusted ancestor owner")
		}
		if st.Mode().Perm()&0022 != 0 && !(s.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return nil, errors.New("writable private ancestor")
		}
		if p == path && (st.Mode().Perm() != 0700 || s.Uid != uint32(os.Geteuid())) {
			return nil, errors.New("private directory owner or mode")
		}
		if p == "/" {
			break
		}
	}
	return os.OpenRoot(path)
}

func checkedFile(root *os.Root, name string, flags int) (*os.File, error) {
	f, e := root.OpenFile(name, flags|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	s := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("unsafe private state file")
	}
	return f, nil
}
func syncRoot(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func (a *Allocator) lock() (*os.File, error) {
	f, e := checkedFile(a.root, "lock", os.O_CREATE|os.O_RDWR)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func unlockAllocation(f *os.File) { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }
func (a *Allocator) read() (allocationState, error) {
	f, e := checkedFile(a.root, "state", os.O_RDONLY)
	if e != nil {
		return allocationState{}, e
	}
	defer f.Close()
	var s allocationState
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return s, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF || s.Authority != a.authority || s.Next < 2000000001 || s.Next > 2001000001 {
		return s, errors.New("allocation authority or counter corrupt")
	}
	return s, nil
}
func (a *Allocator) save(s allocationState) error {
	f, e := checkedFile(a.root, "next", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	e = json.NewEncoder(f).Encode(s)
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return e
	}
	if e = a.root.Rename("next", "state"); e != nil {
		return e
	}
	return syncRoot(a.root)
}
func OpenAllocator(path, authority string) (*Allocator, error) {
	if !authorityPattern.MatchString(authority) {
		return nil, errors.New("invalid node authority")
	}
	r, e := privateRoot(path)
	if e != nil {
		return nil, e
	}
	a := &Allocator{r, authority}
	ok := false
	defer func() {
		if !ok {
			r.Close()
		}
	}()
	f, e := a.lock()
	if e != nil {
		return nil, e
	}
	defer unlockAllocation(f)
	_, e = a.read()
	if errors.Is(e, os.ErrNotExist) {
		d, e := r.Open(".")
		if e != nil {
			return nil, e
		}
		entries, e := d.ReadDir(-1)
		d.Close()
		if e != nil || len(entries) != 1 || entries[0].Name() != "lock" {
			return nil, errors.New("orphan allocation directory")
		}
		e = a.save(allocationState{authority, 2000000001})
		if e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	ok = true
	return a, nil
}
func (a *Allocator) Allocate(run string) (uint32, error) {
	if !runPattern.MatchString(run) {
		return 0, errors.New("invalid allocation RunID")
	}
	f, e := a.lock()
	if e != nil {
		return 0, e
	}
	defer unlockAllocation(f)
	if _, e = a.root.Lstat(run); !errors.Is(e, os.ErrNotExist) {
		return 0, errors.New("run identity already allocated or unknown")
	}
	s, e := a.read()
	if e != nil {
		return 0, e
	}
	if s.Next > 2001000000 {
		return 0, errors.New("host UID range exhausted")
	}
	u := s.Next
	s.Next++
	if e = a.save(s); e != nil {
		return 0, e
	}
	// Counter is already durable: even failure creating this record burns u.
	record, e := checkedFile(a.root, run, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return 0, e
	}
	_, e = io.Copy(record, strings.NewReader(fmt.Sprintf("%s\n%d\n", a.authority, u)))
	e = errors.Join(e, record.Sync(), record.Close(), syncRoot(a.root))
	if e != nil {
		return 0, e
	}
	return u, nil
}
func (a *Allocator) Close() error { return a.root.Close() }
