// Package gate permanently consumes launch identities and serializes Start/Reap.
// Its private directory is durable runtime-node state, never temporary storage.
package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"warden/runtimes"
)

var ErrConsumed = errors.New("run launch identity consumed")
var idPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)
var nodePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Driver interface {
	runtimes.Runtime
	Reap(context.Context, string) error
}
type Gate struct {
	driver        Driver
	dir           string
	node          string
	authority     string
	device, inode uint64
}

func New(dir, node string, d Driver) (*Gate, error) {
	return newGate(dir, node, d, nil)
}

// NewBound creates a gate whose authority is permanently bound to one backend
// identity. The digest must be derived from trusted operator configuration and
// observed backend identifiers, never tenant input. It is not attestation or
// proof of quiescence. Drivers must also verify the live backend on operations.
// A bound gate requires fresh state; legacy gate records cannot be migrated.
func NewBound(dir, node string, d Driver, identity [32]byte) (*Gate, error) {
	if identity == ([32]byte{}) {
		return nil, errors.New("nonzero backend identity required")
	}
	return newGate(dir, node, d, &identity)
}

func newGate(dir, node string, d Driver, identity *[32]byte) (*Gate, error) {
	if !filepath.IsAbs(dir) || !nodePattern.MatchString(node) || d == nil {
		return nil, errors.New("trusted gate directory, node and driver required")
	}
	// Reject directory redirection and shared writable state. Ancestors must also
	// be operator controlled; the deployment owns this path for the node lifetime.
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("gate directory must be private mode 0700")
	}
	var stat unix.Stat_t
	if err = unix.Lstat(dir, &stat); err != nil {
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("gate directory owner mismatch")
	}
	g := &Gate{driver: d, dir: dir, node: node, device: stat.Dev, inode: stat.Ino}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := g.lock(ctx, "node")
	if err != nil {
		return nil, err
	}
	defer unlock(f)
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		if identity != nil {
			// The node lock serializes fresh initialization. Missing authority
			// beside any prior state is an orphan, not permission to adopt it.
			entries, readErr := f.directory.ReadDir(-1)
			if readErr != nil || len(entries) != 1 || entries[0].Name() != "node" {
				return nil, errors.New("bound gate requires fresh private state")
			}
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		content = []byte(node + "/" + hex.EncodeToString(nonce[:]))
		if identity != nil {
			content = append(content, []byte("\nbackend-v1:"+hex.EncodeToString(identity[:]))...)
		}
		if err = g.mark(f, string(content)); err != nil {
			return nil, err
		}
	}
	authority, binding, bound := strings.Cut(string(content), "\n")
	if identity == nil && bound {
		return nil, errors.New("backend-bound gate requires its original identity")
	}
	if identity != nil && (!bound || binding != "backend-v1:"+hex.EncodeToString(identity[:])) {
		return nil, errors.New("gate backend identity mismatch or legacy state")
	}
	parts := strings.Split(authority, "/")
	if len(parts) != 2 || parts[0] != node || len(parts[1]) != 32 {
		return nil, errors.New("gate directory node identity mismatch")
	}
	if _, err = hex.DecodeString(parts[1]); err != nil {
		return nil, errors.New("invalid gate identity")
	}
	g.authority = authority
	return g, nil
}
func (g *Gate) Node() string { return g.node }

type lockedFile struct {
	*os.File
	directory *os.File
}

func (g *Gate) lock(ctx context.Context, name string) (*lockedFile, error) {
	dirfd, err := unix.Open(g.dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(dirfd), g.dir)
	success := false
	defer func() {
		if !success {
			_ = directory.Close()
		}
	}()
	var directoryStat unix.Stat_t
	if err = unix.Fstat(dirfd, &directoryStat); err != nil {
		return nil, err
	}
	if directoryStat.Dev != g.device || directoryStat.Ino != g.inode || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&0777 != 0700 {
		return nil, errors.New("runtime gate directory changed")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		f.Close()
		return nil, errors.New("unsafe gate file")
	}
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			success = true
			return &lockedFile{File: f, directory: directory}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func unlock(f *lockedFile) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
	_ = f.directory.Close()
}
func (g *Gate) mark(f *lockedFile, value string) error {
	if _, err := f.WriteAt([]byte(value), 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(value))); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.directory.Sync()
}
func (g *Gate) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	if !idPattern.MatchString(s.RunID) {
		return nil, errors.New("invalid run ID")
	}
	admission, err := g.lock(ctx, "admission")
	if err != nil {
		return nil, err
	}
	defer func() {
		if admission != nil {
			unlock(admission)
		}
	}()
	sealed, err := g.admissionSealed(admission.directory)
	if err != nil {
		return nil, err
	}
	if sealed {
		return nil, ErrRetired
	}
	retired, err := g.lock(ctx, "retirement")
	if err != nil {
		return nil, err
	}
	state, err := retired.Stat()
	unlock(retired)
	if err != nil {
		return nil, err
	}
	if state.Size() != 0 {
		return nil, ErrRetired
	}
	f, err := g.lock(ctx, s.RunID)
	if err != nil {
		return nil, err
	}
	defer unlock(f)
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() != 0 {
		return nil, ErrConsumed
	}
	// Persist before any external action. Even ambiguous or failed Start consumes
	// this ID permanently. Reap shares this lock through complete creation.
	if err = g.mark(f, "launching\n"); err != nil {
		return nil, err
	}
	unlock(admission)
	admission = nil
	h, startErr := g.driver.Start(ctx, s)
	if startErr != nil {
		return h, startErr
	}
	// Only an acknowledged creation can be considered quiescent after ordinary
	// Reap. A crash/error before this durable acknowledgement remains uncertain.
	if err = g.mark(f, "started\n"); err != nil {
		return h, err
	}
	return h, nil
}
func (g *Gate) Reap(ctx context.Context, id string) error {
	if !idPattern.MatchString(id) {
		return errors.New("invalid run ID")
	}
	f, err := g.lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock(f)
	marker, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	ambiguous := len(marker) > 0 && string(marker) != "started\n" && string(marker) != "revoked\n"
	next := "revoked\n"
	if ambiguous {
		next = "revoked-uncertain\n"
	}
	if err = g.mark(f, next); err != nil {
		return err
	}
	cleanupErr := g.driver.Reap(ctx, id)
	if ambiguous {
		return errors.Join(ErrAmbiguous, cleanupErr)
	}
	return cleanupErr
}

func (g *Gate) Authority() string { return g.authority }

// ErrAmbiguous means a creation RPC may still finish on the original daemon.
var ErrAmbiguous = errors.New("creation outcome unknown; runtime quiescence required")

// ErrRetired refuses new launches, including a deny-only admission seal. It is
// not evidence of kernel quiescence, original-owner retirement or reconciliation.
var ErrRetired = errors.New("runtime node permanently closed to new launches")
