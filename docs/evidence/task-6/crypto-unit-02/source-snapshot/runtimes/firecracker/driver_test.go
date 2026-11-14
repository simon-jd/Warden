package firecracker

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"warden/runtimes"
	"warden/runtimes/gate"
)

func TestDriverFailsClosedWithoutOwnedReviewedNode(t *testing.T) {
	if _, _, e := Open(); e == nil {
		t.Fatal("unconfigured code process became live backend")
	}
	d := new(Driver)
	if _, e := d.Start(context.Background(), spec()); e == nil {
		t.Fatal("unconfigured driver launched")
	}
	if e := d.Reap(context.Background(), spec().RunID); e == nil {
		t.Fatal("absent original owner claimed cleanup")
	}
}

// Deliberate durable-marker fault fixture: an already locally retired handle
// cannot erase the gate's lost-launch ambiguity or issue node retirement.
func TestLocalRetirementCannotSwallowAmbiguousGate(t *testing.T) {
	dir := private(t)
	if e := os.Mkdir(filepath.Join(dir, "gate"), 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	d := &Driver{root: root, handles: map[string]*vm{}}
	g, e := gate.NewBound(filepath.Join(dir, "gate"), "fc-test", d, [32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	d.gate = g
	h := &vm{driver: d, profile: Profile{Spec: spec()}, startDone: make(chan struct{}), done: make(chan struct{})}
	h.retired.Store(true)
	close(h.startDone)
	close(h.done)
	d.handles[spec().RunID] = h
	if e = os.WriteFile(filepath.Join(dir, "gate", spec().RunID), []byte("launching\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = d.Close(); !errors.Is(e, gate.ErrAmbiguous) {
		t.Fatalf("lost ambiguity: %v", e)
	}
	if _, e = os.Stat(filepath.Join(dir, "retired")); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("ambiguous node issued retirement: %v", e)
	}
}
func TestUnknownOriginalOwnerRemainsCleanupPending(t *testing.T) {
	dir := private(t)
	for _, name := range []string{"gate", "runs"} {
		if e := os.Mkdir(filepath.Join(dir, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	d := &Driver{root: root, handles: map[string]*vm{}}
	g, e := gate.NewBound(filepath.Join(dir, "gate"), "fc-test", d, [32]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	d.gate = g
	if e = os.WriteFile(filepath.Join(dir, "runs", spec().RunID), []byte("original owner lost"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = d.Reap(context.Background(), spec().RunID); !errors.Is(e, ErrCleanupPending) {
		t.Fatalf("unknown owner released: %v", e)
	}
}

// These fixtures use real private files, allocator and Gate; no VM/cgroup
// operation is performed. The cgroup/input roots are only Close-owned FDs.
func retirementFixture(t *testing.T) (*Driver, string) {
	t.Helper()
	dir := private(t)
	for _, name := range []string{"gate", "runs", "uids", "cgroups", "input"} {
		if e := os.Mkdir(filepath.Join(dir, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	return reopenRetirementFixture(t, dir), dir
}
func reopenRetirementFixture(t *testing.T, dir string) *Driver {
	t.Helper()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	d := &Driver{root: root, handles: map[string]*vm{}, options: map[string]startOptions{}, manifest: Manifest{ImageDigest: spec().ImageDigest}, limit: 1}
	d.gate, e = gate.NewBound(filepath.Join(dir, "gate"), "fc-test", d, [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	d.allocator, e = OpenAllocator(filepath.Join(dir, "uids"), d.gate.Authority())
	if e != nil {
		t.Fatal(e)
	}
	d.cgroups, e = os.OpenRoot(filepath.Join(dir, "cgroups"))
	if e != nil {
		t.Fatal(e)
	}
	d.input, e = os.OpenRoot(filepath.Join(dir, "input"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.root.Close(); d.allocator.Close(); d.cgroups.Close(); d.input.Close() })
	return d
}
func assertNoRetirement(t *testing.T, dir string) {
	t.Helper()
	if _, e := os.Stat(filepath.Join(dir, "retired")); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("pending node published retirement: %v", e)
	}
}
func TestCloseAccountsForGatedFailureWithoutHandle(t *testing.T) {
	for _, kind := range []string{"invalid-profile", "image-mismatch", "reservation-full", "record-collision", "allocator-state"} {
		t.Run(kind, func(t *testing.T) {
			d, dir := retirementFixture(t)
			s := spec()
			switch kind {
			case "invalid-profile":
				s.Cmd = []string{"/not-supported"}
			case "image-mismatch":
				d.manifest.ImageDigest = "sha256:" + strings.Repeat("f", 64)
			case "reservation-full":
				d.limit = 0
			case "record-collision":
				if e := os.WriteFile(filepath.Join(dir, "runs", s.RunID), []byte("orphan"), 0600); e != nil {
					t.Fatal(e)
				}
			case "allocator-state":
				if e := os.WriteFile(filepath.Join(dir, "uids/state"), []byte("corrupt"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := d.gate.Start(context.Background(), s); e == nil {
				t.Fatal("expected real failed gated start")
			}
			if len(d.handles) != 0 {
				t.Fatal("test did not reach no-handle failure")
			}
			if e := d.Close(); !errors.Is(e, gate.ErrAmbiguous) {
				t.Errorf("lost gate ambiguity: %v", e)
			}
			assertNoRetirement(t, dir)
		})
	}
}
func TestClosePreservesPendingFilesAfterReopen(t *testing.T) {
	for _, kind := range []string{"launching", "orphan-run"} {
		t.Run(kind, func(t *testing.T) {
			old, dir := retirementFixture(t)
			s := spec()
			if kind == "launching" {
				s.Cmd = nil
				if _, e := old.gate.Start(context.Background(), s); e == nil {
					t.Fatal("expected rejected start")
				}
			} else if e := os.WriteFile(filepath.Join(dir, "runs", s.RunID), []byte("original owner unavailable"), 0600); e != nil {
				t.Fatal(e)
			}
			old.root.Close()
			old.allocator.Close()
			old.cgroups.Close()
			old.input.Close()
			d := reopenRetirementFixture(t, dir)
			e := d.Close()
			if kind == "launching" && !errors.Is(e, gate.ErrAmbiguous) {
				t.Errorf("reopen lost ambiguity: %v", e)
			}
			if kind == "orphan-run" && !errors.Is(e, ErrCleanupPending) {
				t.Errorf("orphan run released: %v", e)
			}
			assertNoRetirement(t, dir)
		})
	}
}

func TestCloseSealsLateGateAndDirectStarts(t *testing.T) {
	d, dir := retirementFixture(t)
	second, e := gate.NewBound(filepath.Join(dir, "gate"), "fc-test", d, [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	if raw, e := os.ReadFile(filepath.Join(dir, "retired")); e != nil || string(raw) != "known-owner-retired\n" {
		t.Fatalf("empty node failed retirement: %q %v", raw, e)
	}
	reopened, e := gate.NewBound(filepath.Join(dir, "gate"), "fc-test", d, [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	for _, g := range []*gate.Gate{d.gate, second, reopened} {
		if _, e = g.Start(context.Background(), spec()); !errors.Is(e, gate.ErrRetired) {
			t.Fatalf("late gated launch: %v", e)
		}
	}
	if _, e = d.Start(context.Background(), spec()); !errors.Is(e, gate.ErrRetired) {
		t.Fatalf("late direct launch: %v", e)
	}
	if _, e = os.Stat(filepath.Join(dir, "gate", spec().RunID)); !os.IsNotExist(e) {
		t.Fatal("late gate created durable marker")
	}
}
func TestCloseCoordinatesInflightGateAdmission(t *testing.T) {
	d, dir := retirementFixture(t)
	s := spec()
	s.Cmd = nil // callback must reject before any VM path
	run, e := os.OpenFile(filepath.Join(dir, "gate", s.RunID), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer run.Close()
	if e = unix.Flock(int(run.Fd()), unix.LOCK_EX); e != nil {
		t.Fatal(e)
	}
	defer unix.Flock(int(run.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan error, 1)
	go func() { _, e := d.gate.Start(ctx, s); started <- e }()
	// The real Gate holds admission while waiting for our original run flock.
	deadline := time.Now().Add(time.Second)
	for {
		admission, e := os.OpenFile(filepath.Join(dir, "gate/admission"), os.O_RDWR, 0600)
		if e == nil {
			e = unix.Flock(int(admission.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if e == nil {
				unix.Flock(int(admission.Fd()), unix.LOCK_UN)
			}
			admission.Close()
			if errors.Is(e, unix.EWOULDBLOCK) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Gate never acquired admission")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case e := <-closed:
		t.Fatalf("Close passed in-flight admission: %v", e)
	case <-time.After(20 * time.Millisecond):
	}
	assertNoRetirement(t, dir)
	unix.Flock(int(run.Fd()), unix.LOCK_UN)
	select {
	case e := <-started:
		if e == nil {
			t.Fatal("rejected start succeeded")
		}
	case <-ctx.Done():
		t.Fatal("in-flight Start deadlocked")
	}
	select {
	case e := <-closed:
		if !errors.Is(e, gate.ErrAmbiguous) {
			t.Fatalf("Close lost in-flight ambiguity: %v", e)
		}
	case <-ctx.Done():
		t.Fatal("Close deadlocked")
	}
	assertNoRetirement(t, dir)
}
func TestCloseRejectsUnknownOrUnsafeJournals(t *testing.T) {
	for _, kind := range []string{"extra-gate", "extra-runs", "extra-uids", "corrupt-allocator", "unsafe-run", "lost-owner-started", "missing-runs", "corrupt-gate-node"} {
		t.Run(kind, func(t *testing.T) {
			d, dir := retirementFixture(t)
			var e error
			switch kind {
			case "missing-runs":
				e = os.Remove(filepath.Join(dir, "runs"))
			case "corrupt-gate-node":
				e = os.WriteFile(filepath.Join(dir, "gate/node"), []byte(d.gate.Authority()+"\nbackend-v1:not-a-hash"), 0600)
			case "extra-gate":
				e = os.WriteFile(filepath.Join(dir, "gate/unexpected"), nil, 0600)
			case "extra-runs":
				e = os.WriteFile(filepath.Join(dir, "runs/unexpected"), nil, 0600)
			case "extra-uids":
				e = os.WriteFile(filepath.Join(dir, "uids/unexpected"), nil, 0600)
			case "corrupt-allocator":
				e = os.WriteFile(filepath.Join(dir, "uids/state"), []byte("bad"), 0600)
			case "unsafe-run":
				e = os.Symlink("../owner", filepath.Join(dir, "runs", spec().RunID))
			case "lost-owner-started":
				e = os.WriteFile(filepath.Join(dir, "gate", spec().RunID), []byte("started\n"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = d.Close(); !errors.Is(e, ErrCleanupPending) {
				t.Fatalf("unknown state released: %v", e)
			}
			assertNoRetirement(t, dir)
		})
	}
}

// This barrier only schedules the actual Driver callback. It supplies no
// successful handle, cleanup result, cgroup observation or retirement witness.
type pausedGateCallback struct {
	*Driver
	entered, release chan struct{}
}

func (p *pausedGateCallback) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	close(p.entered)
	select {
	case <-p.release:
		return p.Driver.Start(ctx, s)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestCloseWaitsForAlreadyAdmittedCallback(t *testing.T) {
	d, dir := retirementFixture(t)
	paused := &pausedGateCallback{Driver: d, entered: make(chan struct{}), release: make(chan struct{})}
	g, e := gate.NewBound(filepath.Join(dir, "gate"), "fc-test", paused, [32]byte{3})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan error, 1)
	go func() { _, e := g.Start(ctx, spec()); started <- e }()
	select {
	case <-paused.entered:
	case <-ctx.Done():
		t.Fatal("callback did not enter")
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case e := <-closed:
		t.Fatalf("Close passed admitted callback: %v", e)
	case <-time.After(20 * time.Millisecond):
	}
	assertNoRetirement(t, dir)
	close(paused.release)
	select {
	case e := <-started:
		if e == nil {
			t.Fatal("shutdown admitted actual driver")
		}
	case <-ctx.Done():
		t.Fatal("callback deadlocked")
	}
	select {
	case e := <-closed:
		if !errors.Is(e, gate.ErrAmbiguous) {
			t.Fatalf("callback ambiguity lost: %v", e)
		}
	case <-ctx.Done():
		t.Fatal("Close deadlocked")
	}
	assertNoRetirement(t, dir)
}
