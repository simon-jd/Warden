package gate_test

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"warden/runtimes"
	"warden/runtimes/gate"
)

type driver struct {
	starts, reaps    atomic.Int32
	entered, release chan struct{}
}

func (d *driver) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	d.starts.Add(1)
	if d.entered != nil {
		close(d.entered)
		<-d.release
	}
	return handle{}, nil
}
func (d *driver) Reap(context.Context, string) error { d.reaps.Add(1); return nil }

type handle struct{}

func (handle) Wait(context.Context) (runtimes.Exit, error) {
	return runtimes.Exit{CgroupEmpty: true}, nil
}
func (handle) Kill() error         { return nil }
func (handle) Logs() io.ReadCloser { return io.NopCloser(strings.NewReader("")) }

const id = "AAAAAAAAAAAAAAAAAAAAAAAAAA"

// Break caught: recovery completes but a delayed Start subsequently creates an orphan.
func TestReapPermanentlyRevokesDelayedStartAcrossInstances(t *testing.T) {
	dir := privateDir(t)
	d := &driver{}
	a, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Reap(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Start(context.Background(), runtimes.Spec{RunID: id}); !errors.Is(err, gate.ErrConsumed) {
		t.Fatalf("delayed launch: %v", err)
	}
	if d.starts.Load() != 0 || d.reaps.Load() != 1 {
		t.Fatal("revocation failed")
	}
}

// Break caught: Reap reports cleanup success while Start still owns the creation gate.
func TestInflightLaunchBlocksReapUntilBoundedTimeout(t *testing.T) {
	d := &driver{entered: make(chan struct{}), release: make(chan struct{})}
	g, err := gate.New(privateDir(t), "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := g.Start(context.Background(), runtimes.Spec{RunID: id}); done <- e }()
	<-d.entered
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err = g.Reap(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reap %v", err)
	}
	if d.reaps.Load() != 0 {
		t.Fatal("cleaned concurrently with creation")
	}
	close(d.release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = g.Reap(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Start(context.Background(), runtimes.Spec{RunID: id}); !errors.Is(err, gate.ErrConsumed) {
		t.Fatalf("second start %v", err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Break caught: replacing a node's gate directory silently reuses its recovery authority.
func TestDistinctGateDirectoriesHaveDistinctAuthority(t *testing.T) {
	a, err := gate.New(privateDir(t), "node-A", &driver{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := gate.New(privateDir(t), "node-A", &driver{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Authority() == b.Authority() {
		t.Fatal("different durable state directories share recovery authority")
	}
}

// Break caught: an existing gate follows a replaced directory and forgets tombstones.
func TestGateRefusesReplacedDirectory(t *testing.T) {
	dir := privateDir(t)
	d := &driver{}
	g, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Reap(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dir, dir+"-original"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir + "-original") })
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Start(context.Background(), runtimes.Spec{RunID: id}); err == nil {
		t.Fatal("replacement directory forgot consumed run")
	}
	if d.starts.Load() != 0 {
		t.Fatal("started after gate directory replaced")
	}
}

// Break caught: a client-side Start error is treated as server-side quiescence,
// allowing Reap's early not-found result to hide a delayed remote creation.
func TestAmbiguousCreationCannotBeClearedBySuccessfulReap(t *testing.T) {
	dir := privateDir(t)
	d := &ambiguousDriver{}
	a, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Start(context.Background(), runtimes.Spec{RunID: id}); err == nil {
		t.Fatal("expected ambiguous transport failure")
	}
	for range 2 {
		// A separate instance models a worker restart; neither retry nor restart may
		// forget that the server operation can commit after this Reap returns.
		b, err := gate.New(dir, "node-A", d)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Reap(context.Background(), id); !errors.Is(err, gate.ErrAmbiguous) {
			t.Fatalf("ambiguous operation reported clean: %v", err)
		}
		if _, err = b.Start(context.Background(), runtimes.Spec{RunID: id}); !errors.Is(err, gate.ErrConsumed) {
			t.Fatalf("ambiguous run relaunched: %v", err)
		}
	}
}

type ambiguousDriver struct{}

func (*ambiguousDriver) Start(context.Context, runtimes.Spec) (runtimes.Handle, error) {
	return nil, errors.New("RPC response lost; remote Create may still commit")
}
func (*ambiguousDriver) Reap(context.Context, string) error { return nil }

// Break caught: each scheduler poll/recovery leaks the gate directory descriptor.
func TestGateOperationsReleaseDirectoryDescriptors(t *testing.T) {
	g, err := gate.New(privateDir(t), "node-A", &driver{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		if err = g.Reap(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+2 {
		t.Fatalf("gate leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}
