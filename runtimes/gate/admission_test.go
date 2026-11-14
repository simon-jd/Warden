package gate_test

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
	"warden/runtimes"
	"warden/runtimes/gate"
)

func sealGate(g *gate.Gate) error {
	s, ok := any(g).(interface{ SealAdmission(context.Context) error })
	if !ok {
		return errors.New("durable admission seal unavailable")
	}
	return s.SealAdmission(context.Background())
}
func TestSealAdmissionAcrossInstancesAndReopenWithoutProof(t *testing.T) {
	dir := privateDir(t)
	d := &driver{}
	binding := [32]byte{9}
	a, e := gate.NewBound(dir, "node-A", d, binding)
	if e != nil {
		t.Fatal(e)
	}
	b, e := gate.NewBound(dir, "node-A", d, binding)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, id), []byte("launching\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = sealGate(a); e != nil {
		t.Fatal(e)
	}
	if e = sealGate(b); e != nil {
		t.Fatal(e)
	}
	c, e := gate.NewBound(dir, "node-A", d, binding)
	if e != nil {
		t.Fatal(e)
	}
	for _, g := range []*gate.Gate{a, b, c} {
		if _, e = g.Start(context.Background(), runtimes.Spec{RunID: "BBBBBBBBBBBBBBBBBBBBBBBBBB"}); !errors.Is(e, gate.ErrRetired) {
			t.Fatalf("sealed node admitted late start: %v", e)
		}
		if e = g.Reap(context.Background(), id); !errors.Is(e, gate.ErrAmbiguous) {
			t.Fatalf("seal erased ambiguity: %v", e)
		}
		if proof, e := g.Reconciliation(context.Background(), id); e == nil || proof != nil {
			t.Fatal("admission seal manufactured proof")
		}
	}
	if d.starts.Load() != 0 {
		t.Fatal("driver invoked after seal")
	}
	if _, e = os.Stat(filepath.Join(dir, "BBBBBBBBBBBBBBBBBBBBBBBBBB")); !os.IsNotExist(e) {
		t.Fatal("late start created run marker")
	}
	if _, e = os.Stat(filepath.Join(dir, "retirement-binding")); !os.IsNotExist(e) {
		t.Fatal("seal fabricated binding")
	}
	if raw, e := os.ReadFile(filepath.Join(dir, "retirement")); e != nil || len(raw) != 0 {
		t.Fatalf("retirement proof modified: %q %v", raw, e)
	}
}
func TestSealAdmissionRejectsMalformedOrUnsafeState(t *testing.T) {
	for _, kind := range []string{"empty", "corrupt", "other-authority", "mode", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDir(t)
			d := &driver{}
			g, e := gate.NewBound(dir, "node-A", d, [32]byte{8})
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(dir, "admission-sealed")
			raw := []byte("bad")
			switch kind {
			case "empty":
				raw = nil
			case "other-authority":
				raw = []byte("admission-sealed-v1\nnode-A/00000000000000000000000000000000\n")
			}
			if kind == "symlink" {
				e = os.Symlink("node", p)
			} else {
				e = os.WriteFile(p, raw, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if kind == "mode" {
				if e = os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "hardlink" {
				if e = os.Link(p, filepath.Join(dir, "alias")); e != nil {
					t.Fatal(e)
				}
			}
			if e = sealGate(g); e == nil {
				t.Fatal("unsafe seal accepted")
			}
			if _, e = g.Start(context.Background(), runtimes.Spec{RunID: id}); e == nil {
				t.Fatal("unsafe seal bypassed")
			}
			if d.starts.Load() != 0 {
				t.Fatal("unsafe state invoked driver")
			}
		})
	}
}

func TestSealAdmissionWaitIsBoundedByContext(t *testing.T) {
	dir := privateDir(t)
	g, e := gate.NewBound(dir, "node-A", &driver{}, [32]byte{7})
	if e != nil {
		t.Fatal(e)
	}
	admission, e := os.OpenFile(filepath.Join(dir, "admission"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer admission.Close()
	if e = unix.Flock(int(admission.Fd()), unix.LOCK_EX); e != nil {
		t.Fatal(e)
	}
	defer unix.Flock(int(admission.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e = g.SealAdmission(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("unbounded/ignored admission wait: %v", e)
	}
	if _, e = os.Stat(filepath.Join(dir, "admission-sealed")); !os.IsNotExist(e) {
		t.Fatal("timed-out seal published state")
	}
}
