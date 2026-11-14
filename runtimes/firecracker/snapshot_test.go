package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotBindsAllImmutableInputsAndShape(t *testing.T) {
	k := SnapshotKey{Kernel: strings.Repeat("1", 64), Agent: strings.Repeat("2", 64), RootFS: strings.Repeat("3", 64), Payload: strings.Repeat("4", 64), Firecracker: strings.Repeat("5", 64), Policy: strings.Repeat("6", 64), MemoryMiB: 640, VCPUs: 1}
	want, e := k.Digest()
	if e != nil || len(want) != 64 {
		t.Fatalf("key %q %v", want, e)
	}
	for _, change := range []func(*SnapshotKey){func(k *SnapshotKey) { k.Kernel = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.Agent = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.RootFS = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.Payload = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.Firecracker = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.Policy = strings.Repeat("7", 64) }, func(k *SnapshotKey) { k.MemoryMiB = 128 }} {
		n := k
		change(&n)
		got, e := n.Digest()
		if e != nil || got == want {
			t.Fatalf("snapshot compatible despite change %+v", n)
		}
	}
	k.Agent = ""
	if _, e := k.Digest(); e == nil {
		t.Fatal("unbound snapshot allowed")
	}
}

// Catches synthetic/missing samples and wrong median comparisons. These are
// arithmetic unit fixtures only, never real VM startup measurements.
func TestMeasuredMedianComparison(t *testing.T) {
	cold, restored := make([]time.Duration, 20), make([]time.Duration, 20)
	for i := 0; i < 20; i++ {
		cold[i] = time.Duration(i+1) * time.Millisecond
		restored[i] = time.Duration(i+1) * time.Microsecond
	}
	m, e := CompareStarts(cold, restored)
	if e != nil {
		t.Fatal(e)
	}
	if m.ColdP50 != 10500*time.Microsecond || m.ColdP95 != 19*time.Millisecond || m.RestoreP50 != 10500*time.Nanosecond || m.RestoreP95 != 19*time.Microsecond {
		t.Fatalf("wrong observed quantiles %+v", m)
	}
	if _, e := CompareStarts(cold, cold); e == nil {
		t.Fatal("equal median passed")
	}
	if _, e := CompareStarts(cold[:19], restored[:19]); e == nil {
		t.Fatal("too few observations")
	}
	restored[0] = 0
	if _, e := CompareStarts(cold, restored); e == nil {
		t.Fatal("zero duration accepted")
	}
}

func TestSnapshotCacheRejectsTamperingAndWritableAliases(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	key := strings.Repeat("a", 64)
	for _, name := range []string{"memory", "state"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(name), 0400); e != nil {
			t.Fatal(e)
		}
	}
	record := snapshotRecord{Key: key, MemorySHA: digestBytes([]byte("memory")), StateSHA: digestBytes([]byte("state")), MemoryBytes: 6, StateBytes: 5}
	if e := validateSnapshot(root, record, key, 640); e != nil {
		t.Fatal(e)
	}
	if e := validateSnapshot(root, record, strings.Repeat("b", 64), 640); e == nil {
		t.Fatal("cross-profile snapshot accepted")
	}
	if e := os.Chmod(filepath.Join(dir, "memory"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := validateSnapshot(root, record, key, 640); e == nil {
		t.Fatal("writable baseline accepted")
	}
	if e := os.WriteFile(filepath.Join(dir, "memory"), []byte("tamper"), 0400); e != nil {
		t.Fatal(e)
	}
	os.Chmod(filepath.Join(dir, "memory"), 0400)
	if e := validateSnapshot(root, record, key, 640); e == nil {
		t.Fatal("changed baseline accepted")
	}
}
