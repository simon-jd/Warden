package firecracker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const authority = "fc-node/0123456789abcdef0123456789abcdef"

func private(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

// Catches identity reuse following reopen, duplicate RunID, or changed authority.
func TestUIDsSurviveProcessReopen(t *testing.T) {
	if os.Getenv("WARDEN_UID_TEST_CHILD") == "1" {
		a, e := OpenAllocator(os.Getenv("WARDEN_UID_TEST_DIR"), authority)
		if e != nil {
			t.Fatal(e)
		}
		defer a.Close()
		u, e := a.Allocate(strings.Repeat("B", 26))
		if e != nil || u != 2000000002 {
			t.Fatalf("reopened uid=%d err=%v", u, e)
		}
		return
	}
	p := private(t)
	a, e := OpenAllocator(p, authority)
	if e != nil {
		t.Fatal(e)
	}
	u, e := a.Allocate(strings.Repeat("A", 26))
	if e != nil || u != 2000000001 {
		t.Fatalf("first uid=%d err=%v", u, e)
	}
	if _, e = a.Allocate(strings.Repeat("A", 26)); e == nil {
		t.Fatal("duplicate run allocated")
	}
	a.Close()
	c := exec.Command(os.Args[0], "-test.run=^TestUIDsSurviveProcessReopen$")
	c.Env = append(os.Environ(), "WARDEN_UID_TEST_CHILD=1", "WARDEN_UID_TEST_DIR="+p)
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("child %v %s", e, b)
	}
	if a, e = OpenAllocator(p, "fc-node/11111111111111111111111111111111"); e == nil {
		a.Close()
		t.Fatal("authority rebound")
	}
	a, e = OpenAllocator(p, authority)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	u, e = a.Allocate(strings.Repeat("C", 26))
	if e != nil || u != 2000000003 {
		t.Fatalf("post reopen uid=%d err=%v", u, e)
	}
}

// Catches lost/corrupt allocation state being interpreted as a fresh authority.
func TestUIDAllocatorRejectsOrphansAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"orphan", "symlink", "hardlink", "corrupt", "mode"} {
		t.Run(kind, func(t *testing.T) {
			p := private(t)
			if kind == "orphan" {
				os.WriteFile(filepath.Join(p, "leftover"), []byte("x"), 0600)
			} else {
				a, e := OpenAllocator(p, authority)
				if e != nil {
					t.Fatal(e)
				}
				a.Close()
				switch kind {
				case "symlink":
					os.Remove(filepath.Join(p, "state"))
					os.Symlink("/etc/passwd", filepath.Join(p, "state"))
				case "hardlink":
					os.Link(filepath.Join(p, "state"), filepath.Join(p, "alias"))
				case "corrupt":
					os.WriteFile(filepath.Join(p, "state"), []byte("truncated"), 0600)
				case "mode":
					os.Chmod(filepath.Join(p, "state"), 0666)
				}
			}
			if a, e := OpenAllocator(p, authority); e == nil {
				a.Close()
				t.Fatalf("accepted %s", kind)
			}
		})
	}
}

// Catches cross-process read/increment races assigning the same host identity.
func TestConcurrentUIDAllocation(t *testing.T) {
	p := private(t)
	a, e := OpenAllocator(p, authority)
	if e != nil {
		t.Fatal(e)
	}
	a.Close()
	type result struct {
		u uint32
		e error
	}
	ch := make(chan result, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			a, e := OpenAllocator(p, authority)
			if e != nil {
				ch <- result{e: e}
				return
			}
			defer a.Close()
			u, e := a.Allocate(strings.Repeat(string(rune('A'+i)), 26))
			ch <- result{u, e}
		}(i)
	}
	seen := map[uint32]bool{}
	for i := 0; i < 20; i++ {
		r := <-ch
		if r.e != nil || r.u < 2000000001 || r.u > 2000000020 || seen[r.u] {
			t.Fatal(fmt.Sprintf("bad allocation %+v", r))
		}
		seen[r.u] = true
	}
}
