package firecracker

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// A real child test process (never a VMM) catches returning before the original
// child was reaped and its pidfd closed. It is not cgroup quiescence evidence.
func TestOwnedProcessRetainsOriginalPIDFDThroughReap(t *testing.T) {
	if os.Getenv("WARDEN_PROCESS_TEST_CHILD") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	before, _ := os.ReadDir("/proc/self/fd")
	for i := 0; i < 4; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessRetainsOriginalPIDFDThroughReap$")
		cmd.Env = append(os.Environ(), "WARDEN_PROCESS_TEST_CHILD=1")
		p, e := startOwned(cmd)
		if e != nil {
			t.Fatal(e)
		}
		pid := cmd.Process.Pid
		if e = p.Stop(); e != nil {
			t.Fatal(e)
		}
		if e = p.Stop(); e != nil {
			t.Fatal("idempotent stop", e)
		}
		if _, e = os.Stat("/proc/" + strconv.Itoa(pid)); !os.IsNotExist(e) {
			t.Fatalf("original child still present: %v", e)
		}
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before)+1 {
		t.Fatalf("FD leak before=%d after=%d", len(before), len(after))
	}
}

func TestOwnedProcessStartFailureDoesNotLeakDescriptors(t *testing.T) {
	before, _ := os.ReadDir("/proc/self/fd")
	if _, e := startOwned(exec.Command("/definitely/absent/warden-process")); e == nil {
		t.Fatal("missing binary accepted")
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before) {
		t.Fatal("failed exec leaked fd")
	}
}
