package firecracker

import (
	"context"
	"os"
	"testing"
	"time"
	"warden/runtimes"
)

func TestFirecrackerCapacity(t *testing.T) {
	mode := os.Getenv("WARDEN_FC_MODE")
	if mode != "capacity-default" && mode != "capacity-benchmark" {
		t.Skip("NOT EXECUTED: requires separately reviewed post-conformance capacity mode")
	}
	d, g := reviewedLab(t, mode)
	maxVMs := 16
	benchmark := mode == "capacity-benchmark"
	if benchmark {
		maxVMs = 32
	}
	d.mu.Lock()
	d.limit = maxVMs
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	var handles []runtimes.Handle
	for i := 0; i < maxVMs; i++ {
		s := labSpec(t, d, "timeout")
		s.Limits.TimeoutS = 300
		if benchmark {
			d.mu.Lock()
			d.options[s.RunID] = startOptions{benchmark: true}
			d.mu.Unlock()
		}
		h, e := g.Start(ctx, s)
		if e != nil {
			t.Logf("bounded capacity observed=%d limit=%d stopped_on=%v", len(handles), maxVMs, e)
			t.Fatalf("capacity launch stopped; original gate may be ambiguous: %v", e)
		}
		handles = append(handles, h)
		for _, active := range handles {
			v := active.(*vm)
			if v.retired.Load() {
				t.Fatal("a prior VM exited before the simultaneous capacity observation")
			}
			raw, e := v.scope.root.ReadFile("cgroup.events")
			if e != nil {
				t.Fatal(e)
			}
			n, e := Counter(string(raw), "populated")
			if e != nil || n != 1 {
				t.Fatal("active capacity VM is not populated")
			}
		}
		raw, e := os.ReadFile("/sys/fs/cgroup/memory.events")
		if e != nil {
			t.Fatal(e)
		}
		pressure, e := Counter(string(raw), "max")
		if e != nil {
			t.Fatal(e)
		}
		oom, e := Counter(string(raw), "oom")
		if e != nil {
			t.Fatal(e)
		}
		current, e := os.ReadFile("/sys/fs/cgroup/memory.current")
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("actual active=%d outer_memory_current=%s outer_memory_events=%s", i+1, current, raw)
		if pressure > 0 || oom > 0 {
			t.Log("bounded pressure boundary observed; not a physical host maximum")
			break
		}
	}
	// All processes were admitted at once and remain accounted until explicit
	// retirement; no sleep-based fake startup or inferred host-capacity result.
	for _, h := range handles {
		if e := h.Kill(); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("simultaneously launched=%d reviewed upper bound=%d right_censored=%v outer=15000000000 host_allowance=1000000000", len(handles), maxVMs, len(handles) == maxVMs)
}
