package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"warden/runtimes"
)

func TestFirecrackerCapacity(t *testing.T) {
	mode := os.Getenv("WARDEN_FC_MODE")
	if mode != "capacity-default" && mode != "capacity-benchmark" && mode != "capacity-pressure" {
		t.Skip("live KVM test: needs WARDEN_FC_MODE=capacity-default|capacity-benchmark|capacity-pressure inside the Firecracker lab node")
	}
	d, g := reviewedLab(t, mode)
	// Idle guests (timeout probe) stay far below the 15 GB outer within the
	// 16/32 caps. The pressure mode runs 128 MiB VMs whose payload holds
	// 48 MiB (fill probe), and stops at the first outer memory.events max/oom.
	maxVMs, probe, budget := 16, "timeout", 240*time.Second
	benchmark := mode != "capacity-default"
	switch mode {
	case "capacity-benchmark":
		maxVMs = 32
	case "capacity-pressure":
		maxVMs, probe, budget = 160, "fill", 540*time.Second
	}
	d.mu.Lock()
	d.limit = maxVMs
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var handles []runtimes.Handle
	pressureAt := 0
	for i := 0; i < maxVMs; i++ {
		s := labSpec(t, d, probe)
		s.Limits.TimeoutS = 300
		if benchmark {
			d.mu.Lock()
			d.options[s.RunID] = startOptions{benchmark: true}
			d.mu.Unlock()
		}
		h, e := g.Start(ctx, s)
		if e != nil {
			t.Logf("bounded capacity observed=%d limit=%d stopped_on=%v", len(handles), maxVMs, e)
			if o, e := readOuter("/sys/fs/cgroup"); e != nil {
				t.Logf("at the stop: outer reading failed: %v", e)
			} else {
				t.Logf("at the stop: %s", o)
			}
			t.Fatalf("capacity launch stopped; original gate may be ambiguous: %v", e)
		}
		handles = append(handles, h)
		if probe == "fill" {
			waitReady(t, ctx, h, "READY fill\n")
		}
		o, e := readOuter("/sys/fs/cgroup")
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("actual active=%d %s", i+1, o)
		if o.pressure > 0 || o.oom > 0 {
			pressureAt = i + 1
			alive := 0
			for _, active := range handles {
				if !active.(*vm).retired.Load() {
					alive++
				}
			}
			t.Logf("bounded pressure boundary observed at active=%d (still running %d); not a physical host maximum", pressureAt, alive)
			break
		}
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
	}
	// All processes were admitted at once and remain accounted until explicit
	// retirement; no sleep-based fake startup or inferred host-capacity result.
	for _, h := range handles {
		if e := h.Kill(); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("simultaneously launched=%d reviewed upper bound=%d right_censored=%v pressure_at=%d probe=%s outer=15000000000 host_allowance=1000000000", len(handles), maxVMs, pressureAt == 0 && len(handles) == maxVMs, pressureAt, probe)
}

// outerReading is one look at the outer's own cgroup files (the private
// namespace root): memory, whose events stop the capacity run, and the pids
// beside it. pids.events also counts a limit hit below the outer, such as a
// VM scope's 64; pids.events.local, where the kernel has it, counts only the
// outer's own.
type outerReading struct {
	memoryCurrent, memoryEvents                                 string
	pidsCurrent, pidsPeak, pidsMax, pidsEvents, pidsEventsLocal string
	pressure, oom, pidsMaxEvents                                uint64
}

func readOuter(dir string) (outerReading, error) {
	var r outerReading
	read := func(name string) (string, error) {
		raw, e := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(raw)), e
	}
	var e error
	for _, f := range []struct {
		name string
		to   *string
	}{{"memory.current", &r.memoryCurrent}, {"memory.events", &r.memoryEvents}, {"pids.current", &r.pidsCurrent}, {"pids.max", &r.pidsMax}, {"pids.events", &r.pidsEvents}} {
		if *f.to, e = read(f.name); e != nil {
			return r, e
		}
	}
	if r.pressure, e = Counter(r.memoryEvents, "max"); e != nil {
		return r, e
	}
	if r.oom, e = Counter(r.memoryEvents, "oom"); e != nil {
		return r, e
	}
	if r.pidsMaxEvents, e = Counter(r.pidsEvents, "max"); e != nil {
		return r, e
	}
	for _, f := range []struct {
		name string
		to   *string
	}{{"pids.peak", &r.pidsPeak}, {"pids.events.local", &r.pidsEventsLocal}} {
		if *f.to, e = read(f.name); e != nil && !errors.Is(e, fs.ErrNotExist) {
			return r, e
		}
	}
	return r, nil
}

func (r outerReading) String() string {
	return fmt.Sprintf("outer_memory_current=%s outer_pids_current=%s outer_pids_peak=%s outer_pids_max=%s outer_pids_events=%q outer_pids_events_local=%q outer_memory_events=%s",
		r.memoryCurrent, r.pidsCurrent, r.pidsPeak, r.pidsMax, r.pidsEvents, r.pidsEventsLocal, r.memoryEvents)
}

// waitReady polls the trusted framed tenant log until the fixed probe line.
func waitReady(t *testing.T, ctx context.Context, h runtimes.Handle, line string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		logs := h.Logs()
		raw, e := io.ReadAll(logs)
		logs.Close()
		if e == nil && bytes.Contains(raw, []byte(line)) {
			return
		}
		if ctx.Err() != nil || time.Now().After(deadline) || h.(*vm).retired.Load() {
			t.Fatalf("probe did not report %q: logs=%q err=%v", line, raw, e)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The capacity log says why a launch stopped: the outer's pids.max and
// pids.events sit next to its memory files in every reading. On 2026-11-10
// the log had pids.current only, so the 101st VM's timeout could not be tied
// to the pid limit. pids.events.local is read when the kernel has it.
func TestOuterReadingIncludesPids(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	write("memory.current", "12703633408\n")
	write("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n")
	write("pids.current", "508\n")
	write("pids.max", "512\n")
	write("pids.events", "max 3\n")
	r, e := readOuter(dir)
	if e != nil {
		t.Fatal(e)
	}
	if r.pressure != 0 || r.oom != 0 || r.pidsMaxEvents != 3 || r.pidsEventsLocal != "" || r.pidsPeak != "" {
		t.Fatalf("reading %+v", r)
	}
	for _, want := range []string{"outer_memory_current=12703633408", "outer_pids_current=508", "outer_pids_max=512", `outer_pids_events="max 3"`, `outer_pids_events_local=""`, "outer_memory_events=low 0"} {
		if !strings.Contains(r.String(), want) {
			t.Errorf("reading %q lacks %q", r.String(), want)
		}
	}
	write("pids.events.local", "max 2\n")
	write("pids.peak", "512\n")
	write("memory.events", "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n")
	if r, e = readOuter(dir); e != nil || r.pidsEventsLocal != "max 2" || r.pidsPeak != "512" || r.pressure != 1 ||
		!strings.Contains(r.String(), `outer_pids_events_local="max 2"`) || !strings.Contains(r.String(), "outer_pids_peak=512") {
		t.Fatalf("reading with pids.events.local: %+v %v", r, e)
	}
	for _, name := range []string{"pids.events", "pids.max", "pids.current", "memory.current", "memory.events"} {
		if e := os.Rename(filepath.Join(dir, name), filepath.Join(dir, name+".gone")); e != nil {
			t.Fatal(e)
		}
		if _, e := readOuter(dir); e == nil {
			t.Errorf("reading without %s succeeded", name)
		}
		if e := os.Rename(filepath.Join(dir, name+".gone"), filepath.Join(dir, name)); e != nil {
			t.Fatal(e)
		}
	}
	write("pids.events", "max x\n")
	if _, e := readOuter(dir); e == nil {
		t.Error("malformed pids.events accepted")
	}
}
