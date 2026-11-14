package supervisor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestArgsRoundTrip(t *testing.T) {
	c := Config{Pids: 32, TimeoutS: 2, Cmd: []string{"/warden-probe", "fork", "--", "-x"}}
	got, err := Parse(Args(c))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip %+v != %+v", got, c)
	}
}

func TestParseRejectsBadConfigs(t *testing.T) {
	for name, args := range map[string][]string{
		"no separator":   {"-pids", "32", "-timeout-s", "2", "/warden-probe"},
		"no command":     {"-pids", "32", "-timeout-s", "2", "--"},
		"relative path":  {"-pids", "32", "-timeout-s", "2", "--", "warden-probe"},
		"zero pids":      {"-pids", "0", "-timeout-s", "2", "--", "/p"},
		"huge pids":      {"-pids", "4194305", "-timeout-s", "2", "--", "/p"},
		"zero timeout":   {"-pids", "32", "-timeout-s", "0", "--", "/p"},
		"day timeout":    {"-pids", "32", "-timeout-s", "86401", "--", "/p"},
		"unknown flag":   {"-pids", "32", "-timeout-s", "2", "-uid", "0", "--", "/p"},
		"stray argument": {"-pids", "32", "x", "-timeout-s", "2", "--", "/p"},
		"nul in command": {"-pids", "32", "-timeout-s", "2", "--", "/p\x00"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("%s: accepted %q", name, args)
		}
	}
}

func TestParseReportIsStrict(t *testing.T) {
	good := `{"v":1,"code":0,"timed_out":false,"pids_max_events":1,"peak_pids":32,"cgroup_empty":true,"init_ns":10,"exec_ns":20}`
	r, err := ParseReport([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if r.PeakPids != 32 || r.PidsMaxEvents != 1 || !r.CgroupEmpty || r.ExecUnixNano != 20 {
		t.Fatalf("parsed %+v", r)
	}
	for name, raw := range map[string]string{
		"empty":         ``,
		"version":       `{"v":2,"code":0}`,
		"unknown field": `{"v":1,"code":0,"extra":1}`,
		"trailing":      good + `{}`,
		"too long":      `{"v":1,"error":"` + strings.Repeat("x", MaxReportBytes) + `"}`,
	} {
		if _, err := ParseReport([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if b, err := r.Encode(); err != nil || len(b) > MaxReportBytes {
		t.Fatalf("encode: %v %d", err, len(b))
	}
	long := Report{Version: 1, Error: strings.Repeat("e", 2*MaxReportBytes)}
	if b, err := long.Encode(); err != nil || len(b) > MaxReportBytes {
		t.Fatalf("long error must be cut to fit: %v %d", err, len(b))
	}
}

// fakeCgroup lays out the files the supervisor touches, the way cgroupfs
// shows them. A plain directory cannot create control files on mkdir, so the
// workload directory is pre-created and the test checks what was written.
func fakeCgroup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"cgroup.procs":                    "1\n7\n",
		"cgroup.subtree_control":          "",
		"init/cgroup.procs":               "",
		"workload/cgroup.procs":           "",
		"workload/pids.max":               "",
		"workload/cgroup.kill":            "",
		"workload/cgroup.events":          "populated 0\nfrozen 0\n",
		"workload/pids.events":            "max 3\n",
		"workload/pids.peak":              "32\n",
		"workload/pids.events.local":      "max 3\n",
		"workload/cgroup.subtree_control": "",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareMovesProcessesAndSetsPidsMax(t *testing.T) {
	dir := fakeCgroup(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	w, err := prepare(root, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Each write starts at offset 0 (no O_TRUNC, which cgroupfs need not
	// support), so the last PID moved is what the file holds.
	if got := read(t, filepath.Join(dir, "init/cgroup.procs")); got != "7" {
		t.Errorf("init/cgroup.procs = %q", got)
	}
	if got := read(t, filepath.Join(dir, "cgroup.subtree_control")); got != "+pids" {
		t.Errorf("subtree_control = %q", got)
	}
	if got := read(t, filepath.Join(dir, "workload/pids.max")); got != "32" {
		t.Errorf("pids.max = %q", got)
	}
}

func TestCollectReadsCountersAndEmptiness(t *testing.T) {
	dir := fakeCgroup(t)
	root, err := os.OpenRoot(filepath.Join(dir, "workload"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var r Report
	if err := collect(root, &r); err != nil {
		t.Fatal(err)
	}
	if r.PidsMaxEvents != 3 || r.PeakPids != 32 {
		t.Fatalf("collected %+v", r)
	}
	if err := kill(root); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, "workload/cgroup.kill")); got != "1" {
		t.Errorf("cgroup.kill = %q", got)
	}
	if pop, err := populated(root); err != nil || pop {
		t.Fatalf("populated = %v %v", pop, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workload/cgroup.events"), []byte("frozen 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := populated(root); err == nil {
		t.Fatal("missing populated key accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "workload/pids.peak"), []byte("lots\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := collect(root, &r); err == nil {
		t.Fatal("bad pids.peak accepted")
	}
}
