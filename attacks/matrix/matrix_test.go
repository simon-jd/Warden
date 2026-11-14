package matrix

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"warden/runtimes"
)

// hostShell runs a probe with the host's /bin/sh. It stands in for a sandbox
// runtime so the whole path (corpus, command line, output, verdict) runs in a
// unit test; it is only ever given the two fake probes in testdata.
type hostShell struct{ specs []runtimes.Spec }

type shellHandle struct {
	cmd    *exec.Cmd
	out    bytes.Buffer
	killed bool
}

func (h *hostShell) Start(ctx context.Context, spec runtimes.Spec) (runtimes.Handle, error) {
	h.specs = append(h.specs, spec)
	sh := &shellHandle{cmd: exec.CommandContext(ctx, spec.Cmd[0], spec.Cmd[1:]...)}
	sh.cmd.Env = []string{"PATH=/usr/bin:/bin"}
	sh.cmd.Stdout, sh.cmd.Stderr = &sh.out, &sh.out
	return sh, sh.cmd.Start()
}

func (h *shellHandle) Wait(context.Context) (runtimes.Exit, error) {
	err := h.cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return runtimes.Exit{}, err
	}
	return runtimes.Exit{Code: uint32(h.cmd.ProcessState.ExitCode()), CgroupEmpty: true}, nil
}
func (h *shellHandle) Kill() error         { h.killed = true; return nil }
func (h *shellHandle) Logs() io.ReadCloser { return io.NopCloser(bytes.NewReader(h.out.Bytes())) }

func TestMatrixClassifiesFixture(t *testing.T) {
	attacks, err := LoadCorpus("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	if len(attacks) != 2 || attacks[0].ID != "fake-always-fails" || attacks[1].ID != "fake-always-succeeds" {
		t.Fatalf("corpus = %+v", attacks)
	}
	rt := &hostShell{}
	res, err := Run(context.Background(), rt, attacks, Options{Runtime: "host-shell", ImageDigest: "sha256:fake"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Verdict{}
	for _, c := range res.Cells {
		got[c.Attack] = c.Verdict
		if len(c.RunID) != 26 || c.StartedAt.IsZero() || c.FinishedAt.Before(c.StartedAt) || c.Exit == nil {
			t.Errorf("%s: incomplete cell %+v", c.Attack, c)
		}
	}
	if got["fake-always-succeeds"] != Missed || got["fake-always-fails"] != Blocked {
		t.Fatalf("verdicts = %v, want succeeds=missed fails=blocked", got)
	}
	for _, spec := range rt.specs {
		if spec.Network != "none" || spec.Limits != DefaultLimits || spec.ImageDigest != "sha256:fake" || spec.Cmd[0] != "/bin/sh" || spec.Cmd[1] != "-c" {
			t.Errorf("spec = %+v", spec)
		}
	}

	m, err := Merge([]Results{res})
	if err != nil {
		t.Fatal(err)
	}
	success := m.Cells["fake-always-succeeds"]["host-shell"]
	fail := m.Cells["fake-always-fails"]["host-shell"]
	at := success.StartedAt.Add(2 * time.Second).Format(time.RFC3339Nano)
	if err := m.ApplyAlerts([]Alert{
		{AlertID: "a1", ExecutionID: success.RunID, RuleID: "r1", AlertedAt: at},
		{AlertID: "a2", ExecutionID: fail.RunID, RuleID: "r2", AlertedAt: at},
		{AlertID: "other", ExecutionID: "unrelated-run", RuleID: "r3", AlertedAt: at},
	}); err != nil {
		t.Fatal(err)
	}
	if v := m.Cells["fake-always-succeeds"]["host-shell"].Verdict; v != Detected {
		t.Fatalf("alerted success = %s, want detected", v)
	}
	if c := m.Cells["fake-always-fails"]["host-shell"]; c.Verdict != Blocked || len(c.Alerts) != 1 {
		t.Fatalf("alerted block = %+v, want blocked with one alert", c)
	}
	md := m.Markdown()
	for _, want := range []string{"| fake-always-fails | T1059.004 | blocked |", "| fake-always-succeeds | T1059.004 | detected |", "| host-shell | 1 | 1 | 0 | 0 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}

func TestClassify(t *testing.T) {
	clean := runtimes.Exit{CgroupEmpty: true}
	boom := errors.New("boom")
	for _, tc := range []struct {
		name   string
		o      Observation
		signal string
		want   Verdict
		reason string
	}{
		{"clean run without signal", Observation{Exit: clean, Logs: []byte("denied\n")}, "SIG", Blocked, "no success signal"},
		{"signal", Observation{Exit: clean, Logs: []byte("x SIG y")}, "SIG", Missed, "success signal"},
		{"nonzero exit is still blocked", Observation{Exit: runtimes.Exit{Code: 1, CgroupEmpty: true}}, "SIG", Blocked, "no success signal"},
		{"timeout without signal", Observation{Exit: runtimes.Exit{Code: 137, TimedOut: true, CgroupEmpty: true}}, "SIG", Blocked, "no success signal"},
		{"start error", Observation{StartErr: boom, Logs: []byte("SIG")}, "SIG", Error, "start: boom"},
		{"wait error without signal", Observation{WaitErr: boom}, "SIG", Error, "wait: boom"},
		{"wait error with signal", Observation{WaitErr: boom, Logs: []byte("SIG")}, "SIG", Missed, "wait: boom"},
		{"log error", Observation{Exit: clean, LogErr: boom}, "SIG", Error, "logs: boom"},
		{"cleanup error", Observation{Exit: clean, KillErr: boom}, "SIG", Error, "cleanup: boom"},
		{"truncated output", Observation{Exit: runtimes.Exit{LogsTruncated: true, CgroupEmpty: true}}, "SIG", Error, "truncated"},
		{"truncated but signal seen", Observation{Exit: runtimes.Exit{LogsTruncated: true, CgroupEmpty: true}, Logs: []byte("SIG")}, "SIG", Missed, "output truncated"},
		{"processes left", Observation{Exit: runtimes.Exit{}}, "SIG", Error, "processes left"},
		{"empty signal never matches", Observation{Exit: clean, Logs: []byte("anything")}, "", Blocked, "no success signal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := Classify(tc.o, tc.signal)
			if got != tc.want || !strings.Contains(reason, tc.reason) {
				t.Fatalf("got %s %q, want %s containing %q", got, reason, tc.want, tc.reason)
			}
		})
	}
}

func TestParseExpect(t *testing.T) {
	a, err := ParseExpect([]byte("---\n# probe\nid: probe-1\ntechnique: T1611 # escape\nsuccess_signal: \"OK \\\"1\\\"\"\n"))
	if err != nil || a.ID != "probe-1" || a.Technique != "T1611" || a.SuccessSignal != `OK "1"` {
		t.Fatalf("got %+v %v", a, err)
	}
	a, err = ParseExpect([]byte("id: p\r\ntechnique: T1611.001\r\nsuccess_signal: 'it''s # here'\r\n"))
	if err != nil || a.Technique != "T1611.001" || a.SuccessSignal != "it's # here" {
		t.Fatalf("got %+v %v", a, err)
	}
	for name, doc := range map[string]string{
		"missing signal":     "id: p\ntechnique: T1611\n",
		"unknown key":        "id: p\ntechnique: T1611\nsuccess_signal: S\nextra: 1\n",
		"duplicate key":      "id: p\nid: q\ntechnique: T1611\nsuccess_signal: S\n",
		"nested value":       "id: p\ntechnique: T1611\nsuccess_signal:\n  - S\n",
		"bad technique":      "id: p\ntechnique: 1611\nsuccess_signal: S\n",
		"bad id":             "id: P_1\ntechnique: T1611\nsuccess_signal: S\n",
		"no colon":           "id p\n",
		"unterminated quote": "id: p\ntechnique: T1611\nsuccess_signal: \"S\n",
		"flow value":         "id: p\ntechnique: T1611\nsuccess_signal: [S]\n",
		"blank signal":       "id: p\ntechnique: T1611\nsuccess_signal: '  '\n",
		"text after quote":   "id: p\ntechnique: T1611\nsuccess_signal: 'S' x\n",
	} {
		if _, err := ParseExpect([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func writeEntry(t *testing.T, dir, id, expect, script string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id, "expect.yaml"), []byte(expect), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id, "run.sh"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCorpusRejects(t *testing.T) {
	good := "id: a\ntechnique: T1611\nsuccess_signal: DONE_1\n"
	for name, setup := range map[string]func(t *testing.T, dir string){
		"empty corpus": func(t *testing.T, dir string) {},
		"id differs from directory": func(t *testing.T, dir string) {
			writeEntry(t, dir, "b", good, "true\n")
		},
		"script holds the signal": func(t *testing.T, dir string) {
			writeEntry(t, dir, "a", good, "echo DONE_1\n")
		},
		"empty script": func(t *testing.T, dir string) {
			writeEntry(t, dir, "a", good, "\n")
		},
		"missing run.sh": func(t *testing.T, dir string) {
			writeEntry(t, dir, "a", good, "true\n")
			os.Remove(filepath.Join(dir, "a", "run.sh"))
		},
		"symlinked script": func(t *testing.T, dir string) {
			writeEntry(t, dir, "a", good, "true\n")
			os.Remove(filepath.Join(dir, "a", "run.sh"))
			if err := os.Symlink("/bin/true", filepath.Join(dir, "a", "run.sh")); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked entry": func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "a")); err != nil {
				t.Fatal(err)
			}
		},
		"oversized script": func(t *testing.T, dir string) {
			writeEntry(t, dir, "a", good, strings.Repeat("#", maxScriptBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			if _, err := LoadCorpus(dir); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	dir := t.TempDir()
	writeEntry(t, dir, "a", good, "printf '%s_%s\\n' DONE 1\n")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	attacks, err := LoadCorpus(dir)
	if err != nil || len(attacks) != 1 || !strings.HasPrefix(attacks[0].Digest, "sha256:") {
		t.Fatalf("got %+v %v", attacks, err)
	}
	before := CorpusDigest(attacks)
	writeEntry(t, dir, "a", good, "printf '%s_%s\\n' DONE 1 # changed\n")
	attacks, _ = LoadCorpus(dir)
	if CorpusDigest(attacks) == before {
		t.Fatal("corpus digest ignores a script change")
	}
}

// scripted is a runtime whose every step returns what the test asks for.
type scripted struct {
	startErr, waitErr, logErr, killErr error
	logs                               string
	exit                               runtimes.Exit
	nilLogs                            bool
	kills                              int
}

func (s *scripted) Start(context.Context, runtimes.Spec) (runtimes.Handle, error) {
	if s.startErr != nil {
		return nil, s.startErr
	}
	return s, nil
}
func (s *scripted) Wait(context.Context) (runtimes.Exit, error) { return s.exit, s.waitErr }
func (s *scripted) Kill() error                                 { s.kills++; return s.killErr }
func (s *scripted) Logs() io.ReadCloser {
	if s.nilLogs {
		return nil
	}
	return readCloser{strings.NewReader(s.logs), s.logErr}
}

type readCloser struct {
	io.Reader
	closeErr error
}

func (r readCloser) Close() error { return r.closeErr }

func TestRunRecordsRuntimeFailures(t *testing.T) {
	probe := []Attack{{ID: "p", Technique: "T1611", SuccessSignal: "SIG", Digest: "sha256:x", Script: "true"}}
	boom := errors.New("boom")
	clean := runtimes.Exit{CgroupEmpty: true}
	for _, tc := range []struct {
		name  string
		rt    *scripted
		want  Verdict
		kills int
	}{
		{"start fails", &scripted{startErr: boom}, Error, 0},
		{"wait fails", &scripted{waitErr: boom}, Error, 1},
		{"log close fails", &scripted{exit: clean, logErr: boom}, Error, 1},
		{"no log stream", &scripted{exit: clean, nilLogs: true}, Error, 1},
		{"kill fails", &scripted{exit: clean, killErr: boom}, Error, 1},
		{"clean block", &scripted{exit: clean, logs: "nope"}, Blocked, 1},
		{"signal", &scripted{exit: clean, logs: "SIG"}, Missed, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Run(context.Background(), tc.rt, probe, Options{Runtime: "fake", ImageDigest: "sha256:img"})
			if err != nil {
				t.Fatal(err)
			}
			c := res.Cells[0]
			if c.Verdict != tc.want || tc.rt.kills != tc.kills || c.RunID == "" {
				t.Fatalf("cell %+v kills=%d, want %s kills=%d", c, tc.rt.kills, tc.want, tc.kills)
			}
		})
	}
	for name, opt := range map[string]Options{
		"bad runtime name": {Runtime: "Bad Name", ImageDigest: "sha256:img"},
		"no image":         {Runtime: "fake"},
		"bad timeout":      {Runtime: "fake", ImageDigest: "sha256:img", Limits: runtimes.Limits{CPU: 1}},
	} {
		if _, err := Run(context.Background(), &scripted{}, probe, opt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	long := &scripted{exit: clean, logs: strings.Repeat("x", maxOutputBytes+10)}
	res, _ := Run(context.Background(), long, probe, Options{Runtime: "fake", ImageDigest: "sha256:img"})
	if !strings.HasSuffix(res.Cells[0].Output, "[... output cut at 4 KiB]") {
		t.Fatal("long output kept whole")
	}
}

func pass(rt, corpus string, cells ...Cell) Results {
	for i := range cells {
		cells[i].Runtime = rt
	}
	return Results{Runtime: rt, CorpusDigest: corpus, Cells: cells}
}

func TestMergeChecksConsistency(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cell := func(attack, run string, v Verdict) Cell {
		return Cell{Attack: attack, Technique: "T1611", RunID: run, Verdict: v, StartedAt: start, FinishedAt: start.Add(time.Second)}
	}
	for name, passes := range map[string][]Results{
		"no passes":         nil,
		"different corpora": {pass("runc", "sha256:a", cell("p", "r1", Blocked)), pass("gvisor", "sha256:b", cell("p", "r2", Blocked))},
		"runtime twice":     {pass("runc", "sha256:a", cell("p", "r1", Blocked)), pass("runc", "sha256:a", cell("p", "r2", Blocked))},
		"missing cell":      {pass("runc", "sha256:a", cell("p", "r1", Blocked), cell("q", "r3", Blocked)), pass("gvisor", "sha256:a", cell("p", "r2", Blocked))},
		"foreign cell":      {{Runtime: "runc", CorpusDigest: "sha256:a", Cells: []Cell{{Attack: "p", Runtime: "gvisor"}}}},
	} {
		if _, err := Merge(passes); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	m, err := Merge([]Results{
		pass("runc", "sha256:0123456789abcdef", cell("p", "r1", Missed), cell("q", "r3", Error)),
		pass("gvisor", "sha256:0123456789abcdef", cell("p", "r2", Blocked), cell("q", "r4", Missed)),
	})
	if err != nil {
		t.Fatal(err)
	}
	early := start.Add(-time.Second).Format(time.RFC3339)
	if err := m.ApplyAlerts([]Alert{{AlertID: "a", ExecutionID: "r1", RuleID: "x", AlertedAt: early}}); err == nil {
		t.Fatal("alert before its run accepted")
	}
	got := map[string]string{}
	for _, e := range m.Executions() {
		got[e.ExecutionID] = e.Outcome
		if e.TechniqueID != "T1611" || e.ExecutedAt != "2026-01-01T00:00:00Z" || !strings.HasSuffix(e.RunID, "/0123456789ab") {
			t.Errorf("execution %+v", e)
		}
	}
	want := map[string]string{"r1": "succeeded", "r2": "failed", "r3": "skipped", "r4": "succeeded"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("outcomes = %v, want %v", got, want)
			break
		}
	}
	if md := m.Markdown(); !strings.Contains(md, "No alerts were joined") || !strings.Contains(md, "| p | T1611 | missed | blocked |") {
		t.Errorf("markdown:\n%s", md)
	}
}

func TestReadAlerts(t *testing.T) {
	alerts, err := ReadAlerts(strings.NewReader(`{"alert_id":"a","execution_id":"e","rule_id":"r","alerted_at":"2026-01-01T00:00:02Z"}` + "\n\n"))
	if err != nil || len(alerts) != 1 || alerts[0].RuleID != "r" {
		t.Fatalf("got %+v %v", alerts, err)
	}
	for name, line := range map[string]string{
		"unknown field": `{"alert_id":"a","execution_id":"e","rule_id":"r","alerted_at":"2026-01-01T00:00:02Z","x":1}`,
		"missing field": `{"alert_id":"a","execution_id":"e","alerted_at":"2026-01-01T00:00:02Z"}`,
		"bad time":      `{"alert_id":"a","execution_id":"e","rule_id":"r","alerted_at":"yesterday"}`,
		"not json":      `alert`,
	} {
		if _, err := ReadAlerts(strings.NewReader(line)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunFromEnvSkipsWithoutCorpus(t *testing.T) {
	t.Setenv("WARDEN_MATRIX_CORPUS", "")
	RunFromEnv(t, nil, "none")
}

func TestResultsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runc.json")
	in := pass("runc", "sha256:a", Cell{Attack: "p", Technique: "T1611", RunID: "r", Verdict: Blocked, Exit: &runtimes.Exit{Code: 1, CgroupEmpty: true}})
	if err := WriteResults(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadResults(path)
	if err != nil || out.Cells[0].Exit.Code != 1 || out.Cells[0].Verdict != Blocked {
		t.Fatalf("got %+v %v", out, err)
	}
}

// A live probe that exits before recording its objective cannot claim an isolation block.
func TestClassifyRequiresObjectiveProof(t *testing.T) {
	clean := runtimes.Exit{CgroupEmpty: true}
	if got, _ := Classify(Observation{Exit: clean, RequireProof: true, Logs: []byte("shell: /warden-attack: not found\n")}, "WARDEN_test"); got != Error {
		t.Fatalf("missing probe classified %s", got)
	}
	if got, _ := Classify(Observation{Exit: clean, RequireProof: true, Logs: []byte("WARDEN_DENIED test EPERM\n")}, "WARDEN_test"); got != Blocked {
		t.Fatalf("denied probe classified %s", got)
	}
	if got, _ := Classify(Observation{Exit: runtimes.Exit{OOMKilled: true, CgroupEmpty: true}, RequireProof: true}, "WARDEN_test"); got != Blocked {
		t.Fatalf("OOM-killed probe classified %s", got)
	}
}
