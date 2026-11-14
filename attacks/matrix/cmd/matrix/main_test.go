package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"warden/attacks/matrix"
	"warden/runtimes"
)

func TestValidate(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"validate", "-corpus", "../../testdata/corpus"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 entries, corpus sha256:") {
		t.Fatalf("output:\n%s", out.String())
	}
	if err := run([]string{"validate", "-corpus", t.TempDir()}, &out); err == nil {
		t.Fatal("empty corpus accepted")
	}
}

func TestRender(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for rt, verdict := range map[string]matrix.Verdict{"runc": matrix.Missed, "gvisor": matrix.Blocked} {
		res := matrix.Results{Runtime: rt, CorpusDigest: "sha256:0123456789abcdef", ImageDigest: "sha256:img", Limits: matrix.DefaultLimits,
			Cells: []matrix.Cell{{Attack: "p", Technique: "T1611", Runtime: rt, RunID: "run-" + rt, Verdict: verdict,
				StartedAt: start, FinishedAt: start.Add(time.Second), Exit: &runtimes.Exit{CgroupEmpty: true}}}}
		if err := matrix.WriteResults(filepath.Join(dir, rt+".json"), res); err != nil {
			t.Fatal(err)
		}
	}
	alerts := filepath.Join(dir, "alerts.jsonl")
	if err := os.WriteFile(alerts, []byte(`{"alert_id":"a1","execution_id":"run-runc","rule_id":"r","alerted_at":"2026-01-01T00:00:03Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	md, execs := filepath.Join(dir, "matrix.md"), filepath.Join(dir, "executions.jsonl")
	args := []string{"render", "-results", filepath.Join(dir, "runc.json") + "," + filepath.Join(dir, "gvisor.json"), "-alerts", alerts, "-out", md, "-executions", execs}
	if err := run(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(md)
	if !strings.Contains(string(got), "| Attack | Technique | runc | gvisor |") || !strings.Contains(string(got), "| p | T1611 | detected | blocked |") {
		t.Fatalf("markdown:\n%s", got)
	}
	lines, _ := os.ReadFile(execs)
	if n := strings.Count(string(lines), "\n"); n != 2 || !strings.Contains(string(lines), `"outcome":"succeeded"`) {
		t.Fatalf("executions:\n%s", lines)
	}
	if err := run([]string{"render"}, &bytes.Buffer{}); err == nil {
		t.Fatal("render without results accepted")
	}
	if err := run([]string{"bogus"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}
