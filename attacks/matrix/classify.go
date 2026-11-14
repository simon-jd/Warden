package matrix

import (
	"bytes"
	"warden/runtimes"
)

// Verdict is one cell of the matrix.
type Verdict string

const (
	// Blocked: the probe ran to the end and never printed its success signal.
	Blocked Verdict = "blocked"
	// Detected: the probe printed its success signal and an alert names its run.
	Detected Verdict = "detected"
	// Missed: the probe printed its success signal and no alert names its run.
	Missed Verdict = "missed"
	// Error: the run itself failed, so the cell has no verdict.
	Error Verdict = "error"
)

// Observation is everything one run of one probe produced.
type Observation struct {
	StartErr, WaitErr, LogErr, KillErr error
	Exit                               runtimes.Exit
	Logs                               []byte
	RequireProof                       bool
}

// Classify gives a run's verdict from what it produced and the probe's
// success signal. It never returns Detected: alerts are joined afterwards by
// ApplyAlerts, once detection (Task 12) has run.
//
// The signal in the output is proof the probe reached its goal, whatever
// else went wrong. Without it the run counts as blocked only when the run
// completed, its output is complete and the sandbox cgroup is empty, so a
// lost or cut-off output can never pass for a block.
func Classify(o Observation, signal string) (Verdict, string) {
	if o.StartErr != nil {
		return Error, "start: " + o.StartErr.Error()
	}
	if signal != "" && bytes.Contains(o.Logs, []byte(signal)) {
		return Missed, "success signal in the output" + noteErrors(o)
	}
	switch {
	case o.WaitErr != nil:
		return Error, "wait: " + o.WaitErr.Error()
	case o.LogErr != nil:
		return Error, "logs: " + o.LogErr.Error()
	case o.KillErr != nil:
		return Error, "cleanup: " + o.KillErr.Error()
	case o.Exit.LogsTruncated:
		return Error, "output truncated, so the success signal cannot be ruled out"
	case !o.Exit.CgroupEmpty:
		return Error, "processes left in the sandbox cgroup after exit"
	case o.RequireProof && !o.Exit.OOMKilled && o.Exit.PidsMaxEvents == 0 && !bytes.Contains(o.Logs, []byte("WARDEN_DENIED ")):
		return Error, "probe objective or denial not recorded"
	}
	return Blocked, "no success signal in the complete output"
}

func noteErrors(o Observation) string {
	var notes []byte
	for _, e := range []struct {
		name string
		err  error
	}{{"wait", o.WaitErr}, {"logs", o.LogErr}, {"cleanup", o.KillErr}} {
		if e.err != nil {
			notes = append(notes, "; "+e.name+": "+e.err.Error()...)
		}
	}
	if o.Exit.LogsTruncated {
		notes = append(notes, "; output truncated"...)
	}
	if o.WaitErr == nil && !o.Exit.CgroupEmpty {
		notes = append(notes, "; processes left in the sandbox cgroup"...)
	}
	return string(notes)
}
