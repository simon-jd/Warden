package matrix

import (
	"strconv"
	"testing"
)

// Every record here was authored by subagent /root/matrix_classifier. These are
// in-memory fake attacks, NOT execution results or evidence for any live cell.
func fixture(outcome Claim, source Source) Fixture {
	id := Identity{"fixture-run", "fixture-image", "fixture-corpus", "fake-attack", "fake-runtime", "synthetic-cross-boundary-objective"}
	return Fixture{
		Provenance: Provenance{"agent_authored_fixture", "subagent:/root/matrix_classifier"},
		Expected: id,
		Execution: &Execution{Identity: id, Logs: LogsComplete, Exit: &Exit{0}, Cleanup: CleanupEmpty,
			Evidence: []Evidence{
				{Identity: id, Ref: "entry", Detail: "fixture authenticated entry assertion", Source: Runtime, Claim: AttackEntry},
				{Identity: id, Ref: "outcome", Detail: "fixture predicate for defined synthetic objective", Source: source, Claim: outcome},
			}},
	}
}

func assertResult(t *testing.T, f Fixture, evaluation Evaluation, verdict Verdict, reason Reason) {
	t.Helper()
	got := ClassifyFixture(f)
	if got.Evaluation != evaluation || got.Reason != reason || got.DetectorState != "unavailable" ||
		(verdict == "" && got.Verdict != nil) || (verdict != "" && (got.Verdict == nil || *got.Verdict != verdict)) {
		t.Fatalf("got %+v, want evaluation=%s verdict=%q reason=%s unavailable detector", got, evaluation, verdict, reason)
	}
	if got.Provenance != f.Provenance { t.Fatal("fixture provenance lost") }
}

func TestMatrixClassifiesFixture(t *testing.T) {
	success := fixture(ObjectiveSuccess, Collector)
	success.Execution.Evidence = append(success.Execution.Evidence, Evidence{Identity: success.Expected, Ref: "marker", Detail: "exact fixture marker", Source: Guest, Claim: Marker})
	assertResult(t, success, Evaluated, Missed, ObjectiveSucceeded)
	denied := fixture(PolicyDenial, Guest)
	denied.Execution.Exit.Code = 1
	assertResult(t, denied, Evaluated, Blocked, ObjectiveDenied)
}

func TestUnexecutedFixturesStayUnevaluated(t *testing.T) {
	for _, reason := range []Reason{NotRun, PrerequisiteUnavailable, ScenarioUnavailable} {
		t.Run(string(reason), func(t *testing.T) {
			f := fixture(ObjectiveSuccess, Collector)
			f.Execution = nil
			f.Unavailable = reason
			assertResult(t, f, Unevaluated, "", reason)
		})
	}
}

func TestAmbiguousFixturesNeverProduceVerdicts(t *testing.T) {
	tests := []struct { name string; mutate func(*Fixture); reason Reason }{
		{"zero fixture", func(f *Fixture) { *f = Fixture{} }, InvalidFixture},
		{"unattributed fixture", func(f *Fixture) { f.Provenance.Author = "" }, InvalidFixture},
		{"pretend live provenance", func(f *Fixture) { f.Provenance.Kind = "live" }, InvalidFixture},
		{"not run with execution", func(f *Fixture) { f.Unavailable = NotRun }, InvalidFixture},
		{"absent execution", func(f *Fixture) { f.Execution = nil }, InvalidFixture},
		{"invented prerequisite", func(f *Fixture) { f.Execution = nil; f.Unavailable = "unknown" }, InvalidFixture},
		{"unknown identity", func(f *Fixture) { f.Expected.Objective = "" }, InvalidIdentity},
		{"run mismatch", func(f *Fixture) { f.Execution.Identity.Run = "other" }, IdentityMismatch},
		{"image mismatch", func(f *Fixture) { f.Execution.Identity.Image = "other" }, IdentityMismatch},
		{"corpus mismatch", func(f *Fixture) { f.Execution.Identity.Corpus = "other" }, IdentityMismatch},
		{"attack mismatch", func(f *Fixture) { f.Execution.Identity.Attack = "other" }, IdentityMismatch},
		{"runtime mismatch", func(f *Fixture) { f.Execution.Identity.Runtime = "other" }, IdentityMismatch},
		{"objective mismatch", func(f *Fixture) { f.Execution.Identity.Objective = "other" }, IdentityMismatch},
		{"invalid negative exit", func(f *Fixture) { f.Execution.Exit.Code = -1 }, UnknownExit},
		{"unknown exit", func(f *Fixture) { f.Execution.Exit = nil }, UnknownExit},
		{"missing entry", func(f *Fixture) { f.Execution.Evidence = f.Execution.Evidence[1:] }, MissingEntry},
		{"guest entry string", func(f *Fixture) { f.Execution.Evidence[0].Source = Guest }, InvalidEvidence},
		{"unbound evidence", func(f *Fixture) { f.Execution.Evidence[1].Identity.Run = "other" }, IdentityMismatch},
		{"empty evidence reference", func(f *Fixture) { f.Execution.Evidence[1].Ref = "" }, InvalidEvidence},
		{"missing predicate", func(f *Fixture) { f.Execution.Evidence[1].Detail = "" }, InvalidEvidence},
		{"duplicate event", func(f *Fixture) { f.Execution.Evidence = append(f.Execution.Evidence, f.Execution.Evidence[1]) }, ContradictoryEvidence},
		{"guest objective claim", func(f *Fixture) { f.Execution.Evidence[1].Source = Guest }, InvalidEvidence},
		{"invented source", func(f *Fixture) { f.Execution.Evidence[1].Source = "kernel-string" }, InvalidEvidence},
		{"primitive alone", func(f *Fixture) { f.Execution.Evidence[1].Claim = PrimitiveSuccess; f.Execution.Evidence[1].Source = Guest }, IncompleteObjective},
		{"marker alone", func(f *Fixture) { f.Execution.Evidence[1].Claim = Marker; f.Execution.Evidence[1].Source = Guest }, UnsubstantiatedMarker},
		{"kill success is not objective evidence", func(f *Fixture) { f.Execution.Evidence[1].Claim = "kill_success" }, InvalidEvidence},
		{"forged detector", func(f *Fixture) { f.Execution.Evidence[1].Claim = DetectorEvent }, InvalidEvidence},
		{"invented claim", func(f *Fixture) { f.Execution.Evidence[1].Claim = "detected" }, InvalidEvidence},
		{"guest limit string", func(f *Fixture) { f.Execution.Evidence[1].Claim = LimitDenial; f.Execution.Evidence[1].Source = Guest }, InvalidEvidence},
		{"opposed outcomes", func(f *Fixture) { e := f.Execution.Evidence[1]; e.Ref = "opposite"; e.Claim = PolicyDenial; e.Source = Runtime; f.Execution.Evidence = append(f.Execution.Evidence, e) }, ContradictoryEvidence},
		{"marker contradicts denial", func(f *Fixture) { f.Execution.Evidence[1].Claim = PolicyDenial; e := f.Execution.Evidence[1]; e.Ref = "marker"; e.Claim = Marker; e.Source = Guest; f.Execution.Evidence = append(f.Execution.Evidence, e) }, ContradictoryEvidence},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { f := fixture(ObjectiveSuccess, Collector); test.mutate(&f); assertResult(t, f, Error, "", test.reason) })
	}
}

func TestIncompleteExecutionCannotBeClassified(t *testing.T) {
	for _, failure := range []Failure{SetupFailure, StartFailure, WaitFailure, TransportFailure, KillFailure, "unknown"} {
		t.Run(string(failure), func(t *testing.T) {
			f := fixture(PolicyDenial, Runtime)
			f.Execution.Failures = []Failure{failure}
			reason := Reason(string(failure) + "_error")
			if failure == "unknown" { reason = InvalidFixture }
			assertResult(t, f, Error, "", reason)
		})
	}
	for _, logs := range []LogState{"", LogsTruncated, LogsDropped, LogsReadError, LogsCloseError, "unknown"} {
		t.Run("logs_"+string(logs), func(t *testing.T) { f := fixture(PolicyDenial, Runtime); f.Execution.Logs = logs; assertResult(t, f, Error, "", IncompleteLogs) })
	}
	for _, cleanup := range []Cleanup{"", CleanupUnknown, CleanupNonempty, CleanupOuterDeleted} {
		t.Run("cleanup_"+string(cleanup), func(t *testing.T) { f := fixture(PolicyDenial, Runtime); f.Execution.Cleanup = cleanup; assertResult(t, f, Error, "", IncompleteCleanup) })
	}
}

func TestExitOrKillCannotProvePolicyDenial(t *testing.T) {
	for _, code := range []int{0, 1, 137} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := fixture(PolicyDenial, Runtime)
			f.Execution.Exit.Code = code
			f.Execution.Evidence = f.Execution.Evidence[:1]
			assertResult(t, f, Error, "", IncompleteObjective)
		})
	}
	f := fixture(LimitDenial, Runtime)
	f.Execution.Exit.Code = 137
	assertResult(t, f, Evaluated, Blocked, ObjectiveDenied)
	f.Execution.Evidence = nil // even a limit claim cannot rescue absent entry
	assertResult(t, f, Error, "", MissingEntry)
}

func TestResultPreservesFixtureSourcesWithoutAliasing(t *testing.T) {
	f := fixture(ObjectiveSuccess, Collector)
	got := ClassifyFixture(f)
	if len(got.Evidence) != 2 || got.Evidence[1].Source != Collector { t.Fatal("evidence source lost") }
	got.Evidence[1].Source = Guest
	if f.Execution.Evidence[1].Source != Collector { t.Fatal("result mutated input") }
}
