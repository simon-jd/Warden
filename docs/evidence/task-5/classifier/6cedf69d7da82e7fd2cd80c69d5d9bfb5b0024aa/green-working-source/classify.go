// Package matrix classifies caller-supplied, agent-authored fixtures only.
// It does not authenticate evidence or provide a runtime, runner or CLI.
package matrix

import "strings"

type Evaluation string
type Verdict string
type Reason string

const (
	Unevaluated             Evaluation = "unevaluated"
	Error                   Evaluation = "error"
	Evaluated               Evaluation = "evaluated"
	Blocked                 Verdict = "blocked"
	Missed                  Verdict = "missed"
	// Detected is intentionally unavailable before Task12.
	NotRun                  Reason = "not_run"
	PrerequisiteUnavailable Reason = "prerequisite_unavailable"
	ScenarioUnavailable     Reason = "scenario_unavailable"
	InvalidFixture          Reason = "invalid_fixture"
	InvalidIdentity         Reason = "invalid_identity"
	IdentityMismatch        Reason = "identity_mismatch"
	IncompleteLogs          Reason = "incomplete_logs"
	UnknownExit             Reason = "unknown_exit"
	IncompleteCleanup       Reason = "incomplete_cleanup"
	MissingEntry            Reason = "missing_bound_attack_entry"
	InvalidEvidence         Reason = "invalid_evidence"
	ContradictoryEvidence   Reason = "contradictory_evidence"
	UnsubstantiatedMarker   Reason = "unsubstantiated_marker"
	IncompleteObjective     Reason = "incomplete_objective"
	ObjectiveDenied         Reason = "objective_policy_or_limit_denied"
	ObjectiveSucceeded      Reason = "objective_succeeded_detector_unavailable"
)

type Identity struct {
	Run, Image, Corpus, Attack, Runtime, Objective string
}
type Provenance struct {
	Kind, Author string
}

// Fixture and all nested records are caller assertions, never verified live truth.
// Exactly one of Unavailable and Execution must be supplied.
type Fixture struct {
	Provenance  Provenance
	Expected    Identity
	Unavailable Reason
	Execution   *Execution
}

type LogState string
const (
	LogsComplete   LogState = "complete"
	LogsTruncated  LogState = "truncated"
	LogsDropped    LogState = "dropped"
	LogsReadError  LogState = "read_error"
	LogsCloseError LogState = "close_error"
)
type Cleanup string
const (
	CleanupEmpty        Cleanup = "known_empty"
	CleanupUnknown      Cleanup = "unknown"
	CleanupNonempty     Cleanup = "nonempty"
	CleanupOuterDeleted Cleanup = "outer_deleted_only"
)
type Failure string
const (
	SetupFailure     Failure = "setup"
	StartFailure     Failure = "start"
	WaitFailure      Failure = "wait"
	TransportFailure Failure = "transport"
	KillFailure      Failure = "kill"
)

type Exit struct {
	Code int
}
type Execution struct {
	Identity Identity
	Failures []Failure
	Logs     LogState
	Exit     *Exit
	Cleanup  Cleanup
	Evidence []Evidence
}

type Source string
const (
	Guest     Source = "guest"
	Runtime   Source = "runtime"
	Collector Source = "independent_collector"
)
type Claim string
const (
	AttackEntry      Claim = "attack_entry"
	Marker           Claim = "success_marker"
	PolicyDenial     Claim = "defined_objective_policy_denial"
	LimitDenial      Claim = "defined_objective_limit_denial"
	ObjectiveSuccess Claim = "defined_objective_success"
	PrimitiveSuccess Claim = "primitive_success_only"
	DetectorEvent    Claim = "detector_event_unavailable_before_task12"
)

// Ref identifies a fixture evidence item; Detail states the defined-objective
// predicate/observation. Source never upgrades a guest string into collector truth.
type Evidence struct {
	Identity Identity
	Ref,     Detail string
	Source   Source
	Claim    Claim
}
type Result struct {
	Evaluation    Evaluation
	Verdict       *Verdict // nil unless evaluated
	Reason        Reason
	DetectorState string // always unavailable; Task12 has not run
	Provenance    Provenance
	Evidence      []Evidence // copied with original source distinctions
}

// ClassifyFixture has no I/O. Future live admission/authentication is not implemented.
func ClassifyFixture(f Fixture) Result {
	r := Result{Evaluation: Error, Reason: InvalidFixture, DetectorState: "unavailable", Provenance: f.Provenance}
	fail := func(reason Reason) Result {
		r.Reason = reason
		return r
	}
	if f.Execution != nil {
		r.Evidence = append([]Evidence(nil), f.Execution.Evidence...)
	}
	if f.Provenance.Kind != "agent_authored_fixture" || strings.TrimSpace(f.Provenance.Author) == "" {
		return r
	}
	if f.Execution == nil {
		switch f.Unavailable {
		case NotRun, PrerequisiteUnavailable, ScenarioUnavailable:
			r.Evaluation = Unevaluated
			return fail(f.Unavailable)
		default:
			return r
		}
	}
	if f.Unavailable != "" {
		return r
	}
	if !validIdentity(f.Expected) {
		return fail(InvalidIdentity)
	}
	x := f.Execution
	if x.Identity != f.Expected {
		return fail(IdentityMismatch)
	}
	for _, failure := range x.Failures {
		switch failure {
		case SetupFailure, StartFailure, WaitFailure, TransportFailure, KillFailure:
		default:
			return r
		}
	}
	if len(x.Failures) != 0 {
		return fail(Reason(string(x.Failures[0]) + "_error"))
	}
	if x.Logs != LogsComplete {
		return fail(IncompleteLogs)
	}
	if x.Exit == nil || x.Exit.Code < 0 || x.Exit.Code > 255 {
		return fail(UnknownExit)
	}
	if x.Cleanup != CleanupEmpty {
		return fail(IncompleteCleanup)
	}
	refs := make(map[string]bool)
	entries, markers, successes, denials := 0, 0, 0, 0
	for _, e := range x.Evidence {
		if e.Identity != f.Expected {
			return fail(IdentityMismatch)
		}
		if strings.TrimSpace(e.Ref) == "" || strings.TrimSpace(e.Detail) == "" {
			return fail(InvalidEvidence)
		}
		if refs[e.Ref] {
			return fail(ContradictoryEvidence)
		}
		refs[e.Ref] = true
		if e.Source != Guest && e.Source != Runtime && e.Source != Collector {
			return fail(InvalidEvidence)
		}
		switch e.Claim {
		case AttackEntry:
			if e.Source != Runtime {
				return fail(InvalidEvidence)
			}
			entries++
		case Marker:
			if e.Source != Guest {
				return fail(InvalidEvidence)
			}
			markers++
		case ObjectiveSuccess:
			if e.Source != Collector {
				return fail(InvalidEvidence)
			}
			successes++
		case PolicyDenial:
			denials++
		case LimitDenial:
			if e.Source != Runtime {
				return fail(InvalidEvidence)
			}
			denials++
		case PrimitiveSuccess:
			if e.Source != Guest {
				return fail(InvalidEvidence)
			}
		default:
			return fail(InvalidEvidence)
		}
	}
	if entries == 0 {
		return fail(MissingEntry)
	}
	if entries != 1 || markers > 1 || successes+denials > 1 || (markers != 0 && denials != 0) {
		return fail(ContradictoryEvidence)
	}
	if successes == 0 && denials == 0 {
		if markers != 0 {
			return fail(UnsubstantiatedMarker)
		}
		return fail(IncompleteObjective)
	}
	r.Evaluation = Evaluated
	verdict := Blocked
	r.Reason = ObjectiveDenied
	if successes == 1 {
		verdict = Missed
		r.Reason = ObjectiveSucceeded
	}
	r.Verdict = &verdict
	return r
}

func validIdentity(id Identity) bool {
	for _, value := range []string{id.Run, id.Image, id.Corpus, id.Attack, id.Runtime, id.Objective} {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}
