package vuln

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// SLAResult uses an inclusive due boundary and the supplied evaluation clock.
type SLAResult struct {
	Due         time.Time
	EvaluatedAt time.Time
	Allowed     time.Duration
	Closed      bool
	Breached    bool
}

// Summary describes only the supplied cohort, not a measured fleet population.
type Summary struct {
	OpenCount         int
	FixedCount        int
	OpenBreaches      int
	FixedBreaches     int
	MedianRemediation time.Duration
	HasMedian         bool
}

const day = 24 * time.Hour

// maxYear keeps every timestamp RFC 3339 representable.
const maxYear = 9999

// SLADuration applies the local 7/30/90 elapsed-day policy to valid findings.
// The stricter of the severity label and the CVSS band wins.
func SLADuration(f Finding, isKEV bool) time.Duration {
	switch {
	case isKEV || f.Severity == "critical" || f.CVSS >= 9:
		return 7 * day
	case f.Severity == "high" || f.CVSS >= 7:
		return 30 * day
	default:
		return 90 * day
	}
}

// EvaluateSLA samples now exactly once. Callers supply trusted first-seen history.
func EvaluateSLA(f Finding, isKEV bool, now func() time.Time) (SLAResult, error) {
	if now == nil {
		return SLAResult{}, errors.New("vuln: nil clock")
	}
	if err := validateFinding(f); err != nil {
		return SLAResult{}, err
	}
	r, _, err := evaluate(f, isKEV, now())
	return r, err
}

// evaluate also returns the remediation duration for closed findings.
func evaluate(f Finding, isKEV bool, at time.Time) (SLAResult, time.Duration, error) {
	if at.IsZero() {
		return SLAResult{}, 0, errors.New("vuln: zero evaluation time")
	}
	if f.FirstSeen.After(at) {
		return SLAResult{}, 0, fmt.Errorf("finding %q: first seen after evaluation time", f.ID)
	}
	allowed := SLADuration(f, isKEV)
	due := f.FirstSeen.Add(allowed).UTC()
	if due.Year() > maxYear {
		return SLAResult{}, 0, fmt.Errorf("finding %q: due date beyond year %d", f.ID, maxYear)
	}
	r := SLAResult{Due: due, EvaluatedAt: at.UTC(), Allowed: allowed}
	if f.FixedAt == nil {
		r.Breached = at.After(due)
		return r, 0, nil
	}
	if f.FixedAt.After(at) {
		return SLAResult{}, 0, fmt.Errorf("finding %q: fixed after evaluation time", f.ID)
	}
	took := f.FixedAt.Sub(f.FirstSeen)
	// Sub saturates at ~292 years; a saturated value is not a measurement.
	if !f.FirstSeen.Add(took).Equal(*f.FixedAt) {
		return SLAResult{}, 0, fmt.Errorf("finding %q: remediation duration overflows", f.ID)
	}
	r.Closed = true
	r.Breached = f.FixedAt.After(due)
	return r, took, nil
}

// Summarize samples one clock for the cohort; invalid input yields no summary.
func Summarize(fs []Finding, kev map[string]bool, now func() time.Time) (Summary, error) {
	if now == nil {
		return Summary{}, errors.New("vuln: nil clock")
	}
	if err := ValidateInputs(fs, nil, kev); err != nil {
		return Summary{}, err
	}
	at := now()
	var s Summary
	var fixed []time.Duration
	for _, f := range fs {
		r, took, err := evaluate(f, kev[f.CVE], at)
		if err != nil {
			return Summary{}, err
		}
		switch {
		case r.Closed:
			s.FixedCount++
			fixed = append(fixed, took)
			if r.Breached {
				s.FixedBreaches++
			}
		default:
			s.OpenCount++
			if r.Breached {
				s.OpenBreaches++
			}
		}
	}
	if len(fixed) > 0 {
		sort.Slice(fixed, func(i, j int) bool { return fixed[i] < fixed[j] })
		mid := len(fixed) / 2
		s.MedianRemediation = fixed[mid]
		if len(fixed)%2 == 0 {
			lo := fixed[mid-1]
			s.MedianRemediation = lo + (fixed[mid]-lo)/2
		}
		s.HasMedian = true
	}
	return s, nil
}
