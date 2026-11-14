// Package vuln ranks caller-supplied findings and evaluates a local remediation
// policy. It does not authenticate discovery history or run a daily feed job.
package vuln

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"
)

// Finding identifies one occurrence of a vulnerability on a caller-owned asset.
// FirstSeen must come from trusted discovery history, never a feed timestamp.
type Finding struct {
	ID        string
	CVE       string
	Severity  string
	CVSS      float64
	Exposed   bool
	FirstSeen time.Time
	FixedAt   *time.Time
}

// Ranked preserves unknown EPSS separately from a known probability of zero.
type Ranked struct {
	Finding   Finding
	KEV       bool
	EPSS      float64
	EPSSKnown bool
}

const maxIDLen = 256

// cvePattern is the CVE JSON 5 schema's cveId pattern.
var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

var severities = map[string]bool{"": true, "none": true, "low": true, "medium": true, "high": true, "critical": true}

func validCVE(s string) bool { return cvePattern.MatchString(s) }

func validProbability(p float64) bool { return !math.IsNaN(p) && p >= 0 && p <= 1 }

func validateFinding(f Finding) error {
	switch {
	case f.ID == "" || len(f.ID) > maxIDLen:
		return fmt.Errorf("finding id must be 1-%d bytes", maxIDLen)
	case !validCVE(f.CVE):
		return fmt.Errorf("finding %q: malformed CVE %q", f.ID, f.CVE)
	case !severities[f.Severity]:
		return fmt.Errorf("finding %q: unknown severity %q", f.ID, f.Severity)
	case math.IsNaN(f.CVSS) || f.CVSS < 0 || f.CVSS > 10:
		return fmt.Errorf("finding %q: CVSS %v outside [0,10]", f.ID, f.CVSS)
	case f.FirstSeen.IsZero():
		return fmt.Errorf("finding %q: missing first-seen time", f.ID)
	case f.FixedAt != nil && f.FixedAt.Before(f.FirstSeen):
		return fmt.Errorf("finding %q: fixed before first seen", f.ID)
	}
	return nil
}

// ValidateInputs reports malformed findings and enrichment maps.
func ValidateInputs(fs []Finding, epss map[string]float64, kev map[string]bool) error {
	seen := make(map[string]bool, len(fs))
	for _, f := range fs {
		if err := validateFinding(f); err != nil {
			return err
		}
		if seen[f.ID] {
			return fmt.Errorf("duplicate finding id %q", f.ID)
		}
		seen[f.ID] = true
	}
	for cve, p := range epss {
		if !validCVE(cve) {
			return fmt.Errorf("EPSS key %q is not a CVE", cve)
		}
		if !validProbability(p) {
			return fmt.Errorf("EPSS %s=%v outside [0,1]", cve, p)
		}
	}
	for cve := range kev {
		if !validCVE(cve) {
			return fmt.Errorf("KEV key %q is not a CVE", cve)
		}
	}
	return nil
}

// Prioritize returns a copied, stable ordering: KEV, EPSS, CVSS, then exposure.
// Invalid inputs return nil; call ValidateInputs first to distinguish errors
// from an empty input. Bare maps cannot carry or establish feed freshness.
func Prioritize(fs []Finding, epss map[string]float64, kev map[string]bool) []Ranked {
	if ValidateInputs(fs, epss, kev) != nil {
		return nil
	}
	out := make([]Ranked, len(fs))
	for i, f := range fs {
		if f.FixedAt != nil {
			t := *f.FixedAt
			f.FixedAt = &t
		}
		p, known := epss[f.CVE]
		out[i] = Ranked{Finding: f, KEV: kev[f.CVE], EPSS: p, EPSSKnown: known}
	}
	// Unknown EPSS sorts as 0: there is no hidden "known" dimension.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.Finding.CVSS != b.Finding.CVSS {
			return a.Finding.CVSS > b.Finding.CVSS
		}
		return a.Finding.Exposed && !b.Finding.Exposed
	})
	return out
}
