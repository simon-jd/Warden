// Package dns_exfil scores trusted per-run DNS observations.
// This preparation contains the intentional RED stub, not an implemented detector.
package dns_exfil

import "time"

// Query identity and time must be supplied by a trusted collector, not DNS data.
// QType is the numeric DNS question type (TXT is 16); all nonzero types count.
type Query struct {
	TenantID   string
	RunID      string
	Name       string
	QType      uint16
	ObservedAt time.Time
}

// Alert describes the earliest qualifying (WindowStart, WindowEnd] window.
// MeanEntropy is the arithmetic mean of per-query subdomain Shannon entropy.
type Alert struct {
	TenantID    string
	RunID       string
	WindowStart time.Time
	WindowEnd   time.Time
	QueryCount  int
	MeanEntropy float64
}

// Score will reject empty, malformed or mixed-identity batches with nil.
// The collector must report invalid/dropped telemetry separately. The intended
// rule is strictly more than 30 questions in a rolling 60 seconds AND mean
// subdomain entropy strictly greater than 3.5 bits/character. No DNS is performed.
//
// Deliberate semantic stub for the first real RED: it detects nothing. Do not
// deploy or interpret nil from this preparation as evidence that traffic is safe.
func Score(queries []Query) *Alert {
	return nil
}
