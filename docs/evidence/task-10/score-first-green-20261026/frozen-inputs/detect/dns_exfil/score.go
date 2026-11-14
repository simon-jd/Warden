// Package dns_exfil scores trusted per-run DNS observations without network I/O.
package dns_exfil

import (
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

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

type observation struct {
	at      time.Time
	entropy float64
}

// Score returns an alert only when a single tenant/run has strictly more than
// 30 questions in a rolling 60 seconds AND mean subdomain entropy strictly
// greater than 3.5 bits/character. Repeated questions and all nonzero QTypes count.
//
// Empty, malformed or mixed-identity batches return nil. The entire batch is
// validated before scoring; the collector must report rejected/lost telemetry
// separately. Names use ASCII LDH labels, case folding and one optional root dot.
// The pinned public suffix list includes private suffixes. Registrable-domain
// labels and dots do not contribute to subdomain entropy; no subdomain means zero.
//
// Score owns its sorted copy and considers whole groups of equal timestamps.
// Both arrivals and expirations can change a window; it checks these events in
// the observed interval, without predicting times beyond the last observation.
// This is a heuristic, not proof of exfiltration or a network enforcement rule.
func Score(queries []Query) *Alert {
	if len(queries) == 0 || queries[0].TenantID == "" || queries[0].RunID == "" {
		return nil
	}
	tenant, run := queries[0].TenantID, queries[0].RunID
	samples := make([]observation, len(queries))
	for i, query := range queries {
		if query.TenantID != tenant || query.RunID != run || query.QType == 0 || query.ObservedAt.IsZero() {
			return nil
		}
		entropy, valid := nameEntropy(query.Name)
		if !valid {
			return nil
		}
		// UTC strips monotonic readings so order uses trusted observation time
		// consistently, including batches containing deserialized timestamps.
		samples[i] = observation{at: query.ObservedAt.UTC(), entropy: entropy}
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].at.Equal(samples[j].at) {
			// Deterministic floating-point accumulation for reordered ties.
			return samples[i].entropy < samples[j].entropy
		}
		return samples[i].at.Before(samples[j].at)
	})

	left, right := 0, 0
	var sum, correction float64
	// Compensated updates limit rounding drift as the window advances.
	add := func(value float64) {
		y := value - correction
		next := sum + y
		correction = (next - sum) - y
		sum = next
	}
	for right < len(samples) {
		end := samples[right].at
		if left < right {
			expires := samples[left].at.Add(time.Minute)
			if expires.Before(end) {
				end = expires
			}
		}
		start := end.Add(-time.Minute)
		for left < right && !samples[left].at.After(start) {
			add(-samples[left].entropy)
			left++
		}
		if left == right {
			sum, correction = 0, 0
		}
		// Include every observation at end before checking either threshold.
		for right < len(samples) && !samples[right].at.After(end) {
			add(samples[right].entropy)
			right++
		}
		count := right - left
		if count > 30 {
			mean := sum / float64(count)
			if mean > 3.5 {
				return &Alert{TenantID: tenant, RunID: run, WindowStart: start, WindowEnd: end, QueryCount: count, MeanEntropy: mean}
			}
		}
	}
	return nil
}

func nameEntropy(raw string) (float64, bool) {
	name := strings.TrimSuffix(raw, ".")
	// A dotted presentation name without the terminal dot uses two fewer
	// bytes than its DNS wire encoding (label lengths plus terminal zero).
	if len(name) == 0 || len(name) > 253 {
		return 0, false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return 0, false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return 0, false
			}
		}
	}
	// Validate ASCII before folding: Unicode characters must not fold into LDH.
	name = strings.ToLower(name)
	if _, err := netip.ParseAddr(name); err == nil {
		return 0, false
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return 0, false
	}
	if name == registrable {
		return 0, true
	}
	subdomain := strings.TrimSuffix(name, "."+registrable)
	var counts [128]int
	total := 0
	for i := 0; i < len(subdomain); i++ {
		if subdomain[i] != '.' {
			counts[subdomain[i]]++
			total++
		}
	}
	if total == 0 {
		return 0, true
	}
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy, true
}
