// Package dns_exfil scores trusted per-run DNS observations without network I/O.
package dns_exfil

import (
	"math"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Query identity and time must be supplied by a trusted collector, not DNS data.
// QType is the numeric DNS question type (TXT is 16); all nonzero types count.
// Name is a DNS presentation name: dots separate labels, a final dot is optional,
// and backslash escapes encode one character or exactly three decimal digits.
// Labels contain octets (including UTF-8 bytes); no implicit IDNA conversion.
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
// Empty batches return nil. Invalid identity/time/QType rejects the whole batch;
// malformed names are excluded without erasing valid evidence. Call ScoreDetailed
// to observe both conditions. ASCII case folding precedes entropy calculation.
// The pinned public suffix list includes private suffixes. Registrable-domain
// labels and separator dots do not contribute to entropy. Root, public suffixes
// and names without subdomains have zero entropy, but count as questions.
//
// Score owns its sorted copy and considers whole groups of equal timestamps.
// Both arrivals and expirations can change a window; it checks these events in
// the observed interval, without predicting times beyond the last observation.
// This is a heuristic, not proof of exfiltration or a network enforcement rule.
func Score(queries []Query) *Alert {
	return ScoreDetailed(queries).Alert
}

// ScoreResult distinguishes invalid trusted metadata from rejected names.
// RejectedNames contains zero-based input indexes, even after an early alert.
// InvalidMetadata means no scoring or name classification was performed.
// A nil Alert alone does not imply complete or valid telemetry.
type ScoreResult struct {
	Alert           *Alert
	RejectedNames   []int
	InvalidMetadata bool
}

// ScoreDetailed validates all metadata before classifying untrusted names.
// Rejected names do not count or contribute entropy, but their trusted timestamps
// still bound the observed interval. This API reports diagnostics; it does not
// deliver them to a collector or monitoring system.
func ScoreDetailed(queries []Query) ScoreResult {
	var result ScoreResult
	if len(queries) == 0 {
		return result
	}
	tenant, run := queries[0].TenantID, queries[0].RunID
	until := queries[0].ObservedAt.UTC()
	for _, query := range queries {
		if tenant == "" || run == "" || query.TenantID != tenant || query.RunID != run || query.QType == 0 || query.ObservedAt.IsZero() {
			return ScoreResult{InvalidMetadata: true}
		}
		if query.ObservedAt.After(until) {
			until = query.ObservedAt.UTC()
		}
	}
	samples := make([]observation, 0, len(queries))
	for i, query := range queries {
		entropy, valid := nameEntropy(query.Name)
		if !valid {
			result.RejectedNames = append(result.RejectedNames, i)
			continue
		}
		// UTC strips monotonic readings so all ordering uses observation time.
		samples = append(samples, observation{at: query.ObservedAt.UTC(), entropy: entropy})
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
	for right < len(samples) || left < right && !samples[left].at.Add(time.Minute).After(until) {
		end := until
		if right < len(samples) {
			end = samples[right].at
		}
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
				result.Alert = &Alert{TenantID: tenant, RunID: run, WindowStart: start, WindowEnd: end, QueryCount: count, MeanEntropy: mean}
				return result
			}
		}
	}
	return result
}

// Decode DNS presentation syntax before applying label/wire-length limits.
func nameEntropy(raw string) (float64, bool) {
	if raw == "." {
		return 0, true
	}
	if raw == "" {
		return 0, false
	}
	// Wire length is checked per completed label, so an oversized name is
	// rejected after at most 255 bytes of label data and bounded allocations.
	var labels []string
	label := make([]byte, 0, 63)
	wireBytes := 1
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '.' {
			if len(label) == 0 {
				return 0, false
			}
			if wireBytes += len(label) + 1; wireBytes > 255 {
				return 0, false
			}
			labels = append(labels, string(label))
			label = label[:0]
			continue
		}
		if c == '\\' {
			i++
			if i == len(raw) {
				return 0, false
			}
			c = raw[i]
			if c >= '0' && c <= '9' {
				if i+2 >= len(raw) || raw[i+1] < '0' || raw[i+1] > '9' || raw[i+2] < '0' || raw[i+2] > '9' {
					return 0, false
				}
				n := int(c-'0')*100 + int(raw[i+1]-'0')*10 + int(raw[i+2]-'0')
				if n > 255 {
					return 0, false
				}
				c, i = byte(n), i+2
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		label = append(label, c)
		if len(label) > 63 {
			return 0, false
		}
	}
	if len(label) != 0 {
		if wireBytes += len(label) + 1; wireBytes > 255 {
			return 0, false
		}
		labels = append(labels, string(label))
	}
	lookup := make([]string, len(labels))
	for i, label := range labels {
		// An escaped dot is label data, never a PSL label separator. NUL cannot
		// match a literal PSL rule; wildcard rules still match this whole label.
		lookup[i] = strings.ReplaceAll(label, ".", "\x00")
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(strings.Join(lookup, "."))
	if err != nil {
		return 0, true // Root/TLD/public suffix has no registrable subdomain.
	}
	subdomains := len(labels) - strings.Count(registrable, ".") - 1
	var counts [256]int
	total := 0
	for _, label := range labels[:subdomains] {
		for i := 0; i < len(label); i++ {
			counts[label[i]]++
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
