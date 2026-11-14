package dns_exfil_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"warden/detect/dns_exfil"
)

// These are scoring-component tests, not the original full Task10 transport,
// collector, Envoy, Cilium or runc acceptance tests. No external DNS is queried.
var scoreEpoch = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)

const balanced32 = "abcdefghijklmnopqrstuvwxyz234567"

func observations(name string, n int, step time.Duration) []dns_exfil.Query {
	out := make([]dns_exfil.Query, n)
	for i := range out {
		out[i] = dns_exfil.Query{TenantID: "tenant-a", RunID: "run-a", Name: name, QType: 16, ObservedAt: scoreEpoch.Add(time.Duration(i) * step)}
	}
	return out
}

// Fixture-only reference: sorted runs, not the production histogram algorithm.
func referenceEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	b := []byte(s)
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	var h float64
	for i := 0; i < len(b); {
		j := i + 1
		for j < len(b) && b[j] == b[i] {
			j++
		}
		p := float64(j-i) / float64(len(b))
		h -= p * math.Log2(p)
		i = j
	}
	return h
}

func legalFixtureName(t *testing.T, name string) {
	t.Helper()
	if len(name) > 253 || strings.HasSuffix(name, ".") {
		t.Fatalf("illegal fixture name length/form: %q", name)
	}
	wireBytes := 1
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			t.Fatalf("illegal fixture label: %q", label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				t.Fatalf("illegal fixture character: %q", c)
			}
		}
		wireBytes += 1 + len(label)
	}
	if wireBytes > 255 {
		t.Fatalf("fixture exceeds DNS wire name limit: %d", wireBytes)
	}
}

func requireAlert(t *testing.T, q []dns_exfil.Query, count int, end time.Time, entropy float64) {
	t.Helper()
	got := dns_exfil.Score(q)
	if got == nil {
		t.Fatal("expected DNS score alert, got nil")
	}
	if got.TenantID != "tenant-a" || got.RunID != "run-a" || got.QueryCount != count || !got.WindowEnd.Equal(end) || !got.WindowStart.Equal(end.Add(-time.Minute)) {
		t.Fatalf("wrong earliest window/identity: %+v", got)
	}
	if math.IsNaN(got.MeanEntropy) || math.IsInf(got.MeanEntropy, 0) || math.Abs(got.MeanEntropy-entropy) > 1e-12 {
		t.Fatalf("mean entropy = %.16g, want %.16g", got.MeanEntropy, entropy)
	}
}

func requireNoAlert(t *testing.T, q []dns_exfil.Query) {
	t.Helper()
	if got := dns_exfil.Score(q); got != nil {
		t.Fatalf("unexpected alert: %+v", got)
	}
}

func TestDNSScoreTXT4KiBAlert(t *testing.T) {
	const suffix = ".exfil.example.com"
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	payload := make([]byte, 0, 4096)
	q := make([]dns_exfil.Query, 0, 128)
	var reconstructed []byte
	var firstMean float64
	for i := 0; i < 128; i++ {
		block := sha256.Sum256([]byte(fmt.Sprintf("warden-task10-payload-%03d", i)))
		payload = append(payload, block[:]...)
		label := strings.ToLower(encoding.EncodeToString(block[:]))
		name := label + suffix
		legalFixtureName(t, name)
		decoded, err := encoding.DecodeString(strings.ToUpper(strings.TrimSuffix(name, suffix)))
		if err != nil {
			t.Fatal(err)
		}
		reconstructed = append(reconstructed, decoded...)
		// Registrable suffix is example.com: the entropy includes label+exfil.
		h := referenceEntropy(label + "exfil")
		if h <= 3.5 {
			t.Fatalf("fixture question %d lacks required entropy: %g", i, h)
		}
		if i < 31 {
			firstMean += h / 31
		}
		q = append(q, dns_exfil.Query{TenantID: "tenant-a", RunID: "run-a", Name: name, QType: 16, ObservedAt: scoreEpoch.Add(time.Duration(i) * 250 * time.Millisecond)})
	}
	if len(payload) != 4096 || !bytes.Equal(payload, reconstructed) || len(q) <= 30 || q[len(q)-1].ObservedAt.Sub(q[0].ObservedAt) >= time.Minute || firstMean <= 3.5 {
		t.Fatal("fixture does not demonstrate intact 4096-byte legal TXT-question stream")
	}
	t.Logf("SCORING_FIXTURE_OK payload_bytes=%d queries=%d span=%s first31_mean=%.12f", len(payload), len(q), q[len(q)-1].ObservedAt.Sub(q[0].ObservedAt), firstMean)
	requireAlert(t, q, 31, q[30].ObservedAt, firstMean)
}

func TestDNSScoreNormalCDNNoAlert(t *testing.T) {
	for _, name := range []string{"d111111abcdef8.cloudfront.net", "a1.g.akamaiedge.net", "assets.example.com", "www.example.co.uk"} {
		t.Run(name, func(t *testing.T) {
			legalFixtureName(t, name)
			requireNoAlert(t, observations(name, 80, 250*time.Millisecond))
		})
	}
	// High entropy without the required rate is also normal under this rule.
	requireNoAlert(t, observations(balanced32+".example.com", 30, time.Second))
}

func TestDNSScoreStrictCountAndRepeatedAllTypes(t *testing.T) {
	q := observations(balanced32+".example.com", 31, time.Second)
	requireNoAlert(t, q[:30])
	for i := range q {
		q[i].QType = []uint16{1, 16, 28, 255}[i%4]
	}
	// Identical names are distinct observed questions, not deduplicated names.
	requireAlert(t, q, 31, q[30].ObservedAt, 5)
}

func TestDNSScoreStrictEntropyAndPerQueryMean(t *testing.T) {
	const exact = "aabbccdde fghijkl"
	threshold := strings.ReplaceAll(exact, " ", "")
	if referenceEntropy(threshold) != 3.5 {
		t.Fatal("threshold fixture must have exact entropy 3.5")
	}
	q := observations(threshold+".example.com", 31, time.Second)
	requireNoAlert(t, q)
	q[30].Name = "abcdefghijklmnop.example.com"
	requireAlert(t, q, 31, q[30].ObservedAt, (30*3.5+4)/31)
	// Long high-entropy query must not outweigh 30 short low-entropy queries.
	q = observations("a.example.com", 31, time.Second)
	long := strings.Repeat(balanced32, 6)
	q[30].Name = strings.Join([]string{long[:48], long[48:96], long[96:144], long[144:]}, ".") + ".example.com"
	legalFixtureName(t, q[30].Name)
	requireNoAlert(t, q)
}

func TestDNSScoreSlidingWindowBoundary(t *testing.T) {
	q := observations(balanced32+".example.com", 31, 0)
	q[30].ObservedAt = scoreEpoch.Add(time.Minute)
	requireNoAlert(t, q) // lower bound is open: 30 queries at t=0 are excluded.
	q[30].ObservedAt = scoreEpoch.Add(time.Minute - time.Nanosecond)
	requireAlert(t, q, 31, q[30].ObservedAt, 5)
	// Cross a fixed wall-clock minute boundary: this must still be one window.
	q = observations(balanced32+".example.com", 31, time.Second)
	for i := range q {
		q[i].ObservedAt = q[i].ObservedAt.Add(45 * time.Second)
	}
	requireAlert(t, q, 31, q[30].ObservedAt, 5)
}

func TestDNSScoreCanonicalSuffixAndNoCDNExemption(t *testing.T) {
	for _, name := range []string{
		strings.ToUpper(balanced32) + ".EXAMPLE.CO.UK.",
		"abcdefghijklmnop.qrstuvwxyz234567.example.com",
		balanced32 + ".customer.cloudfront.net",
	} {
		t.Run(name, func(t *testing.T) {
			q := observations(name, 31, time.Second)
			requireAlert(t, q, 31, q[30].ObservedAt, 5)
		})
	}
	// A high-entropy registrable label itself is not a subdomain.
	requireNoAlert(t, observations(balanced32+".co.uk", 31, time.Second))
}

func TestDNSScoreEarliestWindowAndInputUnchanged(t *testing.T) {
	q := observations(balanced32+".example.com", 40, time.Second)
	for i, j := 0, len(q)-1; i < j; i, j = i+1, j-1 {
		q[i], q[j] = q[j], q[i]
	}
	before := append([]dns_exfil.Query(nil), q...)
	requireAlert(t, q, 31, scoreEpoch.Add(30*time.Second), 5)
	if !reflect.DeepEqual(q, before) {
		t.Fatal("Score mutated its caller's observations")
	}
}

func TestDNSScoreRejectsInvalidOrMixedBatch(t *testing.T) {
	requireNoAlert(t, nil)
	cases := map[string]func(*dns_exfil.Query){
		"mixed tenant": func(q *dns_exfil.Query) { q.TenantID = "tenant-b" },
		"mixed run":    func(q *dns_exfil.Query) { q.RunID = "run-b" },
		"empty tenant": func(q *dns_exfil.Query) { q.TenantID = "" },
		"empty run":    func(q *dns_exfil.Query) { q.RunID = "" },
		"zero time":    func(q *dns_exfil.Query) { q.ObservedAt = time.Time{} },
		"zero qtype":   func(q *dns_exfil.Query) { q.QType = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := observations(balanced32+".example.com", 40, time.Second)
			// Invalid trusted metadata after a crossing rejects the whole batch.
			mutate(&q[len(q)-1])
			requireNoAlert(t, q)
			q[0].Name = "bad..name"
			got := dns_exfil.ScoreDetailed(q)
			if !got.InvalidMetadata || got.Alert != nil || len(got.RejectedNames) != 0 {
				t.Fatalf("metadata rejection confused with name rejection: %+v", got)
			}
		})
	}
}

func TestDNSScoreTimestampTiesUseCompleteWindow(t *testing.T) {
	q := observations(balanced32+".example.com", 31, 0)
	low := observations("a.example.com", 31, 0)
	q = append(q, low...)
	// All 62 observations share a timestamp: mean=2.5, regardless of order.
	requireNoAlert(t, q)
	for i, j := 0, len(q)-1; i < j; i, j = i+1, j-1 {
		q[i], q[j] = q[j], q[i]
	}
	requireNoAlert(t, q)
}

// R1 regression: legal DNS questions are untrusted input, and appending one
// must not erase an earlier qualifying window in the same trusted run.
func TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions(t *testing.T) {
	for _, name := range []string{"_dmarc.example.com", "com"} {
		t.Run(name, func(t *testing.T) {
			q := observations(balanced32+".example.com", 31, time.Second)
			end := q[30].ObservedAt
			// Healthy control calls the actual production API before augmentation.
			requireAlert(t, q, 31, end, 5)
			t.Log("R1_QUALIFYING_WINDOW_OK count=31 mean=5")
			q = append(q, dns_exfil.Query{
				TenantID: "tenant-a", RunID: "run-a", Name: name, QType: 16,
				ObservedAt: end.Add(time.Second),
			})
			// Same earliest window, identity, count and entropy must survive.
			requireAlert(t, q, 31, end, 5)
		})
	}
}

func TestDNSScoreRejectedNamesAreObservable(t *testing.T) {
	bad := []string{"", "abc..example.com", "abc.example.com..",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com",
		`abc\`, `abc\12.example.com`, `abc\999.example.com`}
	q := observations(balanced32+".example.com", 31, time.Second)
	want := make([]int, len(bad))
	for i, name := range bad {
		want[i] = len(q)
		next := q[0]
		next.Name, next.ObservedAt = name, scoreEpoch.Add(31*time.Second)
		q = append(q, next)
	}
	before := append([]dns_exfil.Query(nil), q...)
	requireAlert(t, q, 31, scoreEpoch.Add(30*time.Second), 5)
	got := dns_exfil.ScoreDetailed(q)
	if got.InvalidMetadata || !reflect.DeepEqual(got.RejectedNames, want) || !reflect.DeepEqual(got.Alert, dns_exfil.Score(q)) || !reflect.DeepEqual(q, before) {
		t.Fatalf("lost diagnostics, alert or input immutability: %+v", got)
	}
	// Names alone cannot create a count crossing; every rejection is observable.
	for _, name := range bad {
		q = observations(name, 31, 0)
		got = dns_exfil.ScoreDetailed(q)
		if got.InvalidMetadata || got.Alert != nil || len(got.RejectedNames) != 31 {
			t.Fatalf("rejected name %q produced wrong result: %+v", name, got)
		}
	}
	if got := dns_exfil.ScoreDetailed(nil); got.InvalidMetadata || got.Alert != nil || len(got.RejectedNames) != 0 {
		t.Fatalf("empty batch is not invalid telemetry: %+v", got)
	}
	// A rejected final name still supplies a trusted observed horizon: the
	// qualifying expiration at t=60 must not disappear when no valid name follows.
	q = observations("a.example.com", 31, 0)
	hi := observations(balanced32+".example.com", 31, 0)
	for i := range hi {
		hi[i].ObservedAt = scoreEpoch.Add(30 * time.Second)
	}
	q = append(q, hi...)
	last := q[0]
	last.Name, last.ObservedAt = "bad..name", scoreEpoch.Add(61*time.Second)
	q = append(q, last)
	requireAlert(t, q, 31, scoreEpoch.Add(time.Minute), 5)
	got = dns_exfil.ScoreDetailed(q)
	if got.InvalidMetadata || !reflect.DeepEqual(got.RejectedNames, []int{62}) {
		t.Fatalf("rejected endpoint diagnostic: %+v", got)
	}
}

func TestDNSScoreQuestionSyntaxAndSuffix(t *testing.T) {
	// DNS questions need not be hostnames. These all count with zero or low
	// entropy, including root/public-suffix names with no registrable subdomain.
	for _, name := range []string{".", "com", "co.uk.", "_dmarc.example.com", "-abc.example.com", "abc-.example.com", " abc.example.com", "é.example.com", "127.0.0.1",
		strings.Repeat(`\097`, 63) + ".example.com",
		strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61)} {
		q := observations(name, 1, 0)
		got := dns_exfil.ScoreDetailed(q)
		if got.InvalidMetadata || len(got.RejectedNames) != 0 || got.Alert != nil {
			t.Fatalf("legal question %q rejected: %+v", name, got)
		}
		// The legal question must count, not be silently skipped.
		q = append(q, observations(balanced32+".example.com", 30, 0)...)
		if got := dns_exfil.Score(q); got == nil || got.QueryCount != 31 {
			t.Fatalf("legal question %q did not count: %+v", name, got)
		}
	}
	for _, name := range []string{".", "com", "co.uk.", balanced32 + ".co.uk"} {
		requireNoAlert(t, observations(name, 31, 0))
	}
	// Decimal and character escapes decode before ASCII folding and entropy.
	q := observations(`\065bcdefghijklmnopqrstuvwxyz234567.example.com`, 31, 0)
	requireAlert(t, q, 31, scoreEpoch, 5)
	q = observations(balanced32+`\.x.example.com`, 31, 0)
	requireAlert(t, q, 31, scoreEpoch, referenceEntropy(balanced32+".x"))
	// Escaped dots inside a registrable label are data, never suffix separators.
	q = observations(balanced32+`\.x.com`, 31, 0)
	requireNoAlert(t, q)
}

func TestDNSScoreExpirationOnlyCrossing(t *testing.T) {
	for _, n := range []int{31, 30} {
		t.Run(fmt.Sprintf("high_count_%d", n), func(t *testing.T) {
			q := observations("a.example.com", 31, 0)
			hi := observations(balanced32+".example.com", n, 0)
			for i := range hi {
				hi[i].ObservedAt = scoreEpoch.Add(30 * time.Second)
			}
			q = append(q, hi...)
			requireNoAlert(t, q) // observed interval ends at t=30, mean <= 2.5.
			last := q[0]
			last.ObservedAt = scoreEpoch.Add(61 * time.Second)
			q = append(q, last)
			if n == 31 {
				requireAlert(t, q, 31, scoreEpoch.Add(time.Minute), 5)
			} else {
				// At t=60 only 30 remain: the final question crosses count at t=61.
				requireAlert(t, q, 31, last.ObservedAt, 150.0/31)
			}
		})
	}
}

// R2: bounded resource regression, not an OOM/stress or transport test.
func TestDNSScoreManyShortLabelsBoundedAllocation(t *testing.T) {
	legal := observations(strings.Repeat("a.", 127), 1, 0)
	got := dns_exfil.ScoreDetailed(legal)
	if got.InvalidMetadata || got.Alert != nil || len(got.RejectedNames) != 0 {
		t.Fatalf("legal 255-byte wire name rejected: %+v", got)
	}
	t.Log("I2_LEGAL_BOUNDARY_OK wire_bytes=255 labels=127")
	// Build the 6KiB malformed input outside the allocation measurement. Two
	// octets per label avoid runtime single-byte-string interning hiding growth.
	q := observations(strings.Repeat("ab.", 2048), 1, 0)
	got = dns_exfil.ScoreDetailed(q)
	if got.InvalidMetadata || got.Alert != nil || !reflect.DeepEqual(got.RejectedNames, []int{0}) {
		t.Fatalf("oversized-name rejection diagnostic missing: %+v", got)
	}
	t.Log("I2_REJECTION_BASELINE_OK labels=2048 input_bytes=6144")
	allocs := testing.AllocsPerRun(5, func() {
		got = dns_exfil.ScoreDetailed(q)
	})
	if got.InvalidMetadata || got.Alert != nil || !reflect.DeepEqual(got.RejectedNames, []int{0}) {
		t.Fatalf("measured call lost rejection diagnostic: %+v", got)
	}
	// A legal DNS name has at most 127 labels. This constant budget allows
	// several allocations per legal label plus bookkeeping, independent of
	// attacker-supplied label count; it does not require an exact algorithm.
	if allocs > 512 {
		t.Fatalf("I2_NAME_ALLOCATION_UNBOUNDED allocs_per_call=%.0f limit=512 input_bytes=%d", allocs, len(q[0].Name))
	}
	t.Logf("I2_NAME_ALLOCATION_BOUNDED allocs_per_call=%.0f limit=512", allocs)
}
