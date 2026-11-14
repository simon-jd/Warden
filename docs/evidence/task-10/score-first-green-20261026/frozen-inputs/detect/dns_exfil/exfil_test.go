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
		"mixed run": func(q *dns_exfil.Query) { q.RunID = "run-b" },
		"empty tenant": func(q *dns_exfil.Query) { q.TenantID = "" },
		"empty run": func(q *dns_exfil.Query) { q.RunID = "" },
		"zero time": func(q *dns_exfil.Query) { q.ObservedAt = time.Time{} },
		"zero qtype": func(q *dns_exfil.Query) { q.QType = 0 },
		"empty name": func(q *dns_exfil.Query) { q.Name = "" },
		"empty label": func(q *dns_exfil.Query) { q.Name = "abc..example.com" },
		"double terminal dot": func(q *dns_exfil.Query) { q.Name += ".." },
		"overlong label": func(q *dns_exfil.Query) { q.Name = strings.Repeat("a", 64) + ".example.com" },
		"overlong name": func(q *dns_exfil.Query) { q.Name = strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com" },
		"unicode": func(q *dns_exfil.Query) { q.Name = "é.example.com" },
		"leading hyphen": func(q *dns_exfil.Query) { q.Name = "-abc.example.com" },
		"trailing hyphen": func(q *dns_exfil.Query) { q.Name = "abc-.example.com" },
		"whitespace": func(q *dns_exfil.Query) { q.Name = " abc.example.com" },
		"underscore": func(q *dns_exfil.Query) { q.Name = "_abc.example.com" },
		"no registrable domain": func(q *dns_exfil.Query) { q.Name = "co.uk" },
		"ip literal": func(q *dns_exfil.Query) { q.Name = "127.0.0.1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := observations(balanced32+".example.com", 40, time.Second)
			// Invalid input after a would-be crossing must reject the whole batch.
			mutate(&q[len(q)-1])
			requireNoAlert(t, q)
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
