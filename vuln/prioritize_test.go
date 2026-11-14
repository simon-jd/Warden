package vuln

// All findings, publications and HTTP responses here are synthetic
// fixtures. They are not live feed observations or remediation measurements.
import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func finding(id string, cvss float64) Finding {
	return Finding{ID: id, CVE: "CVE-2026-1234", CVSS: cvss, FirstSeen: fixtureNow.Add(-time.Hour)}
}
func rankedIDs(rs []Ranked) []string {
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.Finding.ID
	}
	return ids
}
func TestKEVRanksFirst(t *testing.T) {
	a, b := finding("kev", 1), finding("critical", 10)
	b.CVE, b.Exposed = "CVE-2026-9999", true
	got := Prioritize([]Finding{b, a}, map[string]float64{a.CVE: 0.01, b.CVE: 1}, map[string]bool{a.CVE: true})
	if !reflect.DeepEqual(rankedIDs(got), []string{"kev", "critical"}) {
		t.Fatalf("KEV must dominate other dimensions: %+v", got)
	}
}
func TestEPSSBreaksTies(t *testing.T) {
	a, b := finding("epss", 1), finding("cvss", 10)
	b.CVE, b.Exposed = "CVE-2026-9999", true
	got := Prioritize([]Finding{b, a}, map[string]float64{a.CVE: 0.8, b.CVE: 0.2}, nil)
	if !reflect.DeepEqual(rankedIDs(got), []string{"epss", "cvss"}) {
		t.Fatalf("EPSS must precede CVSS and exposure: %+v", got)
	}
}
func TestComparatorStabilityAndCopies(t *testing.T) {
	a, b, c, d := finding("low", 5), finding("hidden", 8), finding("exposed-first", 8), finding("exposed-second", 8)
	c.Exposed, d.Exposed = true, true
	fixed := fixtureNow
	c.FixedAt = &fixed
	input := []Finding{a, b, c, d}
	out := Prioritize(input, nil, nil)
	if !reflect.DeepEqual(rankedIDs(out), []string{"exposed-first", "exposed-second", "hidden", "low"}) {
		t.Fatalf("CVSS/exposure/stable ties: %+v", out)
	}
	if input[0].ID != "low" || out[0].Finding.FixedAt == input[2].FixedAt {
		t.Fatal("ranking must copy slice and FixedAt")
	}
	*out[0].Finding.FixedAt = fixtureNow.Add(-time.Minute)
	if !input[2].FixedAt.Equal(fixtureNow) {
		t.Fatal("output aliased source time pointer")
	}
	known, unknown := finding("known-zero", 5), finding("unknown", 5)
	unknown.CVE = "CVE-2026-9999"
	out = Prioritize([]Finding{unknown, known}, map[string]float64{known.CVE: 0}, nil)
	if len(out) != 2 || out[0].EPSSKnown || !out[1].EPSSKnown || out[0].EPSS != 0 || out[1].EPSS != 0 {
		t.Fatalf("unknown must remain distinct without a hidden sort dimension: %+v", out)
	}
}
func TestInputValidation(t *testing.T) {
	good := finding("valid", 7)
	if err := ValidateInputs([]Finding{good}, nil, nil); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
	if err := ValidateInputs(nil, nil, nil); err != nil {
		t.Fatalf("empty valid: %v", err)
	}
	cases := []struct {
		name string
		fs   []Finding
		epss map[string]float64
		kev  map[string]bool
	}{
		{"duplicate-id", []Finding{good, good}, nil, nil},
		{"nan-epss", []Finding{good}, map[string]float64{good.CVE: math.NaN()}, nil},
		{"infinite-epss", []Finding{good}, map[string]float64{good.CVE: math.Inf(1)}, nil},
		{"negative-epss", []Finding{good}, map[string]float64{good.CVE: -0.1}, nil},
		{"high-epss", []Finding{good}, map[string]float64{good.CVE: 1.1}, nil},
		{"unused-bad-key", []Finding{good}, map[string]float64{"not-cve": 0.5}, nil},
		{"bad-kev-key", []Finding{good}, nil, map[string]bool{"not-cve": false}},
	}
	for _, change := range []struct {
		name  string
		apply func(*Finding)
	}{
		{"empty-id", func(f *Finding) { f.ID = "" }},
		{"long-id", func(f *Finding) { f.ID = strings.Repeat("a", 257) }},
		{"bad-cve", func(f *Finding) { f.CVE = "cve-2026-1234" }},
		{"short-cve", func(f *Finding) { f.CVE = "CVE-2026-123" }},
		{"long-cve", func(f *Finding) { f.CVE = "CVE-2026-" + strings.Repeat("1", 20) }},
		{"severity", func(f *Finding) { f.Severity = "urgent" }},
		{"negative-cvss", func(f *Finding) { f.CVSS = -1 }},
		{"high-cvss", func(f *Finding) { f.CVSS = 10.1 }},
		{"nan-cvss", func(f *Finding) { f.CVSS = math.NaN() }},
		{"zero-seen", func(f *Finding) { f.FirstSeen = time.Time{} }},
		{"fix-before-seen", func(f *Finding) { x := f.FirstSeen.Add(-time.Nanosecond); f.FixedAt = &x }},
	} {
		f := good
		change.apply(&f)
		cases = append(cases, struct {
			name string
			fs   []Finding
			epss map[string]float64
			kev  map[string]bool
		}{change.name, []Finding{f}, nil, nil})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateInputs(tc.fs, tc.epss, tc.kev); err == nil {
				t.Fatal("invalid data accepted")
			}
			if got := Prioritize(tc.fs, tc.epss, tc.kev); got != nil {
				t.Fatalf("invalid input must return nil: %+v", got)
			}
		})
	}
	long := good
	long.CVE = "CVE-2026-1234567890123456789"
	if err := ValidateInputs([]Finding{long}, nil, nil); err != nil {
		t.Fatalf("schema maximum CVE rejected: %v", err)
	}
}

func TestSLABreachDetected(t *testing.T) {
	f := finding("sla", 5)
	f.FirstSeen = fixtureNow.Add(-7 * 24 * time.Hour)
	fake := fixtureNow
	calls := 0
	clock := func() time.Time { calls++; return fake }
	r, err := EvaluateSLA(f, true, clock)
	if err != nil || r.Breached || !r.Due.Equal(fixtureNow) || calls != 1 {
		t.Fatalf("inclusive due/fake clock: %+v %v calls=%d", r, err, calls)
	}
	fake = fake.Add(time.Nanosecond)
	calls = 0
	r, err = EvaluateSLA(f, true, clock)
	if err != nil || !r.Breached || r.Closed || calls != 1 {
		t.Fatalf("open breach after due: %+v %v calls=%d", r, err, calls)
	}
	fixed := fixtureNow
	f.FixedAt = &fixed
	r, err = EvaluateSLA(f, true, clock)
	if err != nil || r.Breached || !r.Closed {
		t.Fatalf("fixed exactly due meets: %+v %v", r, err)
	}
	fixed = fixed.Add(time.Nanosecond)
	r, err = EvaluateSLA(f, true, clock)
	if err != nil || !r.Breached || !r.Closed {
		t.Fatalf("fixed after due is closed breach: %+v %v", r, err)
	}
}
func TestSLAPolicyAndInvalidTimes(t *testing.T) {
	for _, tc := range []struct {
		severity string
		cvss     float64
		kev      bool
		days     int
	}{
		{"", 0, false, 90}, {"low", 6.99, false, 90}, {"medium", 7, false, 30},
		{"", 8.99, false, 30}, {"", 9, false, 7}, {"critical", 1, false, 7},
		{"high", 1, false, 30}, {"high", 10, false, 7}, {"low", 0, true, 7},
	} {
		f := finding("policy", tc.cvss)
		f.Severity = tc.severity
		if got := SLADuration(f, tc.kev); got != time.Duration(tc.days)*24*time.Hour {
			t.Errorf("policy %+v got %s", tc, got)
		}
	}
	// A fixed offset zone change must not turn elapsed-day policy into calendar days.
	f := finding("elapsed", 9)
	f.FirstSeen = time.Date(2026, 10, 31, 12, 0, 0, 0, time.FixedZone("before-DST", -7*3600))
	at := f.FirstSeen.Add(7 * 24 * time.Hour)
	r, err := EvaluateSLA(f, false, func() time.Time { return at.In(time.FixedZone("after-DST", -8*3600)) })
	if err != nil || r.Breached || r.Due.Sub(f.FirstSeen) != 168*time.Hour || r.Due.Location() != time.UTC {
		t.Fatalf("elapsed hours/UTC: %+v %v", r, err)
	}
	for _, tc := range []struct {
		name string
		f    Finding
		at   time.Time
	}{
		{"future-seen", finding("future", 1), fixtureNow.Add(-2 * time.Hour)},
		{"zero-clock", finding("zero", 1), time.Time{}},
		{"due-overflow", Finding{ID: "overflow", CVE: "CVE-2026-1234", FirstSeen: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)}, time.Date(9999, 12, 31, 1, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EvaluateSLA(tc.f, false, func() time.Time { return tc.at }); err == nil {
				t.Fatal("invalid temporal input accepted")
			}
		})
	}
	f = finding("future-fix", 1)
	x := fixtureNow.Add(time.Hour)
	f.FixedAt = &x
	if _, err := EvaluateSLA(f, false, func() time.Time { return fixtureNow }); err == nil {
		t.Fatal("future fix accepted")
	}
	if _, err := EvaluateSLA(finding("nil-clock", 1), false, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	f = finding("saturated-duration", 1)
	f.FirstSeen = time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
	x = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	f.FixedAt = &x
	if _, err := EvaluateSLA(f, false, func() time.Time { return fixtureNow }); err == nil {
		t.Fatal("saturated remediation duration accepted")
	}
}
func TestSummaryCohortMedian(t *testing.T) {
	fs := make([]Finding, 4)
	for i, hours := range []int{2, 8, 4, 6} {
		fs[i] = finding(fmt.Sprint(i), 9)
		fs[i].FirstSeen = fixtureNow.Add(-10 * 24 * time.Hour)
		x := fs[i].FirstSeen.Add(time.Duration(hours) * time.Hour)
		fs[i].FixedAt = &x
	}
	open := finding("open", 1)
	open.FirstSeen = fixtureNow.Add(-8 * 24 * time.Hour)
	open.CVE = "CVE-2026-9999"
	fs = append(fs, open)
	late := finding("late", 9)
	late.FirstSeen = fixtureNow.Add(-10 * 24 * time.Hour)
	fixed := fixtureNow
	late.FixedAt = &fixed
	calls := 0
	clock := func() time.Time { calls++; return fixtureNow }
	s, err := Summarize(fs, map[string]bool{open.CVE: true}, clock)
	if err != nil || calls != 1 || s.OpenCount != 1 || s.FixedCount != 4 || s.OpenBreaches != 1 || s.FixedBreaches != 0 || !s.HasMedian || s.MedianRemediation != 5*time.Hour {
		t.Fatalf("cohort/even median/clock: %+v %v calls=%d", s, err, calls)
	}
	s, err = Summarize(append(fs, late), nil, clock)
	if err != nil || s.FixedBreaches != 1 || s.OpenBreaches != 0 || s.MedianRemediation != 6*time.Hour {
		t.Fatalf("odd median/closed breach: %+v %v", s, err)
	}
	s, err = Summarize(nil, nil, clock)
	if err != nil || s.HasMedian || s.FixedCount != 0 {
		t.Fatalf("no invented median: %+v %v", s, err)
	}
	zero := finding("instant", 1)
	x := zero.FirstSeen
	zero.FixedAt = &x
	s, err = Summarize([]Finding{zero}, nil, clock)
	if err != nil || !s.HasMedian || s.MedianRemediation != 0 {
		t.Fatalf("instant remediation: %+v %v", s, err)
	}
	bad := open
	bad.ID = ""
	if s, err := Summarize([]Finding{late, bad}, nil, clock); err == nil || s != (Summary{}) {
		t.Fatalf("invalid batch cannot yield partial metrics: %+v %v", s, err)
	}
}

func gzipFixture(t *testing.T, csv string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(csv)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func epssCSV() string {
	return "#model_version:v2026.01.01,score_date:2026-10-25\ncve,epss,percentile\nCVE-2026-1234,0.7,0.95\nCVE-2026-9999,0,0.01\n"
}
func kevJSON(t *testing.T) []byte {
	t.Helper()
	entry := map[string]any{"cveID": "CVE-2026-1234", "vendorProject": "Fixture vendor", "product": "Fixture product", "vulnerabilityName": "Fixture only", "dateAdded": "2026-10-24", "shortDescription": "Synthetic fixture", "requiredAction": "Fixture action", "dueDate": "2026-10-31"}
	b, err := json.Marshal(map[string]any{"catalogVersion": "fixture-1", "dateReleased": "2026-10-25T00:00:00Z", "count": 1, "vulnerabilities": []any{entry}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestFeedParsersAndFreshness(t *testing.T) {
	raw := gzipFixture(t, epssCSV())
	e, err := ParseEPSS(bytes.NewReader(raw), EPSSURL, fixtureNow)
	if err != nil || e.Scores["CVE-2026-1234"] != 0.7 || e.Model != "v2026.01.01" || e.Source != EPSSURL || !e.RetrievedAt.Equal(fixtureNow) {
		t.Fatalf("EPSS fixture: %+v %v", e, err)
	}
	if err := e.Fresh(fixtureNow); err != nil {
		t.Fatalf("fresh publication: %v", err)
	}
	reordered := "\ufeff#model_version:v2026.01.01,score_date:2026-10-25\r\npercentile,cve,epss\r\n0.95,CVE-2026-1234,0.7\r\n"
	if _, err := ParseEPSS(bytes.NewReader(gzipFixture(t, reordered)), EPSSURL, fixtureNow); err != nil {
		t.Fatalf("BOM/CRLF/header order: %v", err)
	}
	k, err := ParseKEV(bytes.NewReader(kevJSON(t)), KEVURL, fixtureNow)
	if err != nil || !k.CVEs["CVE-2026-1234"] || k.Count != 1 || k.Source != KEVURL || k.CatalogVersion != "fixture-1" {
		t.Fatalf("KEV fixture: %+v %v", k, err)
	}
	if err := k.Fresh(fixtureNow); err != nil {
		t.Fatalf("fresh KEV: %v", err)
	}
	old := bytes.ReplaceAll(kevJSON(t), []byte("2026-10"), []byte("2020-10"))
	k, err = ParseKEV(bytes.NewReader(old), KEVURL, fixtureNow)
	if err != nil || k.Fresh(fixtureNow) != nil {
		t.Fatalf("unchanged old KEV may be freshly retrieved: %+v %v", k, err)
	}
	for _, age := range []time.Duration{48 * time.Hour, 48*time.Hour + time.Nanosecond} {
		k.RetrievedAt = fixtureNow.Add(-age)
		if got := k.Fresh(fixtureNow); (got == nil) != (age == 48*time.Hour) {
			t.Fatalf("retrieval age boundary %s: %v", age, got)
		}
	}
	oldEPSS := strings.Replace(epssCSV(), "score_date:2026-10-25", "score_date:2026-10-20", 1)
	e, err = ParseEPSS(bytes.NewReader(gzipFixture(t, oldEPSS)), EPSSURL, fixtureNow)
	if err != nil || e.Fresh(fixtureNow) == nil {
		t.Fatalf("fresh retrieval must not rescue old publication: %+v %v", e, err)
	}
}
func TestEPSSRejectsMalformedFixtures(t *testing.T) {
	cases := map[string]string{
		"missing-comment":    strings.SplitN(epssCSV(), "\n", 2)[1],
		"duplicate-metadata": "#model_version:v,score_date:2026-10-25\n" + epssCSV(),
		"duplicate-cve":      epssCSV() + "CVE-2026-1234,0.8,0.5\n",
		"nan":                strings.Replace(epssCSV(), "0.7", "NaN", 1),
		"range":              strings.Replace(epssCSV(), "0.7", "1.1", 1),
		"bad-percentile":     strings.Replace(epssCSV(), "0.95", "-1", 1),
		"future-date":        strings.Replace(epssCSV(), "score_date:2026-10-25", "score_date:2026-10-26", 1),
		"invalid-date":       strings.Replace(epssCSV(), "score_date:2026-10-25", "score_date:2026-02-30", 1),
		"bad-cve":            strings.Replace(epssCSV(), "CVE-2026-1234", "CVE-2026-1", 1),
		"empty":              "#model_version:v,score_date:2026-10-25\ncve,epss,percentile\n",
		"record-limit":       epssCSV() + strings.Repeat("x", 4097) + "\n",
	}
	for name, csv := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEPSS(bytes.NewReader(gzipFixture(t, csv)), EPSSURL, fixtureNow); err == nil {
				t.Fatal("malformed publication accepted")
			}
		})
	}
	raw := gzipFixture(t, epssCSV())
	for name, bad := range map[string][]byte{"truncated": raw[:len(raw)-3], "not-gzip": []byte(epssCSV()), "bad-checksum": append(append([]byte{}, raw[:len(raw)-1]...), raw[len(raw)-1]^1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEPSS(bytes.NewReader(bad), EPSSURL, fixtureNow); err == nil {
				t.Fatal("invalid gzip accepted")
			}
		})
	}
	if _, err := ParseEPSS(nil, EPSSURL, fixtureNow); err == nil {
		t.Fatal("nil reader accepted")
	}
}
func TestKEVRejectsMalformedFixtures(t *testing.T) {
	valid := string(kevJSON(t))
	cases := map[string]string{
		"duplicate-key":       strings.Replace(valid, `"count":1`, `"count":1,"count":1`, 1),
		"wrong-count":         strings.Replace(valid, `"count":1`, `"count":2`, 1),
		"fraction-count":      strings.Replace(valid, `"count":1`, `"count":1.5`, 1),
		"required-null":       strings.Replace(valid, `"requiredAction":"Fixture action"`, `"requiredAction":null`, 1),
		"required-missing":    strings.Replace(valid, `"requiredAction":"Fixture action",`, "", 1),
		"bad-date":            strings.Replace(valid, "2026-10-24", "2026-02-30", 1),
		"due-before-added":    strings.Replace(valid, "2026-10-31", "2026-10-23", 1),
		"added-after-release": strings.Replace(valid, "2026-10-24", "2026-10-26", 1),
		"future-release":      strings.Replace(valid, "2026-10-25T00:00:00Z", "2026-10-26T00:00:00Z", 1),
		"bad-cve":             strings.Replace(valid, "CVE-2026-1234", "CVE-2026-12", 1),
		"trailing":            valid + " {}", "truncated": valid[:len(valid)-1], "empty": "{}",
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(valid), &data); err != nil {
		t.Fatal(err)
	}
	entries := data["vulnerabilities"].([]any)
	data["count"], data["vulnerabilities"] = 2, []any{entries[0], entries[0]}
	dup, _ := json.Marshal(data)
	cases["duplicate-cve"] = string(dup)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKEV(strings.NewReader(raw), KEVURL, fixtureNow); err == nil {
				t.Fatal("malformed catalog accepted")
			}
		})
	}
	unknown := strings.Replace(valid, `"count":1`, `"futureField":{"value":true},"count":1`, 1)
	if _, err := ParseKEV(strings.NewReader(unknown), KEVURL, fixtureNow); err != nil {
		t.Fatalf("future unknown fields supported: %v", err)
	}
	if _, err := ParseKEV(strings.NewReader(strings.Repeat(" ", 16*1024*1024+1)), KEVURL, fixtureNow); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("JSON size cap: %v", err)
	}
	if _, err := ParseKEV(strings.NewReader(valid), "http://untrusted.example", fixtureNow); err == nil {
		t.Fatal("invalid provenance URL accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }
func fixtureResponse(r *http.Request, status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: r}
}
func TestHTTPFetchBoundsAndProvenance(t *testing.T) {
	body := &trackedBody{Reader: bytes.NewReader(gzipFixture(t, epssCSV()))}
	e, err := fetchEPSS(context.Background(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != EPSSURL || r.Header.Get("Authorization") != "" {
			t.Errorf("fixed anonymous request: %+v", r)
		}
		if d, ok := r.Context().Deadline(); !ok || time.Until(d) > 20*time.Second {
			t.Error("bounded request context required")
		}
		return fixtureResponse(r, 200, body), nil
	}), func() time.Time { return fixtureNow })
	if err != nil || e.Source != EPSSURL || !body.closed {
		t.Fatalf("fetch/provenance/close: %+v %v closed=%v", e, err, body.closed)
	}
	kb := &trackedBody{Reader: bytes.NewReader(kevJSON(t))}
	if _, err := fetchKEV(context.Background(), roundTripFunc(func(r *http.Request) (*http.Response, error) { return fixtureResponse(r, 200, kb), nil }), func() time.Time { return fixtureNow }); err != nil || !kb.closed {
		t.Fatalf("KEV fixed fetch: %v closed=%v", err, kb.closed)
	}
	for _, status := range []int{403, 500} {
		b := &trackedBody{Reader: strings.NewReader("fixture rejection")}
		if _, err := fetchEPSS(context.Background(), roundTripFunc(func(r *http.Request) (*http.Response, error) { return fixtureResponse(r, status, b), nil }), func() time.Time { return fixtureNow }); err == nil || !b.closed {
			t.Fatalf("status %d/closed: %v %v", status, err, b.closed)
		}
	}
	stale := gzipFixture(t, strings.Replace(epssCSV(), "score_date:2026-10-25", "score_date:2026-10-20", 1))
	if _, err := fetchEPSS(context.Background(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fixtureResponse(r, 200, io.NopCloser(bytes.NewReader(stale))), nil
	}), func() time.Time { return fixtureNow }); err == nil {
		t.Fatal("fetch accepted stale publication")
	}
}
func TestHTTPRedirectAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		allowed      bool
	}{
		{"same-origin", "https://epss.empiricalsecurity.com/final", true},
		{"downgrade", "http://epss.empiricalsecurity.com/final", false},
		{"other-host", "https://example.invalid/final", false},
		{"credentials", "https://user:pass@epss.empiricalsecurity.com/final", false},
		{"loop", EPSSURL, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			closed := []*trackedBody{}
			_, err := fetchEPSS(context.Background(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				b := &trackedBody{Reader: strings.NewReader("")}
				closed = append(closed, b)
				if calls == 1 || tc.name == "loop" {
					res := fixtureResponse(r, 302, b)
					res.Header.Set("Location", tc.target)
					return res, nil
				}
				b.Reader = bytes.NewReader(gzipFixture(t, epssCSV()))
				return fixtureResponse(r, 200, b), nil
			}), func() time.Time { return fixtureNow })
			if (err == nil) != tc.allowed || calls > 3 {
				t.Fatalf("redirect policy calls=%d err=%v", calls, err)
			}
			for _, b := range closed {
				if !b.closed {
					t.Error("response body leaked")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetchEPSS(ctx, roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }), func() time.Time { return fixtureNow }); err == nil {
		t.Fatal("cancelled fetch accepted")
	}
	if _, err := fetchEPSS(nil, nil, func() time.Time { return fixtureNow }); err == nil {
		t.Fatal("nil context accepted")
	}
}
