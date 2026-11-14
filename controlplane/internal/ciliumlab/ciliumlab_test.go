package ciliumlab

import (
	"math"
	"strings"
	"testing"
)

func TestParseNetResultsKeepsEveryCaseOnce(t *testing.T) {
	out := `{"key":"direct","ok":false,"connect_error":"dial tcp 198.18.18.20:80: i/o timeout","ms":3001.2}
{"key":"proxy","ok":true,"status":200,"proxy_status":200,"body":"origin-allowed\n","ms":12.5}

{"key":"txt","ok":false,"rcode":5,"ms":1.1}
`
	got, err := ParseNetResults([]byte(out), "direct", "proxy", "txt")
	if err != nil {
		t.Fatal(err)
	}
	if r := got["direct"]; r.OK || !strings.Contains(r.ConnectError, "i/o timeout") || r.Millis != 3001.2 {
		t.Errorf("direct = %+v", r)
	}
	if r := got["proxy"]; !r.OK || r.Status != 200 || r.ProxyStatus != 200 || r.Body != "origin-allowed\n" {
		t.Errorf("proxy = %+v", r)
	}
	if r := got["txt"]; r.Rcode == nil || *r.Rcode != 5 {
		t.Errorf("txt = %+v", r)
	}
	if _, err := ParseNetResults([]byte(out), "direct", "missing"); err == nil {
		t.Error("a missing case was accepted")
	}
	if _, err := ParseNetResults([]byte(out+out), "direct"); err == nil {
		t.Error("a case reported twice was accepted")
	}
	if _, err := ParseNetResults([]byte("dial error\n"), "direct"); err == nil {
		t.Error("a line that is not JSON was accepted")
	}
}

func TestParseLogReadsWorldAndProbeLines(t *testing.T) {
	raw := `1731400000.100 serving stream every 0.02
1731400001.000 open 1 198.18.18.10
1731400001.020 rx 1 t03 1 1731400001.010
garbage line
1731400001.040 rx 1 ctl 7 1731400001.030
1731400002.000 dns 198.18.18.10 TXT 6a6b.exfil.warden.test
12 rx not-a-time
1731400003.000 close 1 eof`
	ev := ParseLog([]byte(raw))
	if len(ev) != 6 {
		t.Fatalf("got %d events: %+v", len(ev), ev)
	}
	if e := ev[2]; e.At != 1731400001.020 || e.Kind != "rx" || strings.Join(e.Fields, " ") != "1 t03 1 1731400001.010" {
		t.Errorf("rx line = %+v", e)
	}
	if e := ev[4]; e.Kind != "dns" || e.Fields[1] != "TXT" || e.Fields[2] != "6a6b.exfil.warden.test" {
		t.Errorf("dns line = %+v", e)
	}
}

func TestStreamSeparatesTheDirectionsAndTheStreams(t *testing.T) {
	server := ParseLog([]byte(`1731400010.00 open 1 198.18.18.10
1731400010.02 rx 1 t03 1 1731400010.01
1731400010.03 rx 2 ctl 1 1731400010.02
1731400010.04 rx 1 t03 2 1731400010.03
1731400010.06 rx 1 t030 1 1731400010.05`))
	probe := ParseLog([]byte(`1731400009.90 connected stream.warden.test:443 via proxy
1731400010.05 rx hb 1 1 1731400010.04
1731400010.07 rx hb 1 2 1731400010.06
1731400010.09 rx something-else
1731400011.50 closed read EOF
1731400011.60 closed write broken pipe`))
	s := Stream(server, probe, "t03")
	if len(s.Up) != 2 || s.Up[0] != 1731400010.02 || s.Up[1] != 1731400010.04 {
		t.Errorf("up = %v", s.Up)
	}
	if len(s.Down) != 2 || s.Down[1] != 1731400010.07 {
		t.Errorf("down = %v", s.Down)
	}
	if s.Closed != 1731400011.50 {
		t.Errorf("closed = %v", s.Closed)
	}
}

func TestCountLastAndMaxGap(t *testing.T) {
	times := []float64{1, 2, 2.5, 4, 9}
	if n := Count(times, 2, 4); n != 2 {
		t.Errorf("Count [2,4) = %d", n)
	}
	if l := Last(times, 3, 5); l != 4 {
		t.Errorf("Last [3,5] = %v", l)
	}
	if l := Last(times, 5, 8); l != 5 {
		t.Errorf("Last of nothing = %v, want from", l)
	}
	if g := MaxGap(times, 0, 10); g != 5 {
		t.Errorf("MaxGap = %v, want 5 (4 to 9)", g)
	}
	if g := MaxGap(times, 2, 3); g != 0.5 {
		t.Errorf("MaxGap [2,3] = %v, want 0.5 (2.5 to the end)", g)
	}
	if g := MaxGap(nil, 2, 3); g != 1 {
		t.Errorf("MaxGap of nothing = %v, want the whole window", g)
	}
}

// every is n times, step apart, the first at from.
func every(from float64, n int, step float64) []float64 {
	var out []float64
	for i := range n {
		out = append(out, from+float64(i)*step)
	}
	return out
}

func TestMeasureFindsWhenAStreamStopped(t *testing.T) {
	alert, end := 100.0, 110.0
	// 95.00 to 100.28 is 265 lines: up stops 280 ms after the alert; down
	// (95.00 to 100.52, 277 lines) 520 ms after it.
	cut := Measure(StreamLines{Up: every(95, 265, 0.02), Down: every(95, 277, 0.02)}, alert, end, 3)
	if !cut.Stopped || math.Abs(cut.CutMS-520) > 0.05 || math.Abs(cut.LastUpMS-280) > 0.05 {
		t.Errorf("cut = %+v, want stopped at 520 ms (up 280 ms)", cut)
	}
	// Up never stops (95.00 to 109.98): not cut, whatever the other direction does.
	open := Measure(StreamLines{Up: every(95, 750, 0.02), Down: every(95, 256, 0.02)}, alert, end, 3)
	if open.Stopped || open.CutMS != 0 {
		t.Errorf("open stream = %+v, want not stopped", open)
	}
	// Lines that resume late in the watch also mean it was not cut.
	resumed := Measure(StreamLines{Up: append(every(95, 260, 0.02), 108.5), Down: every(95, 260, 0.02)}, alert, end, 3)
	if resumed.Stopped {
		t.Errorf("stream that resumed = %+v, want not stopped", resumed)
	}
	// Nothing after the alert at all (95.00 to 99.98): cut at once.
	none := Measure(StreamLines{Up: every(95, 250, 0.02), Down: every(95, 250, 0.02)}, alert, end, 3)
	if !none.Stopped || none.CutMS != 0 {
		t.Errorf("stream with nothing after the alert = %+v", none)
	}
}

func TestNearestRank(t *testing.T) {
	v := []float64{9, 1, 8, 2, 7, 3, 6, 4, 5, 10}
	if p := NearestRank(v, 50); p != 5 {
		t.Errorf("p50 = %v, want 5 (5th of 10)", p)
	}
	if p := NearestRank(v, 95); p != 10 {
		t.Errorf("p95 = %v, want 10 (10th of 10)", p)
	}
	if p := NearestRank(v[:3], 50); p != 8 {
		t.Errorf("p50 of 3 = %v, want 8 (2nd)", p)
	}
	if v[0] != 9 {
		t.Error("NearestRank sorted its input")
	}
	if !math.IsNaN(NearestRank(nil, 50)) {
		t.Error("NearestRank of nothing is not NaN")
	}
}

func TestSummaryUsesNearestRank(t *testing.T) {
	s := Summary([]float64{9, 1, 8, 2, 7, 3, 6, 4, 5, 10, 11, 12})
	want := map[string]float64{"n": 12, "min": 1, "p50": 6, "p95": 12, "max": 12}
	for k, v := range want {
		if s[k] != v {
			t.Errorf("%s = %v, want %v (all: %v)", k, s[k], v, s)
		}
	}
	if len(s) != len(want) {
		t.Errorf("summary has %d fields, want %d: %v", len(s), len(want), s)
	}
	if s := Summary(nil); s["n"] != 0 || len(s) != 1 {
		t.Errorf("summary of nothing = %v, want only n=0", s)
	}
}

func TestIdentityRecordLeavesUnobservedFieldsNull(t *testing.T) {
	const e0 = 1000.0
	// The first poll already showed the label: nothing was seen before it.
	first := identityPoll{firstWith: e0 + 0.0001, after: 7, polls: 1}
	r := first.record(e0)
	for _, k := range []string{"before", "last_poll_without_label_ms"} {
		if v, ok := r[k]; !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null", k, v, ok)
		}
	}
	if r["after"] != 7 || r["first_poll_with_label_ms"] != 0.1 || r["polls"] != 1 {
		t.Errorf("labelled fields = %v", r)
	}
	if first.bracketed() {
		t.Error("a switch seen on the first poll counts as bracketed")
	}

	both := identityPoll{lastWithout: e0 + 9.9, before: 3, firstWith: e0 + 10.2, after: 7, polls: 40}
	r = both.record(e0)
	if r["before"] != 3 || r["last_poll_without_label_ms"] != 9900.0 || r["after"] != 7 || r["first_poll_with_label_ms"] != 10200.0 {
		t.Errorf("bracketed record = %v", r)
	}
	if !both.bracketed() {
		t.Error("a switch between two polls is not bracketed")
	}

	none := identityPoll{lastWithout: e0 + 60, before: 3, polls: 240}
	r = none.record(e0)
	for _, k := range []string{"after", "first_poll_with_label_ms"} {
		if v, ok := r[k]; !ok || v != nil {
			t.Errorf("never labelled: %s = %v (present %v), want null", k, v, ok)
		}
	}
	if none.bracketed() {
		t.Error("a label never seen counts as bracketed")
	}
}
