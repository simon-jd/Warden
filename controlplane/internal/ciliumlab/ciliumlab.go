// Package ciliumlab holds the live checks of Tasks 7, 10 and 14 on the
// Cilium mode of the k3s + gVisor lab (scripts/k3s_gvisor_lab.sh up
// --cilium), and the parsers they use, which make test covers offline.
//
// The sandboxes are gVisor pods with their own network stack (RuntimeClass
// gvisor-netstack) and the label warden.dev/sandbox=true that the policies
// in policies/cilium select. They run the conformance probe
// (runtimes/conformance/guest: "net" and "stream" modes). The egress proxy
// is Envoy with the configuration controlplane/internal/scheduler renders.
// The "world" is the lab's stand-ins (runtimes/gvisor/lab/cilium/world.py),
// whose logs say what reached them.
//
// The live tests skip unless WARDEN_LIVE_CILIUM=1 (make test-cilium).
package ciliumlab

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// NetResult is one case of `warden-probe net`.
type NetResult struct {
	Key          string   `json:"key"`
	OK           bool     `json:"ok"`
	Status       int      `json:"status,omitempty"`
	ProxyStatus  int      `json:"proxy_status,omitempty"`
	Body         string   `json:"body,omitempty"`
	Error        string   `json:"error,omitempty"`
	Resolved     string   `json:"resolved,omitempty"`
	ResolveError string   `json:"resolve_error,omitempty"`
	ConnectError string   `json:"connect_error,omitempty"`
	Rcode        *int     `json:"rcode,omitempty"`
	Answers      []string `json:"answers,omitempty"`
	Millis       float64  `json:"ms"`
}

// ParseNetResults reads the probe's output: one JSON object per line, one
// per case. Every case must be there exactly once.
func ParseNetResults(out []byte, keys ...string) (map[string]NetResult, error) {
	got := map[string]NetResult{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r NetResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("probe output line %q: %w", line, err)
		}
		if _, dup := got[r.Key]; dup {
			return nil, fmt.Errorf("probe output has case %q twice", r.Key)
		}
		got[r.Key] = r
	}
	for _, k := range keys {
		if _, ok := got[k]; !ok {
			return nil, fmt.Errorf("probe output has no case %q", k)
		}
	}
	return got, sc.Err()
}

// Event is one log line of world.py or of the probe's stream mode:
// "<epoch seconds> <kind> <fields...>".
type Event struct {
	At     float64
	Kind   string
	Fields []string
}

// ParseLog returns the lines that start with an epoch time and a kind;
// anything else (Docker's own messages, a torn last line) is skipped.
func ParseLog(raw []byte) []Event {
	var out []Event
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		at, err := strconv.ParseFloat(f[0], 64)
		if err != nil || at < 1e9 {
			continue
		}
		out = append(out, Event{At: at, Kind: f[1], Fields: f[2:]})
	}
	return out
}

// StreamLines are the times at which the lines of one stream got through:
// Up, the stream server's receive times of the sandbox's lines ("rx <conn>
// <name> <seq> <t>" in world.py's log); Down, the probe's receive times of
// the server's heartbeats ("rx hb <conn> <seq> <t>" in the probe's log).
type StreamLines struct {
	Up, Down []float64
	// Closed is when the probe saw the connection end ("closed ..."), or 0.
	Closed float64
}

// Stream collects the lines of the stream called name from the server's
// and the probe's logs.
func Stream(server, probe []Event, name string) StreamLines {
	var s StreamLines
	for _, e := range server {
		if e.Kind == "rx" && len(e.Fields) >= 2 && e.Fields[1] == name {
			s.Up = append(s.Up, e.At)
		}
	}
	for _, e := range probe {
		switch {
		case e.Kind == "rx" && len(e.Fields) >= 1 && e.Fields[0] == "hb":
			s.Down = append(s.Down, e.At)
		case e.Kind == "closed" && s.Closed == 0:
			s.Closed = e.At
		}
	}
	sort.Float64s(s.Up)
	sort.Float64s(s.Down)
	return s
}

// Count is the number of times in [from, to).
func Count(times []float64, from, to float64) int {
	n := 0
	for _, t := range times {
		if t >= from && t < to {
			n++
		}
	}
	return n
}

// Last is the latest time in [from, to], or from if there is none.
func Last(times []float64, from, to float64) float64 {
	last := from
	for _, t := range times {
		if t >= from && t <= to && t > last {
			last = t
		}
	}
	return last
}

// MaxGap is the longest interval in [from, to] without a time in times,
// counting from from and up to to.
func MaxGap(times []float64, from, to float64) float64 {
	prev, gap := from, 0.0
	for _, t := range times {
		if t < from || t > to {
			continue
		}
		gap = math.Max(gap, t-prev)
		prev = t
	}
	return math.Max(gap, to-prev)
}

// Cut is what a quarantine did to one established stream, from the alert at
// Alert to the end of the watch at End (epoch seconds).
type Cut struct {
	// LastUpMS and LastDownMS: from the alert to the last line that got
	// through in each direction (0 if none got through after the alert).
	LastUpMS, LastDownMS float64
	// Stopped: no line got through in either direction during the last
	// Quiet seconds of the watch, although each direction carries one
	// every 20 ms while the stream is up.
	Stopped bool
	// CutMS: when Stopped, from the alert to the last line in either
	// direction; the connection carried nothing after that.
	CutMS float64
}

// Measure decides whether the stream stopped after the alert and when.
func Measure(s StreamLines, alert, end, quiet float64) Cut {
	up, down := Last(s.Up, alert, end), Last(s.Down, alert, end)
	c := Cut{LastUpMS: ms(up - alert), LastDownMS: ms(down - alert)}
	c.Stopped = Count(s.Up, end-quiet, end+1e-9) == 0 && Count(s.Down, end-quiet, end+1e-9) == 0
	if c.Stopped {
		c.CutMS = math.Max(c.LastUpMS, c.LastDownMS)
	}
	return c
}

func ms(seconds float64) float64 { return math.Round(seconds*1e4) / 10 }

// NearestRank is the p-th percentile by nearest rank: the ⌈p·n/100⌉-th
// smallest value (the same method as time-to-contain.md's other sections).
func NearestRank(values []float64, p float64) float64 {
	if len(values) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), values...)
	sort.Float64s(s)
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	return s[max(0, min(i, len(s)-1))]
}

// Summary is n, min, p50, p95 (both by nearest rank) and max of values;
// only n when there are none.
func Summary(values []float64) map[string]float64 {
	s := map[string]float64{"n": float64(len(values))}
	if len(values) == 0 {
		return s
	}
	s["min"], s["max"] = NearestRank(values, 0), NearestRank(values, 100)
	s["p50"], s["p95"] = NearestRank(values, 50), NearestRank(values, 95)
	return s
}
