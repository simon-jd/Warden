// Command vulnfeeds fetches the public EPSS and CISA KEV feeds, validates them,
// optionally ranks a findings file and prints one JSON report on stdout.
//
//	vulnfeeds [-findings F]                               live download
//	vulnfeeds -epss-file F -kev-file F -retrieved T [-now T] [-findings F]
//
// Local files must be unmodified copies of vuln.EPSSURL and vuln.KEVURL; -retrieved
// is when they were downloaded. A stale or malformed feed exits non-zero.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"warden/vuln"
)

type epssInfo struct {
	Source      string    `json:"source"`
	SHA256      string    `json:"sha256"`
	Model       string    `json:"model"`
	Published   time.Time `json:"published"`
	RetrievedAt time.Time `json:"retrieved_at"`
	Scores      int       `json:"scores"`
}

type kevInfo struct {
	Source         string    `json:"source"`
	SHA256         string    `json:"sha256"`
	CatalogVersion string    `json:"catalog_version"`
	DateReleased   time.Time `json:"date_released"`
	RetrievedAt    time.Time `json:"retrieved_at"`
	Count          int       `json:"count"`
}

// overlap describes the feeds themselves, independent of any findings.
type overlap struct {
	KEVWithEPSS      int     `json:"kev_with_epss"`
	KEVEPSSMedian    float64 `json:"kev_epss_median"`
	KEVEPSSAtLeast01 int     `json:"kev_epss_ge_0_1"`
	AllEPSSMedian    float64 `json:"all_epss_median"`
	AllEPSSAtLeast01 int     `json:"all_epss_ge_0_1"`
}

type rankedRow struct {
	ID        string  `json:"id"`
	CVE       string  `json:"cve"`
	KEV       bool    `json:"kev"`
	EPSS      float64 `json:"epss"`
	EPSSKnown bool    `json:"epss_known"`
	CVSS      float64 `json:"cvss"`
	Exposed   bool    `json:"exposed"`
	Due       string  `json:"due"`
	Closed    bool    `json:"closed"`
	Breached  bool    `json:"breached"`
}

type summary struct {
	Open                   int      `json:"open"`
	Fixed                  int      `json:"fixed"`
	OpenBreaches           int      `json:"open_breaches"`
	FixedBreaches          int      `json:"fixed_breaches"`
	MedianRemediationHours *float64 `json:"median_remediation_hours"`
}

type findingsReport struct {
	Ranked  []rankedRow `json:"ranked"`
	Summary summary     `json:"summary"`
}

type report struct {
	EvaluatedAt time.Time       `json:"evaluated_at"`
	EPSS        epssInfo        `json:"epss"`
	KEV         kevInfo         `json:"kev"`
	Overlap     overlap         `json:"overlap"`
	Findings    *findingsReport `json:"findings"`
}

type findingJSON struct {
	ID        string     `json:"id"`
	CVE       string     `json:"cve"`
	Severity  string     `json:"severity"`
	CVSS      float64    `json:"cvss"`
	Exposed   bool       `json:"exposed"`
	FirstSeen time.Time  `json:"first_seen"`
	FixedAt   *time.Time `json:"fixed_at"`
}

// Seams for tests; production uses the real clock and the official feeds.
var (
	clock    = time.Now
	liveEPSS = vuln.FetchEPSS
	liveKEV  = vuln.FetchKEV
)

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("vulnfeeds", flag.ContinueOnError)
	fl.SetOutput(stderr)
	epssFile := fl.String("epss-file", "", "local copy of the EPSS gzip CSV")
	kevFile := fl.String("kev-file", "", "local copy of the KEV JSON catalog")
	retrieved := fl.String("retrieved", "", "RFC 3339 download time of the local copies")
	nowFlag := fl.String("now", "", "RFC 3339 evaluation time (default: current time)")
	findingsFile := fl.String("findings", "", "JSON array of findings to rank")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	r, err := build(*epssFile, *kevFile, *retrieved, *nowFlag, *findingsFile)
	if err != nil {
		fmt.Fprintln(stderr, "vulnfeeds:", err)
		return 1
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "vulnfeeds:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", out)
	return 0
}

func build(epssFile, kevFile, retrieved, nowFlag, findingsFile string) (report, error) {
	var now time.Time
	if nowFlag != "" {
		t, err := time.Parse(time.RFC3339Nano, nowFlag)
		if err != nil {
			return report{}, fmt.Errorf("-now: %w", err)
		}
		now = t
	}
	var e vuln.EPSSFeed
	var k vuln.KEVFeed
	var err error
	switch {
	case epssFile == "" && kevFile == "":
		if retrieved != "" {
			return report{}, errors.New("-retrieved only applies to local files")
		}
		if e, err = liveEPSS(context.Background()); err != nil {
			return report{}, err
		}
		if k, err = liveKEV(context.Background()); err != nil {
			return report{}, err
		}
	case epssFile != "" && kevFile != "" && retrieved != "":
		at, err := time.Parse(time.RFC3339Nano, retrieved)
		if err != nil {
			return report{}, fmt.Errorf("-retrieved: %w", err)
		}
		if e, err = parseFile(epssFile, func(r io.Reader) (vuln.EPSSFeed, error) { return vuln.ParseEPSS(r, vuln.EPSSURL, at) }); err != nil {
			return report{}, err
		}
		if k, err = parseFile(kevFile, func(r io.Reader) (vuln.KEVFeed, error) { return vuln.ParseKEV(r, vuln.KEVURL, at) }); err != nil {
			return report{}, err
		}
	default:
		return report{}, errors.New("local mode needs -epss-file, -kev-file and -retrieved together")
	}
	if now.IsZero() { // after the downloads, so retrieval is never in the future
		now = clock().UTC()
	}
	if err := e.Fresh(now); err != nil {
		return report{}, err
	}
	if err := k.Fresh(now); err != nil {
		return report{}, err
	}
	r := report{
		EvaluatedAt: now,
		EPSS:        epssInfo{e.Source, e.SHA256, e.Model, e.Published, e.RetrievedAt, len(e.Scores)},
		KEV:         kevInfo{k.Source, k.SHA256, k.CatalogVersion, k.DateReleased, k.RetrievedAt, k.Count},
		Overlap:     feedOverlap(e.Scores, k.CVEs),
	}
	if findingsFile != "" {
		fr, err := rankFindings(findingsFile, e.Scores, k.CVEs, now)
		if err != nil {
			return report{}, err
		}
		r.Findings = fr
	}
	return r, nil
}

func parseFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(path)
	if err != nil {
		var zero T
		return zero, err
	}
	defer f.Close()
	return parse(f)
}

func feedOverlap(epss map[string]float64, kev map[string]bool) overlap {
	var o overlap
	var all, kevScores []float64
	for cve, p := range epss {
		all = append(all, p)
		if p >= 0.1 {
			o.AllEPSSAtLeast01++
		}
		if kev[cve] {
			kevScores = append(kevScores, p)
			if p >= 0.1 {
				o.KEVEPSSAtLeast01++
			}
		}
	}
	o.KEVWithEPSS = len(kevScores)
	o.KEVEPSSMedian, o.AllEPSSMedian = median(kevScores), median(all)
	return o
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sort.Float64s(xs)
	m := len(xs) / 2
	if len(xs)%2 == 0 {
		return (xs[m-1] + xs[m]) / 2
	}
	return xs[m]
}

func rankFindings(path string, epss map[string]float64, kev map[string]bool, now time.Time) (*findingsReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in []findingJSON
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("findings %s: %w", path, err)
	}
	fs := make([]vuln.Finding, len(in))
	for i, f := range in {
		fs[i] = vuln.Finding{ID: f.ID, CVE: f.CVE, Severity: f.Severity, CVSS: f.CVSS,
			Exposed: f.Exposed, FirstSeen: f.FirstSeen, FixedAt: f.FixedAt}
	}
	if err := vuln.ValidateInputs(fs, epss, kev); err != nil {
		return nil, err
	}
	clock := func() time.Time { return now }
	s, err := vuln.Summarize(fs, kev, clock)
	if err != nil {
		return nil, err
	}
	fr := &findingsReport{Summary: summary{Open: s.OpenCount, Fixed: s.FixedCount,
		OpenBreaches: s.OpenBreaches, FixedBreaches: s.FixedBreaches}}
	if s.HasMedian {
		h := s.MedianRemediation.Hours()
		fr.Summary.MedianRemediationHours = &h
	}
	for _, rk := range vuln.Prioritize(fs, epss, kev) {
		sla, err := vuln.EvaluateSLA(rk.Finding, rk.KEV, clock)
		if err != nil {
			return nil, err
		}
		f := rk.Finding
		fr.Ranked = append(fr.Ranked, rankedRow{ID: f.ID, CVE: f.CVE, KEV: rk.KEV, EPSS: rk.EPSS,
			EPSSKnown: rk.EPSSKnown, CVSS: f.CVSS, Exposed: f.Exposed,
			Due: sla.Due.Format(time.RFC3339), Closed: sla.Closed, Breached: sla.Breached})
	}
	return fr, nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
