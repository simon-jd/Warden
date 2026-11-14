package main

// Fixture feeds and findings only; no network.
import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/vuln"
)

const fixtureEPSS = "#model_version:v2025.03.14,score_date:2026-10-25T00:00:00Z\n" +
	"cve,epss,percentile\nCVE-2026-0001,0.02,0.40\nCVE-2026-0002,0.90,0.99\nCVE-2026-0003,0.10,0.80\n"

const fixtureKEV = `{"title":"fixture","catalogVersion":"2026.10.25","dateReleased":"2026-10-25T10:00:00.000Z","count":1,
"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"v","product":"p","vulnerabilityName":"n",
"dateAdded":"2026-10-20","shortDescription":"d","requiredAction":"a","dueDate":"2026-11-10",
"knownRansomwareCampaignUse":"Unknown","notes":"","cwes":[]}]}`

const fixtureFindings = `[
 {"id":"low-epss-kev","cve":"CVE-2026-0001","cvss":4.0,"first_seen":"2026-10-10T00:00:00Z"},
 {"id":"high-epss","cve":"CVE-2026-0002","cvss":9.8,"exposed":true,"first_seen":"2026-10-24T00:00:00Z"},
 {"id":"fixed","cve":"CVE-2026-0003","severity":"high","cvss":7.5,"first_seen":"2026-10-01T00:00:00Z","fixed_at":"2026-10-03T12:00:00Z"}
]`

func writeFixtures(t *testing.T) (epss, kev, findings string) {
	t.Helper()
	dir := t.TempDir()
	var gz bytes.Buffer
	z := gzip.NewWriter(&gz)
	if _, err := z.Write([]byte(fixtureEPSS)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	epss, kev, findings = filepath.Join(dir, "epss.csv.gz"), filepath.Join(dir, "kev.json"), filepath.Join(dir, "findings.json")
	for path, data := range map[string][]byte{epss: gz.Bytes(), kev: []byte(fixtureKEV), findings: []byte(fixtureFindings)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunWithFixtureFiles(t *testing.T) {
	epss, kev, findings := writeFixtures(t)
	code, out, stderr := runCLI("-epss-file", epss, "-kev-file", kev, "-retrieved", "2026-10-25T12:00:00Z",
		"-now", "2026-10-25T12:00:00Z", "-findings", findings)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var r report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("output is not a report: %v\n%s", err, out)
	}
	if r.EPSS.Scores != 3 || r.EPSS.Model != "v2025.03.14" || r.KEV.Count != 1 || r.KEV.CatalogVersion != "2026.10.25" {
		t.Fatalf("feed metadata: %+v %+v", r.EPSS, r.KEV)
	}
	if len(r.EPSS.SHA256) != 64 || len(r.KEV.SHA256) != 64 {
		t.Fatalf("missing digests: %q %q", r.EPSS.SHA256, r.KEV.SHA256)
	}
	if r.Overlap.KEVWithEPSS != 1 || r.Overlap.KEVEPSSMedian != 0.02 || r.Overlap.AllEPSSMedian != 0.10 {
		t.Fatalf("overlap: %+v", r.Overlap)
	}
	if r.Findings == nil || len(r.Findings.Ranked) != 3 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	var ids []string
	for _, f := range r.Findings.Ranked {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, ",") != "low-epss-kev,high-epss,fixed" {
		t.Fatalf("ranking: %v", ids)
	}
	// KEV: 7 days from 10-10 -> breached on 10-25. fixed: 60h within 30 days.
	s := r.Findings.Summary
	if s.Open != 2 || s.Fixed != 1 || s.OpenBreaches != 1 || s.FixedBreaches != 0 || s.MedianRemediationHours == nil || *s.MedianRemediationHours != 60 {
		t.Fatalf("summary: %+v", s)
	}
	if !r.Findings.Ranked[0].Breached || r.Findings.Ranked[0].Due != "2026-10-17T00:00:00Z" {
		t.Fatalf("KEV row: %+v", r.Findings.Ranked[0])
	}
}

func TestRunWithoutFindingsReportsNoMedian(t *testing.T) {
	epss, kev, _ := writeFixtures(t)
	code, out, stderr := runCLI("-epss-file", epss, "-kev-file", kev, "-retrieved", "2026-10-25T12:00:00Z", "-now", "2026-10-25T13:00:00Z")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, `"findings": null`) {
		t.Fatalf("no findings must not invent a summary:\n%s", out)
	}
}

func TestRunRejectsStaleOrInvalidInput(t *testing.T) {
	epss, kev, _ := writeFixtures(t)
	base := []string{"-epss-file", epss, "-kev-file", kev}
	for name, args := range map[string][]string{
		"stale":             append(base, "-retrieved", "2026-10-25T12:00:00Z", "-now", "2026-10-28T12:00:00Z"),
		"missing-retrieved": base,
		"only-one-file":     {"-epss-file", epss, "-retrieved", "2026-10-25T12:00:00Z"},
		"bad-findings":      append(base, "-retrieved", "2026-10-25T12:00:00Z", "-now", "2026-10-25T12:00:00Z", "-findings", epss),
		"unknown-cve-field": append(base, "-retrieved", "2026-10-25T12:00:00Z", "-now", "2026-10-25T12:00:00Z", "-findings", writeFile(t, `[{"id":"x","cve":"CVE-2026-0001","first_seen":"2026-10-01T00:00:00Z","cvss_v4":1}]`)),
		"future-first-seen": append(base, "-retrieved", "2026-10-25T12:00:00Z", "-now", "2026-10-25T12:00:00Z", "-findings", writeFile(t, `[{"id":"x","cve":"CVE-2026-0001","first_seen":"2026-11-01T00:00:00Z"}]`)),
	} {
		t.Run(name, func(t *testing.T) {
			if code, out, _ := runCLI(args...); code == 0 || out != "" {
				t.Fatalf("accepted: exit %d\n%s", code, out)
			}
		})
	}
}

// Live mode must evaluate freshness after the downloads, not before them.
func TestLiveModeSamplesClockAfterFetch(t *testing.T) {
	tick := time.Date(2026, 10, 27, 13, 0, 0, 0, time.UTC)
	advance := func() time.Time { tick = tick.Add(time.Second); return tick }
	restore := [3]any{clock, liveEPSS, liveKEV}
	t.Cleanup(func() {
		clock = restore[0].(func() time.Time)
		liveEPSS = restore[1].(func(context.Context) (vuln.EPSSFeed, error))
		liveKEV = restore[2].(func(context.Context) (vuln.KEVFeed, error))
	})
	clock = advance
	liveEPSS = func(context.Context) (vuln.EPSSFeed, error) {
		at := advance()
		return vuln.EPSSFeed{Scores: map[string]float64{"CVE-2026-0001": 0.5}, Published: at.Add(-time.Hour), Model: "v", RetrievedAt: at, Source: vuln.EPSSURL}, nil
	}
	liveKEV = func(context.Context) (vuln.KEVFeed, error) {
		at := advance()
		return vuln.KEVFeed{CVEs: map[string]bool{"CVE-2026-0001": true}, Count: 1, DateReleased: at.Add(-time.Hour), RetrievedAt: at, Source: vuln.KEVURL}, nil
	}
	if code, out, stderr := runCLI(); code != 0 || !strings.Contains(out, `"kev_with_epss": 1`) {
		t.Fatalf("exit %d: %s\n%s", code, stderr, out)
	}
}

func writeFile(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
