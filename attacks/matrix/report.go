package matrix

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Alert is one detection alert, in the format detect/report/detection_metrics.py
// reads: execution_id is the run ID of the cell the alert is about.
type Alert struct {
	AlertID     string `json:"alert_id"`
	ExecutionID string `json:"execution_id"`
	RuleID      string `json:"rule_id"`
	AlertedAt   string `json:"alerted_at"`
}

// ReadAlerts reads alerts as JSON lines. Blank lines are skipped; unknown or
// missing fields are errors.
func ReadAlerts(r io.Reader) ([]Alert, error) {
	var alerts []Alert
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		var a Alert
		if err := d.Decode(&a); err != nil {
			return nil, fmt.Errorf("alerts line %d: %w", n, err)
		}
		if a.AlertID == "" || a.ExecutionID == "" || a.RuleID == "" || a.AlertedAt == "" {
			return nil, fmt.Errorf("alerts line %d: alert_id, execution_id, rule_id and alerted_at are required", n)
		}
		if _, err := time.Parse(time.RFC3339Nano, a.AlertedAt); err != nil {
			return nil, fmt.Errorf("alerts line %d: alerted_at: %w", n, err)
		}
		alerts = append(alerts, a)
	}
	return alerts, sc.Err()
}

// Matrix is every runtime's pass over one corpus.
type Matrix struct {
	CorpusDigest  string
	Runtimes      []string
	Attacks       []string // sorted ids
	Techniques    map[string]string
	Cells         map[string]map[string]Cell // attack -> runtime -> cell
	AlertsApplied bool
}

// Merge puts the passes of several runtimes into one matrix. Every pass must
// cover the same corpus, and a runtime may appear only once.
func Merge(passes []Results) (Matrix, error) {
	m := Matrix{Techniques: map[string]string{}, Cells: map[string]map[string]Cell{}}
	if len(passes) == 0 {
		return m, errors.New("no results")
	}
	seen := map[string]bool{}
	for _, p := range passes {
		if m.CorpusDigest == "" {
			m.CorpusDigest = p.CorpusDigest
		}
		if p.CorpusDigest != m.CorpusDigest {
			return m, fmt.Errorf("%s ran corpus %s, not %s", p.Runtime, p.CorpusDigest, m.CorpusDigest)
		}
		if seen[p.Runtime] {
			return m, fmt.Errorf("runtime %s appears twice", p.Runtime)
		}
		seen[p.Runtime] = true
		m.Runtimes = append(m.Runtimes, p.Runtime)
		for _, c := range p.Cells {
			if c.Runtime != p.Runtime {
				return m, fmt.Errorf("%s results hold a %s cell", p.Runtime, c.Runtime)
			}
			if _, ok := m.Cells[c.Attack]; !ok {
				m.Cells[c.Attack] = map[string]Cell{}
				m.Techniques[c.Attack] = c.Technique
				m.Attacks = append(m.Attacks, c.Attack)
			}
			if m.Techniques[c.Attack] != c.Technique {
				return m, fmt.Errorf("%s has technique %s and %s", c.Attack, m.Techniques[c.Attack], c.Technique)
			}
			if _, dup := m.Cells[c.Attack][c.Runtime]; dup {
				return m, fmt.Errorf("%s on %s appears twice", c.Attack, c.Runtime)
			}
			m.Cells[c.Attack][c.Runtime] = c
		}
	}
	sort.Strings(m.Attacks)
	for _, a := range m.Attacks {
		if len(m.Cells[a]) != len(m.Runtimes) {
			return m, fmt.Errorf("%s did not run on every runtime", a)
		}
	}
	return m, nil
}

// ApplyAlerts joins alerts to cells by run ID. A missed cell with an alert
// becomes detected; a blocked cell keeps its verdict and lists the alert.
// Alerts about other runs are ignored. An alert from before its run started
// is an error.
func (m *Matrix) ApplyAlerts(alerts []Alert) error {
	where := map[string][2]string{}
	for _, a := range m.Attacks {
		for rt, c := range m.Cells[a] {
			if c.RunID != "" {
				where[c.RunID] = [2]string{a, rt}
			}
		}
	}
	for _, al := range alerts {
		loc, ok := where[al.ExecutionID]
		if !ok {
			continue
		}
		c := m.Cells[loc[0]][loc[1]]
		at, err := time.Parse(time.RFC3339Nano, al.AlertedAt)
		if err != nil {
			return fmt.Errorf("alert %s: %w", al.AlertID, err)
		}
		if at.Before(c.StartedAt) {
			return fmt.Errorf("alert %s is from before run %s started", al.AlertID, c.RunID)
		}
		c.Alerts = append(c.Alerts, al.AlertID)
		if c.Verdict == Missed {
			c.Verdict = Detected
			c.Reason = "success signal in the output; alerted by " + al.RuleID
		}
		m.Cells[loc[0]][loc[1]] = c
	}
	for _, a := range m.Attacks {
		for rt, c := range m.Cells[a] {
			sort.Strings(c.Alerts)
			m.Cells[a][rt] = c
		}
	}
	m.AlertsApplied = true
	return nil
}

// Markdown renders the matrix for docs/evidence/isolation-matrix.md.
func (m Matrix) Markdown() string {
	var b strings.Builder
	b.WriteString("# Isolation matrix\n\n")
	fmt.Fprintf(&b, "Corpus `%s`, %d entries; runtimes: %s.\n\n", m.CorpusDigest, len(m.Attacks), strings.Join(m.Runtimes, ", "))
	b.WriteString("- **blocked**: the probe finished with complete output and never printed its success signal.\n")
	b.WriteString("- **detected**: the probe printed its success signal and an alert names its run.\n")
	b.WriteString("- **missed**: the probe printed its success signal and no alert names its run.\n")
	b.WriteString("- **error**: the run failed (start, wait, logs or cleanup), so the cell has no verdict.\n\n")
	if !m.AlertsApplied {
		b.WriteString("No alerts were joined, so no cell can be `detected` yet: a `missed` cell may still have raised an alert.\n\n")
	}
	b.WriteString("| Attack | Technique |")
	for _, rt := range m.Runtimes {
		b.WriteString(" " + rt + " |")
	}
	b.WriteString("\n|---|---|" + strings.Repeat("---|", len(m.Runtimes)) + "\n")
	for _, a := range m.Attacks {
		fmt.Fprintf(&b, "| %s | %s |", a, m.Techniques[a])
		for _, rt := range m.Runtimes {
			b.WriteString(" " + string(m.Cells[a][rt].Verdict) + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Totals\n\n| Runtime | blocked | detected | missed | error |\n|---|---|---|---|---|\n")
	for _, rt := range m.Runtimes {
		count := map[Verdict]int{}
		for _, a := range m.Attacks {
			count[m.Cells[a][rt].Verdict]++
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", rt, count[Blocked], count[Detected], count[Missed], count[Error])
	}
	b.WriteString("\n## Runs\n\n| Attack | Runtime | Run ID | Verdict | Reason | Exit | Started (UTC) | Seconds | Alerts |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, a := range m.Attacks {
		for _, rt := range m.Runtimes {
			c := m.Cells[a][rt]
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %s | %.2f | %s |\n",
				a, rt, c.RunID, c.Verdict, cellText(c.Reason), exitText(c), c.StartedAt.UTC().Format(time.RFC3339),
				c.FinishedAt.Sub(c.StartedAt).Seconds(), cellText(strings.Join(c.Alerts, ", ")))
		}
	}
	return b.String()
}

func exitText(c Cell) string {
	if c.Exit == nil {
		return "none"
	}
	parts := []string{fmt.Sprintf("code %d", c.Exit.Code)}
	if c.Exit.OOMKilled {
		parts = append(parts, "OOM-killed")
	}
	if c.Exit.TimedOut {
		parts = append(parts, "timed out")
	}
	if c.Exit.PidsMaxEvents > 0 {
		parts = append(parts, fmt.Sprintf("pids limit hit %d×", c.Exit.PidsMaxEvents))
	}
	return strings.Join(parts, ", ")
}

func cellText(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.Join(strings.Fields(s), " ")
}

// Execution is one line of the executions file detection_metrics.py reads.
type Execution struct {
	ExecutionID string `json:"execution_id"`
	RunID       string `json:"run_id"`
	TechniqueID string `json:"technique_id"`
	ExecutedAt  string `json:"executed_at"`
	Outcome     string `json:"outcome"`
}

// Executions lists every cell that started as a detection_metrics execution:
// a probe that printed its signal "succeeded", a blocked one "failed", and a
// run without a verdict "skipped". run_id names the runtime's pass.
func (m Matrix) Executions() []Execution {
	outcome := map[Verdict]string{Missed: "succeeded", Detected: "succeeded", Blocked: "failed", Error: "skipped"}
	var out []Execution
	for _, a := range m.Attacks {
		for _, rt := range m.Runtimes {
			c := m.Cells[a][rt]
			if c.RunID == "" || c.StartedAt.IsZero() {
				continue
			}
			out = append(out, Execution{
				ExecutionID: c.RunID,
				RunID:       "isolation-matrix/" + rt + "/" + shortDigest(m.CorpusDigest),
				TechniqueID: c.Technique,
				ExecutedAt:  c.StartedAt.UTC().Format(time.RFC3339Nano),
				Outcome:     outcome[c.Verdict],
			})
		}
	}
	return out
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}
