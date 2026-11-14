// Command matrix checks an isolation corpus and turns the runtimes' results
// into the isolation matrix.
//
//	matrix validate -corpus attacks/corpus
//	matrix render -results runc.json,gvisor.json,firecracker.json \
//	    [-alerts alerts.jsonl] [-out docs/evidence/isolation-matrix.md] \
//	    [-executions executions.jsonl]
//
// The results files come from the runtimes' lab tests (matrix.RunFromEnv).
// -alerts joins detection alerts by run ID, turning missed cells into
// detected ones. -executions writes the runs in the format
// detect/report/detection_metrics.py reads.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"warden/attacks/matrix"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "matrix:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: matrix validate|render [flags]")
	}
	switch args[0] {
	case "validate":
		return validate(args[1:], stdout)
	case "render":
		return render(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q (want validate or render)", args[0])
	}
}

func validate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	corpus := fs.String("corpus", "attacks/corpus", "corpus directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	attacks, err := matrix.LoadCorpus(*corpus)
	if err != nil {
		return err
	}
	for _, a := range attacks {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", a.ID, a.Technique, a.Digest)
	}
	fmt.Fprintf(stdout, "%d entries, corpus %s\n", len(attacks), matrix.CorpusDigest(attacks))
	return nil
}

func render(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	results := fs.String("results", "", "comma-separated results files, one per runtime, in column order")
	alerts := fs.String("alerts", "", "alerts JSON lines to join by run ID")
	out := fs.String("out", "", "markdown output file (default stdout)")
	executions := fs.String("executions", "", "write the runs as detection_metrics executions JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *results == "" {
		return errors.New("render: -results is required")
	}
	var passes []matrix.Results
	for _, path := range strings.Split(*results, ",") {
		res, err := matrix.ReadResults(strings.TrimSpace(path))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		passes = append(passes, res)
	}
	m, err := matrix.Merge(passes)
	if err != nil {
		return err
	}
	if *alerts != "" {
		f, err := os.Open(*alerts)
		if err != nil {
			return err
		}
		list, err := matrix.ReadAlerts(f)
		f.Close()
		if err != nil {
			return err
		}
		if err := m.ApplyAlerts(list); err != nil {
			return err
		}
	}
	if *executions != "" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, e := range m.Executions() {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		if err := matrix.WriteFile(*executions, buf.Bytes()); err != nil {
			return err
		}
	}
	md := m.Markdown()
	if *out == "" {
		_, err := io.WriteString(stdout, md)
		return err
	}
	return matrix.WriteFile(*out, []byte(md))
}
