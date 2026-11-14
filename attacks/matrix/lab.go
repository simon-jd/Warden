package matrix

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"warden/runtimes"
)

// RunFromEnv is the hook each runtime's lab test calls with its live runtime.
// It runs the corpus in WARDEN_MATRIX_CORPUS and writes
// WARDEN_MATRIX_OUT/<runtime>.json. Without WARDEN_MATRIX_CORPUS it skips, so
// the lab tests behave as before.
//
//	WARDEN_MATRIX_CORPUS        corpus directory (absolute)
//	WARDEN_MATRIX_OUT           existing directory for the results (absolute)
//	WARDEN_MATRIX_IMAGE_DIGEST  image with /bin/sh; default WARDEN_LAB_IMAGE_DIGEST
//	WARDEN_MATRIX_TIMEOUT_S     per-probe timeout; default 60
//
// A cell with verdict error fails the test, because the matrix is then
// incomplete. blocked, missed and detected are results, not failures.
func RunFromEnv(t *testing.T, rt runtimes.Runtime, runtime string) {
	t.Helper()
	t.Run("IsolationMatrix", func(t *testing.T) {
		corpus := os.Getenv("WARDEN_MATRIX_CORPUS")
		if corpus == "" {
			t.Skip("isolation matrix: set WARDEN_MATRIX_CORPUS and WARDEN_MATRIX_OUT to run it")
		}
		out := os.Getenv("WARDEN_MATRIX_OUT")
		if !filepath.IsAbs(corpus) || !filepath.IsAbs(out) {
			t.Fatal("WARDEN_MATRIX_CORPUS and WARDEN_MATRIX_OUT must be absolute paths")
		}
		if info, err := os.Stat(out); err != nil || !info.IsDir() {
			t.Fatalf("WARDEN_MATRIX_OUT %s is not a directory", out)
		}
		image := os.Getenv("WARDEN_MATRIX_IMAGE_DIGEST")
		if image == "" {
			image = os.Getenv("WARDEN_LAB_IMAGE_DIGEST")
		}
		limits := DefaultLimits
		if s := os.Getenv("WARDEN_MATRIX_TIMEOUT_S"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 3600 {
				t.Fatalf("WARDEN_MATRIX_TIMEOUT_S %q must be 1..3600", s)
			}
			limits.TimeoutS = n
		}
		attacks, err := LoadCorpus(corpus)
		if err != nil {
			t.Fatal(err)
		}
		budget := time.Duration(len(attacks)) * (time.Duration(limits.TimeoutS)*time.Second + time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		res, err := Run(ctx, rt, attacks, Options{Runtime: runtime, ImageDigest: image, Limits: limits})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteResults(filepath.Join(out, runtime+".json"), res); err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Cells {
			t.Logf("%s on %s: %s (%s) run %s", c.Attack, runtime, c.Verdict, c.Reason, c.RunID)
			if c.Verdict == Error {
				t.Errorf("%s on %s: no verdict: %s", c.Attack, runtime, c.Reason)
			}
		}
	})
}

// WriteResults writes one pass as indented JSON, replacing path atomically.
func WriteResults(path string, res Results) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'))
}

// ReadResults reads a file WriteResults wrote.
func ReadResults(path string) (Results, error) {
	var res Results
	data, err := os.ReadFile(path)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(data, &res)
	return res, err
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteFile replaces path atomically; the matrix command uses it for its outputs.
func WriteFile(path string, data []byte) error { return writeAtomic(path, data) }
