// Package matrix runs a corpus of isolation probes against the sandbox
// runtimes and reports, for every probe and runtime, whether the probe was
// blocked, detected or missed.
//
// A corpus is a directory with one subdirectory per probe. Each subdirectory
// holds run.sh (the probe, run by /bin/sh inside the sandbox) and expect.yaml:
//
//	id: <directory name>
//	technique: T1611
//	success_signal: <string the probe prints only when it reached its goal>
package matrix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxScriptBytes = 64 << 10
	maxExpectBytes = 4 << 10
	maxSignalBytes = 256
)

var (
	idPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	techniquePattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

// Attack is one corpus entry.
type Attack struct {
	ID            string `json:"id"`
	Technique     string `json:"technique"`
	SuccessSignal string `json:"success_signal"`
	// Digest is sha256 over expect.yaml, a zero byte and run.sh.
	Digest string `json:"digest"`
	Script string `json:"-"`
}

// LoadCorpus reads every subdirectory of dir and returns the entries sorted
// by id. Files directly in dir (a README, say) are ignored.
func LoadCorpus(dir string) ([]Attack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var attacks []Attack
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: symlinks are not corpus entries", e.Name())
		}
		if !e.IsDir() {
			continue
		}
		a, err := loadAttack(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if a.ID != e.Name() {
			return nil, fmt.Errorf("%s: id %q does not match the directory name", e.Name(), a.ID)
		}
		attacks = append(attacks, a)
	}
	if len(attacks) == 0 {
		return nil, errors.New("corpus has no entries")
	}
	sort.Slice(attacks, func(i, j int) bool { return attacks[i].ID < attacks[j].ID })
	return attacks, nil
}

// CorpusDigest identifies a whole corpus: sha256 over the sorted entry digests.
func CorpusDigest(attacks []Attack) string {
	digests := make([]string, len(attacks))
	for i, a := range attacks {
		digests[i] = a.ID + " " + a.Digest
	}
	sort.Strings(digests)
	sum := sha256.Sum256([]byte(strings.Join(digests, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func loadAttack(dir string) (Attack, error) {
	expect, err := readRegular(filepath.Join(dir, "expect.yaml"), maxExpectBytes)
	if err != nil {
		return Attack{}, err
	}
	script, err := readRegular(filepath.Join(dir, "run.sh"), maxScriptBytes)
	if err != nil {
		return Attack{}, err
	}
	a, err := ParseExpect(expect)
	if err != nil {
		return Attack{}, fmt.Errorf("expect.yaml: %w", err)
	}
	if len(bytes.TrimSpace(script)) == 0 {
		return Attack{}, errors.New("run.sh is empty")
	}
	// The verdict rests on the signal appearing in the output. A shell error
	// message can echo a line of the script, so the script must build the
	// signal at run time rather than contain it.
	if bytes.Contains(script, []byte(a.SuccessSignal)) {
		return Attack{}, errors.New("run.sh contains success_signal literally; build it at run time (for example printf '%s_%s\\n' PART1 PART2)")
	}
	sum := sha256.New()
	sum.Write(expect)
	sum.Write([]byte{0})
	sum.Write(script)
	a.Digest = "sha256:" + hex.EncodeToString(sum.Sum(nil))
	a.Script = string(script)
	return a, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

// ParseExpect reads expect.yaml. It accepts the flat subset the corpus needs:
// one "key: value" per line, values plain or quoted, # comments, and an
// optional leading "---". The keys id, technique and success_signal are all
// required and nothing else is allowed.
func ParseExpect(data []byte) (Attack, error) {
	var a Attack
	seen := map[string]bool{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || (n == 0 && trimmed == "---") {
			continue
		}
		if line != strings.TrimLeft(line, " \t") {
			return a, fmt.Errorf("line %d: nested values are not supported", n+1)
		}
		key, raw, ok := strings.Cut(line, ":")
		if !ok {
			return a, fmt.Errorf("line %d: want key: value", n+1)
		}
		key = strings.TrimSpace(key)
		value, err := scalar(raw)
		if err != nil {
			return a, fmt.Errorf("line %d: %w", n+1, err)
		}
		if seen[key] {
			return a, fmt.Errorf("line %d: duplicate key %q", n+1, key)
		}
		seen[key] = true
		switch key {
		case "id":
			a.ID = value
		case "technique":
			a.Technique = value
		case "success_signal":
			a.SuccessSignal = value
		default:
			return a, fmt.Errorf("line %d: unknown key %q", n+1, key)
		}
	}
	switch {
	case !idPattern.MatchString(a.ID):
		return a, errors.New("id must match " + idPattern.String())
	case !techniquePattern.MatchString(a.Technique):
		return a, errors.New("technique must be an ATT&CK ID such as T1611 or T1611.001")
	case strings.TrimSpace(a.SuccessSignal) == "" || strings.ContainsAny(a.SuccessSignal, "\r\n"):
		return a, errors.New("success_signal must be one non-empty line")
	case len(a.SuccessSignal) > maxSignalBytes:
		return a, fmt.Errorf("success_signal is longer than %d bytes", maxSignalBytes)
	}
	return a, nil
}

func scalar(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, `"`):
		end := closingQuote(s)
		if end < 0 {
			return "", errors.New("unterminated double-quoted value")
		}
		if rest := strings.TrimSpace(s[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("text after a quoted value")
		}
		return strconv.Unquote(s[:end+1])
	case strings.HasPrefix(s, "'"):
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] != '\'' {
				b.WriteByte(s[i])
				continue
			}
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			if rest := strings.TrimSpace(s[i+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
				return "", errors.New("text after a quoted value")
			}
			return b.String(), nil
		}
		return "", errors.New("unterminated single-quoted value")
	default:
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s != "" && strings.ContainsAny(s[:1], "[{&*!|>%@`") {
			return "", errors.New("quote values that start with a YAML indicator")
		}
		return s, nil
	}
}

func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}
