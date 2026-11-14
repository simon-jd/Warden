package matrix

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"warden/runtimes"
)

// DefaultLimits are the platform's sandbox defaults (cpu 1, 512 MiB, pids
// 128), with a 60 s timeout instead of 300 s so a probe that hangs does not
// hold the matrix for five minutes.
var DefaultLimits = runtimes.Limits{CPU: 1, MemoryMiB: 512, Pids: 128, TimeoutS: 60}

const (
	maxLogBytes    = 8 << 20
	maxOutputBytes = 4 << 10
)

var runtimePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Options configure one runtime's pass over the corpus.
type Options struct {
	Runtime     string          // column name, such as runc, gvisor, firecracker
	ImageDigest string          // image with /bin/sh that every probe runs in
	Limits      runtimes.Limits // zero means DefaultLimits
	Grace       time.Duration   // added to the timeout for the run's context; default 30 s
	Now         func() time.Time
}

// Cell is one probe on one runtime.
type Cell struct {
	Attack     string         `json:"attack"`
	Technique  string         `json:"technique"`
	Runtime    string         `json:"runtime"`
	RunID      string         `json:"run_id"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Verdict    Verdict        `json:"verdict"`
	Reason     string         `json:"reason"`
	Exit       *runtimes.Exit `json:"exit,omitempty"`
	Alerts     []string       `json:"alerts,omitempty"`
	// Output is the start of the run's output, at most 4 KiB.
	Output string `json:"output"`
}

// Results is one runtime's pass, as written to <runtime>.json.
type Results struct {
	Runtime      string          `json:"runtime"`
	ImageDigest  string          `json:"image_digest"`
	CorpusDigest string          `json:"corpus_digest"`
	Limits       runtimes.Limits `json:"limits"`
	Cells        []Cell          `json:"cells"`
}

// Run runs every probe once on rt, one after another, each with no network,
// and returns one cell per probe in corpus order.
func Run(ctx context.Context, rt runtimes.Runtime, attacks []Attack, opt Options) (Results, error) {
	if rt == nil {
		return Results{}, errors.New("no runtime")
	}
	if !runtimePattern.MatchString(opt.Runtime) {
		return Results{}, fmt.Errorf("runtime name %q must match %s", opt.Runtime, runtimePattern)
	}
	if opt.ImageDigest == "" {
		return Results{}, errors.New("image digest required")
	}
	if len(attacks) == 0 {
		return Results{}, errors.New("corpus has no entries")
	}
	if opt.Limits == (runtimes.Limits{}) {
		opt.Limits = DefaultLimits
	}
	if opt.Limits.TimeoutS <= 0 {
		return Results{}, errors.New("timeout must be positive")
	}
	if opt.Grace == 0 {
		opt.Grace = 30 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	res := Results{Runtime: opt.Runtime, ImageDigest: opt.ImageDigest, CorpusDigest: CorpusDigest(attacks), Limits: opt.Limits}
	for _, a := range attacks {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Cells = append(res.Cells, runOne(ctx, rt, a, opt))
	}
	return res, nil
}

// runOne's deferred function fills in the verdict on every return path, so
// the result is named.
func runOne(ctx context.Context, rt runtimes.Runtime, a Attack, opt Options) (c Cell) {
	c = Cell{Attack: a.ID, Technique: a.Technique, Runtime: opt.Runtime}
	var o Observation
	o.RequireProof = strings.HasPrefix(a.Script, "exec /warden-attack ")
	defer func() {
		c.FinishedAt = opt.Now().UTC()
		c.Verdict, c.Reason = Classify(o, a.SuccessSignal)
		c.Output = excerpt(o.Logs)
	}()
	id, err := newRunID()
	if err != nil {
		o.StartErr = err
		return c
	}
	c.RunID = id
	spec := runtimes.Spec{
		RunID:       id,
		ImageDigest: opt.ImageDigest,
		Cmd:         []string{"/bin/sh", "-c", a.Script},
		Limits:      opt.Limits,
		Network:     "none",
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(opt.Limits.TimeoutS)*time.Second+opt.Grace)
	defer cancel()
	c.StartedAt = opt.Now().UTC()
	h, err := rt.Start(runCtx, spec)
	if err != nil {
		o.StartErr = err
		return c
	}
	exit, err := h.Wait(runCtx)
	if err != nil {
		o.WaitErr = err
	} else {
		o.Exit = exit
		c.Exit = &exit
	}
	if logs := h.Logs(); logs == nil {
		o.LogErr = errors.New("runtime returned no log stream")
	} else {
		raw, readErr := io.ReadAll(io.LimitReader(logs, maxLogBytes+1))
		closeErr := logs.Close()
		o.Logs = raw
		switch {
		case readErr != nil:
			o.LogErr = readErr
		case closeErr != nil:
			o.LogErr = closeErr
		case len(raw) > maxLogBytes:
			o.Logs = raw[:maxLogBytes]
			o.Exit.LogsTruncated = true
		}
	}
	o.KillErr = h.Kill()
	return c
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]), nil
}

func excerpt(logs []byte) string {
	if len(logs) > maxOutputBytes {
		return strings.ToValidUTF8(string(logs[:maxOutputBytes]), "�") + "\n[... output cut at 4 KiB]"
	}
	return strings.ToValidUTF8(string(logs), "�")
}
