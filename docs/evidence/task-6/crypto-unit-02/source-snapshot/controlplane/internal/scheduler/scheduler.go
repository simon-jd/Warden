// Package scheduler executes durable claims independently of HTTP requests.
package scheduler

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"warden/controlplane/internal/runs"
	"warden/runtimes"
	"warden/runtimes/gate"
)

type Scheduler struct {
	Store            *runs.Store
	Drivers          map[string]*gate.Gate
	Node             string
	Concurrency      int
	PollInterval     time.Duration
	OperationTimeout time.Duration
}

func (s *Scheduler) timeout() time.Duration {
	if s.OperationTimeout > 0 {
		return s.OperationTimeout
	}
	return 30 * time.Second
}
func (s *Scheduler) bounded() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout())
}
func (s *Scheduler) validate() error {
	if s.Store == nil || s.Store.Pool == nil || s.Node == "" {
		return errors.New("scheduler store and stable runtime node required")
	}
	if s.Concurrency < 0 || s.Concurrency > 32 || s.PollInterval < 0 || s.OperationTimeout < 0 {
		return errors.New("invalid scheduler bounds")
	}
	authority := ""
	for name, d := range s.Drivers {
		if (name != "runc" && name != "gvisor" && name != "firecracker") || d == nil || d.Node() != s.Node {
			return errors.New("invalid runtime registry or node binding")
		}
		if authority != "" && authority != d.Authority() {
			return errors.New("runtime drivers must share durable node gate")
		}
		authority = d.Authority()
	}
	return nil
}

// Authority routes recovery to the same durable runtime-node gate. Recreating
// the directory yields a new authority and cannot recover an old node.
func (s *Scheduler) Authority() string {
	for _, d := range s.Drivers {
		if d != nil {
			return d.Authority()
		}
	}
	return s.Node + "/unavailable"
}

// Run owns a bounded number of workers. A failed database operation is retried
// on the next poll; Process never retries Start for an already claimed run.
func (s *Scheduler) Run(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	n := s.Concurrency
	if n == 0 {
		n = 2
	}
	poll := s.PollInterval
	if poll < 10*time.Millisecond {
		poll = 250 * time.Millisecond
	}
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				query, cancel := context.WithTimeout(ctx, s.timeout())
				ids, err := s.Store.Candidates(query, s.Authority(), 128)
				cancel()
				if err == nil {
					for _, id := range ids {
						if ctx.Err() != nil {
							break
						}
						_ = s.Process(ctx, id)
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(poll):
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func (s *Scheduler) finish(c *runs.Claim, out runs.Completion) error {
	ctx, cancel := s.bounded()
	defer cancel()
	return c.Finish(ctx, out)
}
func (s *Scheduler) reap(d *gate.Gate, id string) error {
	ctx, cancel := s.bounded()
	defer cancel()
	return d.Reap(ctx, id)
}
func lostLogs() runs.Logs { return runs.Logs{Lines: []string{}, Status: "lost"} }

// Process executes one claim. Runtime failures become durable safe error codes;
// database failures return to the worker and leave the claim for Reap recovery.
func (s *Scheduler) Process(ctx context.Context, id string) error {
	if err := s.validate(); err != nil {
		return err
	}
	db, cancel := context.WithTimeout(ctx, s.timeout())
	c, err := s.Store.Claim(db, id, s.Authority())
	cancel()
	if err != nil {
		return err
	}
	defer c.Close()
	d := s.Drivers[c.Spec.Runtime]
	if d == nil {
		return s.finish(c, runs.Completion{State: "failed", ErrorCode: "runtime_unavailable", Logs: lostLogs(), CleanupPending: c.Recovery})
	}
	if c.Recovery {
		proofCtx, proofCancel := s.bounded()
		proof, proofErr := d.Reconciliation(proofCtx, id)
		proofCancel()
		if proofErr == nil {
			return s.finish(c, runs.Completion{State: "interrupted", ErrorCode: "node_retired", Logs: lostLogs(), Reconciliation: proof})
		}
		err = s.reap(d, id)
		out := runs.Completion{State: "interrupted", ErrorCode: "worker_lost", Logs: lostLogs()}
		if err != nil {
			out.State = "failed"
			out.ErrorCode = "cleanup_failed"
			if errors.Is(err, gate.ErrAmbiguous) {
				out.ErrorCode = "creation_outcome_unknown"
			}
			out.CleanupPending = true
		}
		return s.finish(c, out)
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	// Loss of the owning session cancels work. A stale launch is additionally
	// fenced at the actual runtime boundary by the durable gate, not just this ping.
	monitorDone := make(chan struct{})
	defer func() { stop(); <-monitorDone }()
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				check, cancel := context.WithTimeout(runCtx, s.timeout())
				err := c.Check(check)
				cancel()
				if err != nil {
					stop()
					return
				}
			}
		}
	}()
	check, cancel := context.WithTimeout(runCtx, s.timeout())
	err = c.Check(check)
	cancel()
	if err != nil {
		return err
	}
	auth, cancel := context.WithTimeout(runCtx, s.timeout())
	err = s.Store.Authorize(auth, c.TenantID, c.Spec)
	cancel()
	if err != nil {
		out := runs.Completion{State: "failed", ErrorCode: "policy_unavailable", Logs: runs.Logs{Lines: []string{}, Status: "not_started"}}
		if errors.Is(err, runs.ErrForbidden) {
			out.State = "denied"
			out.ErrorCode = "policy_denied"
		}
		return s.finish(c, out)
	}
	// No async request context reaches this call. Authorization uses persisted
	// tenant/spec and occurs immediately adjacent to the actual guarded Start.
	launch, cancel := context.WithTimeout(runCtx, s.timeout())
	h, err := d.Start(launch, runtimes.Spec{RunID: id, ImageDigest: c.Spec.ImageDigest, Cmd: c.Spec.Cmd, Limits: runtimes.Limits{CPU: c.Spec.Limits.CPU, MemoryMiB: c.Spec.Limits.MemoryMiB, Pids: c.Spec.Limits.Pids, TimeoutS: c.Spec.Limits.TimeoutS}, Network: c.Spec.Network, AllowDomains: c.Spec.AllowDomains})
	cancel()
	if err != nil {
		if h != nil {
			_ = s.kill(h)
		}
		cleanupErr := s.reap(d, id)
		code := "runtime_start_failed"
		if errors.Is(cleanupErr, gate.ErrAmbiguous) {
			code = "runtime_start_ambiguous"
		}
		return s.finish(c, runs.Completion{State: "failed", ErrorCode: code, Logs: lostLogs(), CleanupPending: cleanupErr != nil})
	}
	db, cancel = s.bounded()
	err = c.Running(db)
	cancel()
	if err != nil {
		_ = s.kill(h)
		_ = s.reap(d, id)
		return err
	}
	wait, cancel := context.WithTimeout(runCtx, time.Duration(c.Spec.Limits.TimeoutS)*time.Second+s.timeout())
	exit, waitErr := h.Wait(wait)
	cancel()
	out := runs.Completion{State: "succeeded", Result: &exit, Logs: lostLogs()}
	switch {
	case waitErr != nil:
		out.State = "failed"
		out.ErrorCode = "runtime_wait_failed"
		out.CleanupPending = true
	case !exit.CgroupEmpty:
		out.State = "failed"
		out.ErrorCode = "cleanup_failed"
		out.CleanupPending = true
	case exit.OOMKilled:
		out.State = "failed"
		out.ErrorCode = "oom_killed"
	case exit.TimedOut:
		out.State = "failed"
		out.ErrorCode = "timed_out"
	case exit.Code != 0:
		out.State = "failed"
		out.ErrorCode = "exit_nonzero"
	}
	if runCtx.Err() != nil || errors.Is(waitErr, context.DeadlineExceeded) {
		killErr := s.kill(h)
		reapErr := s.reap(d, id)
		out.State = "interrupted"
		out.ErrorCode = "worker_stopped"
		out.CleanupPending = killErr != nil || reapErr != nil
		// Wait returned no trustworthy exit evidence. Recovery must not invent it.
		out.Result = nil
	}
	logs, logErr := s.collect(h, exit)
	out.Logs = logs
	if out.State == "interrupted" && out.Logs.Status == "complete" {
		out.Logs.Status = "partial"
		if len(out.Logs.Lines) == 0 {
			out.Logs.Status = "lost"
		}
	}
	if logErr != nil && out.ErrorCode == "" {
		out.State = "failed"
		out.ErrorCode = "log_read_failed"
	}
	return s.finish(c, out)
}
func (s *Scheduler) kill(h runtimes.Handle) error {
	done := make(chan error, 1)
	go func() { done <- h.Kill() }()
	ctx, cancel := s.bounded()
	defer cancel()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Scheduler) collect(h runtimes.Handle, exit runtimes.Exit) (runs.Logs, error) {
	type result struct {
		logs runs.Logs
		err  error
	}
	ctx, cancel := s.bounded()
	defer cancel()
	done := make(chan result, 1)
	// Unbuffered publication transfers timeout-cleanup ownership to the caller.
	// If it has already returned, the producer must close its own late snapshot.
	opened := make(chan func() error)
	go func() {
		reader := h.Logs()
		if reader == nil {
			done <- result{lostLogs(), errors.New("missing log snapshot")}
			return
		}
		var closeOnce sync.Once
		var snapshotCloseErr error
		closeSnapshot := func() error {
			closeOnce.Do(func() { snapshotCloseErr = reader.Close() })
			return snapshotCloseErr
		}
		select {
		case opened <- closeSnapshot:
		case <-ctx.Done():
			_ = closeSnapshot()
			return
		}
		// Runtime Logs is a snapshot contract, not a live pipe. Retain at most 1MiB
		// while counting discarded bytes; a broken reader is bounded by the caller.
		buffer := make([]byte, 32<<10)
		kept := make([]byte, 0, runs.LogLimit)
		var total uint64
		var readErr error
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				total += uint64(n)
				room := runs.LogLimit - len(kept)
				if room > n {
					room = n
				}
				kept = append(kept, buffer[:room]...)
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					readErr = err
				}
				break
			}
			if n == 0 {
				readErr = io.ErrNoProgress
				break
			}
		}
		closeErr := closeSnapshot()
		if readErr == nil {
			readErr = closeErr
		}
		// PostgreSQL JSONB cannot represent NUL, and JSON strings cannot preserve
		// invalid UTF-8. Encode binary snapshots explicitly; cap the encoded data too.
		encoding := ""
		retained := len(kept)
		text := string(kept)
		if !utf8.Valid(kept) || strings.IndexByte(text, 0) >= 0 {
			encoding = "base64"
			if retained > runs.LogLimit/4*3 {
				retained = runs.LogLimit / 4 * 3
			}
			text = base64.StdEncoding.EncodeToString(kept[:retained])
		}
		logs := runs.Logs{Lines: []string{}, Status: "complete", Encoding: encoding, Truncated: exit.LogsTruncated || total > uint64(retained), DroppedBytes: exit.DroppedLogBytes + total - uint64(retained)}
		if len(text) > 0 {
			logs.Lines = []string{text}
		}
		if readErr != nil {
			logs.Status = "partial"
			if len(text) == 0 {
				logs.Status = "lost"
			}
		}
		done <- result{logs, readErr}
	}()
	var closeSnapshot func() error
	select {
	case closeSnapshot = <-opened:
	case result := <-done:
		return result.logs, result.err
	case <-ctx.Done():
		return lostLogs(), ctx.Err()
	}
	select {
	case result := <-done:
		return result.logs, result.err
	case <-ctx.Done():
		go func() { _ = closeSnapshot() }()
		return lostLogs(), ctx.Err()
	}
}
