package runc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"warden/runtimes"
)

type processExit struct {
	code                    uint32
	oom                     bool
	pidsMaxEvents, peakPids uint64
	err                     error
}
type handle struct {
	done     chan struct{}
	logs     *logBuffer
	out      runtimes.Exit
	err      error
	kill     func(context.Context) error
	killOnce sync.Once
	killErr  error
}

func newHandle(timeout time.Duration, logs *logBuffer, exits <-chan processExit, cleanup func(context.Context) (bool, error), kill func(context.Context) error) *handle {
	h := &handle{done: make(chan struct{}), logs: logs, kill: kill}
	go func() {
		defer close(h.done)
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		var result processExit
		select {
		case received, ok := <-exits:
			result = received
			if !ok {
				result.err = errors.New("task exit channel closed without status")
			}
		case <-timer.C:
			h.out.TimedOut = true
			h.err = errors.Join(h.err, h.Kill())
			// Failed kernel cleanup must be observable and must not strand Wait forever.
			select {
			case received, ok := <-exits:
				result = received
				if !ok {
					result.err = errors.New("task exit channel closed without status")
				}
			case <-time.After(10 * time.Second):
				result.err = errors.New("task exit not observed after timeout")
			}
		}
		h.out.Code = result.code
		h.out.OOMKilled = result.oom
		h.out.PidsMaxEvents = result.pidsMaxEvents
		h.out.PeakPids = result.peakPids
		h.err = errors.Join(h.err, result.err, h.Kill())
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		empty, err := cleanup(ctx)
		h.out.CgroupEmpty = empty
		h.out.DroppedLogBytes = h.logs.droppedBytes()
		h.out.LogsTruncated = h.out.DroppedLogBytes > 0
		h.err = errors.Join(h.err, err)
	}()
	return h
}
func (h *handle) Wait(ctx context.Context) (runtimes.Exit, error) {
	select {
	case <-ctx.Done():
		return runtimes.Exit{}, ctx.Err()
	case <-h.done:
		return h.out, h.err
	}
}
func (h *handle) Kill() error {
	h.killOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.killErr = h.kill(ctx)
		if h.killErr != nil {
			h.killErr = fmt.Errorf("kill sandbox subtree: %w", h.killErr)
		}
	})
	return h.killErr
}
func (h *handle) Logs() io.ReadCloser { return h.logs.reader() }

// drainIO preserves buffered output when possible, and bounds a broken shim's
// pipe lifecycle. It is called after subtree termination, before task deletion.
func drainIO(ctx context.Context, streams interface {
	Wait()
	Cancel()
	Close() error
}) error {
	if streams == nil {
		return nil
	}
	drained := make(chan struct{})
	go func() { streams.Wait(); close(drained) }()
	select {
	case <-drained:
		return streams.Close()
	case <-ctx.Done():
		streams.Cancel()
		return errors.Join(ctx.Err(), errors.New("log drain interrupted; output truncated"), streams.Close())
	case <-time.After(time.Second):
		streams.Cancel()
		return errors.Join(errors.New("log drain exceeded grace period; output may be truncated"), streams.Close())
	}
}
