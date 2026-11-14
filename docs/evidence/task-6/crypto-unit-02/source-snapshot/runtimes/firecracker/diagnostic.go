package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"warden/runtimes"
)

// VMM console is untrusted and separate from tenant boundedLog. Only the final
// 16KiB stays in memory; no raw console bytes enter the public failure record.
type vmmTail struct {
	mu      sync.Mutex
	data    [16384]byte
	next    int
	used    int
	dropped uint64
}

type vmmTailView struct {
	*bytes.Reader
	dropped uint64
}

func (v *vmmTailView) Close() error { return nil }

func (b *vmmTail) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	b.dropped += uint64(max(0, b.used+n-len(b.data)))
	b.used = min(len(b.data), b.used+n)
	if n >= len(b.data) {
		copy(b.data[:], p[n-len(b.data):])
		b.next = 0
	} else {
		copied := copy(b.data[b.next:], p)
		copy(b.data[:], p[copied:])
		b.next = (b.next + n) % len(b.data)
	}
	return n, nil
}

func (b *vmmTail) reader() *vmmTailView {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw := make([]byte, b.used)
	start := (b.next - b.used + len(b.data)) % len(b.data)
	n := copy(raw, b.data[start:])
	copy(raw[n:], b.data[:])
	return &vmmTailView{Reader: bytes.NewReader(raw), dropped: b.dropped}
}

type consoleObservation struct {
	Untrusted     bool     `json:"untrusted"`
	RetainedBytes int      `json:"retained_bytes"`
	DroppedBytes  uint64   `json:"dropped_bytes"`
	Truncated     bool     `json:"truncated"`
	RejectedLines int     `json:"rejected_lines"`
	PartialBytes  int      `json:"partial_bytes"`
	Events        []string `json:"events"`
}

var consoleTimestamp = regexp.MustCompile(`^\[ *[0-9]{1,12}\.[0-9]{1,9}\] `)

func (b *vmmTail) observations() consoleObservation {
	view := b.reader()
	defer view.Close()
	raw, _ := io.ReadAll(view)
	result := consoleObservation{Untrusted: true, RetainedBytes: len(raw), DroppedBytes: view.dropped,
		Truncated: view.dropped != 0, Events: []string{}}
	// A cut first/last line is never interpreted as a complete event.
	if view.dropped != 0 {
		n := bytes.IndexByte(raw, '\n')
		if n < 0 {
			result.PartialBytes = len(raw)
			return result
		}
		result.PartialBytes += n + 1
		raw = raw[n+1:]
	}
	seen := map[string]bool{}
	for len(raw) != 0 {
		n := bytes.IndexByte(raw, '\n')
		if n < 0 {
			result.PartialBytes += len(raw)
			break
		}
		line := consoleTimestamp.ReplaceAllString(string(raw[:n]), "")
		raw = raw[n+1:]
		event := ""
		switch {
		case strings.HasPrefix(line, "Kernel panic - not syncing:"):
			event = "kernel_panic"
		case line == "reboot: Restarting system":
			event = "reboot_requested"
		case line == "reboot: Power down":
			event = "power_down_requested"
		case line == "Run /agent as init process":
			event = "agent_init_requested"
		default:
			result.RejectedLines++
		}
		if event != "" && !seen[event] {
			seen[event] = true
			result.Events = append(result.Events, event)
		}
	}
	return result
}

type originalProcessObservation struct {
	Origin           string `json:"origin"`
	State            string `json:"state"`
	WaitComplete     bool   `json:"wait_complete"`
	IOComplete       bool   `json:"io_complete"`
	ExitCode         *int   `json:"exit_code,omitempty"`
	Signal           string `json:"signal"`
	CleanupAttempted bool   `json:"cleanup_attempted"`
	KillSignalResult string `json:"pidfd_kill_result"`
	Context          string `json:"termination_context"`
}

type vmmFailureRecord struct {
	Kind    string                     `json:"kind"`
	Source  string                     `json:"source"`
	RunID   string                     `json:"run_id"`
	Phase   string                     `json:"phase"`
	Failure string                     `json:"failure"`
	Cause   string                     `json:"cause"`
	Cleanup string                     `json:"cleanup"`
	Process originalProcessObservation `json:"process"`
	Console consoleObservation         `json:"console"`
}

type vmmFailure struct {
	public string
	cause  error
}

func (e *vmmFailure) Error() string { return e.public }
func (e *vmmFailure) Unwrap() error { return e.cause }

func diagnosticError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "control_eof"
	default:
		return "unclassified_error"
	}
}

func diagnosticPhase(phase string) string {
	switch phase {
	case "before_boot", "jailer_start", "api_ready", "machine_config", "boot_source", "root_drive", "payload_drive", "vsock", "instance_start", "snapshot_restore", "guest_ready", "bind", "exec", "collect", "retire", "boot_assertion":
		return phase
	default:
		return "unknown"
	}
}

var diagnosticSource = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Called after original cleanup has completed or failed. The error retains its
// internal identity for errors.Is/As; Error and errors.Join never stringify it.
// This record is evidence, never a Gate/FD/cgroup retirement proof.
func (h *vm) failure(phase string, cause, cleanup error) error {
	record := vmmFailureRecord{Kind: "vmm-failure-v1", Source: "unknown", RunID: "unknown",
		Phase: diagnosticPhase(phase), Failure: diagnosticError(cause), Cause: "unknown", Cleanup: "complete",
		Process: h.process.observation(), Console: h.diagnostics.observations()}
	if h.driver != nil && diagnosticSource.MatchString(h.driver.manifest.SourceSHA) {
		record.Source = h.driver.manifest.SourceSHA
	}
	if runPattern.MatchString(h.profile.Spec.RunID) {
		record.RunID = h.profile.Spec.RunID
	}
	if cleanup != nil {
		record.Cleanup = "pending"
	}
	// Every string above is a fixed enum or validated fixed-length binding;
	// events has at most four enums. The record is <4KiB even at integer maxima.
	raw, _ := json.Marshal(record)
	return &vmmFailure{public: string(raw), cause: errors.Join(cause, cleanup)}
}

// The one final boot's assertion must not place tenant bytes or raw decoder /
// API / path errors ahead of the diagnostic in the 1MiB controller attach log.
func bootFailure(h *vm, exit runtimes.Exit, logBytes int, cause, readErr error) string {
	var failure *vmmFailure
	if !errors.As(cause, &failure) {
		cleanup := error(nil)
		if !h.retired.Load() {
			cleanup = ErrCleanupPending
		}
		cause = h.failure("boot_assertion", cause, cleanup)
		errors.As(cause, &failure)
	}
	return fmt.Sprintf("%s boot_exit_code=%d cgroup_empty=%t log_bytes=%d log_read=%s",
		failure.Error(), exit.Code, exit.CgroupEmpty, logBytes, diagnosticError(readErr))
}
