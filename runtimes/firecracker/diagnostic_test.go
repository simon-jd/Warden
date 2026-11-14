package firecracker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"warden/runtimes"
)

const diagnosticSentinel = "Kernel panic - not syncing: Attempted to kill init!\n"
const diagnosticSecret = "SECRET_nonce_environment_API_path_tenant"

func diagnosticVM() *vm {
	return &vm{driver: &Driver{manifest: Manifest{SourceSHA: strings.Repeat("c", 40)}},
		profile: Profile{Spec: runtimes.Spec{RunID: "7J2G4KCYZWPQ3B53EV4TR2RXAI"}},
		done:    make(chan struct{}), executionDeadline: time.Now().Add(time.Minute)}
}

func diagnosticChild(t *testing.T, h *vm, mode string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVMMDiagnosticChild$")
	cmd.Env = []string{"WARDEN_VMM_DIAGNOSTIC_CHILD=" + mode, "GOMAXPROCS=2", "GOMEMLIMIT=1500MiB"}
	cmd.Stdout = &h.diagnostics
	cmd.Stderr = &h.diagnostics
	var err error
	h.process, err = startOwned(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.process.Stop(); err != nil {
			t.Fatal(err)
		}
	})
}

func diagnosticAwait(t *testing.T, p *ownedProcess) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("harmless original child completion timed out")
	}
}

func TestVMMDiagnosticChild(t *testing.T) {
	switch os.Getenv("WARDEN_VMM_DIAGNOSTIC_CHILD") {
	case "tail":
		io.WriteString(os.Stdout, strings.Repeat("prefix private fixture\n", 60000))
		io.WriteString(os.Stderr, diagnosticSecret+"\n"+diagnosticSentinel)
		os.Exit(23)
	case "sleep":
		for {
			time.Sleep(time.Hour)
		}
	case "ok":
		io.WriteString(os.Stdout, "x")
		os.Exit(0)
	default:
		if runtime.Version() != "go1.26.10" {
			t.Fatal("fixed Go1.26.10 required", runtime.Version())
		}
		t.Log("harmless child fixture only; fixed Go1.26.10; no VMM")
	}
}

// Replacing the VMM tail with the tenant prefix buffer loses the final event.
func TestVMMDiagnosticTailKeepsFinalOriginalChildOutput(t *testing.T) {
	h := diagnosticVM()
	diagnosticChild(t, h, "tail")
	diagnosticAwait(t, h.process)
	reader := h.diagnostics.reader()
	raw, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || len(raw) > 16384 || !strings.HasSuffix(string(raw), diagnosticSentinel) {
		t.Fatalf("final event lost or retention unbounded: bytes=%d final=%t read_error=%t", len(raw), strings.HasSuffix(string(raw), diagnosticSentinel), err != nil)
	}
	if h.process.cmd.ProcessState.ExitCode() != 23 {
		t.Fatal("original child exit status was lost")
	}
}

// The real protocol decoder includes unknown field names in its error. Those
// arbitrary bytes must not escape through the failure/cleanup error string.
func TestVMMDiagnosticFailureEnvelopeSanitizesAndBinds(t *testing.T) {
	h := diagnosticVM()
	diagnosticChild(t, h, "tail")
	diagnosticAwait(t, h.process)
	client, server := net.Pipe()
	h.conn = client
	go func() {
		defer server.Close()
		raw := []byte(`{"version":1,"` + diagnosticSecret + `":true}`)
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
		server.Write(prefix[:])
		server.Write(raw)
	}()
	h.collect()
	_, err := h.Wait(context.Background())
	if err == nil {
		t.Fatal("invalid protocol accepted")
	}
	public := errors.Join(err, ErrCleanupPending).Error()
	if strings.Contains(public, diagnosticSecret) || strings.Contains(public, diagnosticSentinel) {
		t.Error("raw untrusted data escaped failure/cleanup error")
	}
	var record map[string]any
	if json.Unmarshal([]byte(err.Error()), &record) != nil || record["kind"] != "vmm-failure-v1" || record["source"] != strings.Repeat("c", 40) || record["run_id"] != "7J2G4KCYZWPQ3B53EV4TR2RXAI" || record["phase"] != "collect" {
		t.Fatal("missing bounded source/RunID/phase failure record")
	}
}

func diagnosticRecord(t *testing.T, err error) vmmFailureRecord {
	t.Helper()
	var record vmmFailureRecord
	if err == nil || len(err.Error()) > 4096 || json.Unmarshal([]byte(err.Error()), &record) != nil {
		t.Fatal("missing bounded diagnostic JSON")
	}
	return record
}

func TestVMMDiagnosticNaturalAndCleanupStatusStayDistinct(t *testing.T) {
	for _, mode := range []string{"tail", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			h := diagnosticVM()
			diagnosticChild(t, h, mode)
			if mode == "tail" {
				diagnosticAwait(t, h.process)
			}
			cleanup := h.retire()
			record := diagnosticRecord(t, h.failure("guest_ready", errors.New(diagnosticSecret), cleanup))
			status := record.Process
			if !status.WaitComplete || !status.IOComplete || status.Origin != "original_child" {
				t.Fatal("original completion/I/O missing", status)
			}
			if mode == "tail" {
				if status.State != "exited" || status.ExitCode == nil || *status.ExitCode != 23 || status.CleanupAttempted || status.Context != "completed_before_cleanup" {
					t.Fatal("natural original completion misattributed", status)
				}
				if !record.Console.Untrusted || !record.Console.Truncated || record.Console.DroppedBytes == 0 || record.Console.RetainedBytes != 16384 || len(record.Console.Events) != 1 || record.Console.Events[0] != "kernel_panic" {
					t.Fatal("bounded final console observation lost", record.Console)
				}
			} else if status.State != "signaled" || status.Signal != "sigkill" || status.ExitCode != nil || !status.CleanupAttempted || status.Context != "cleanup_may_have_terminated" || status.KillSignalResult != "sent" {
				t.Fatal("cleanup signal misreported as spontaneous", status)
			}
			if strings.Contains(record.Failure, diagnosticSecret) || record.Cause != "unknown" {
				t.Fatal("termination observation became a causal claim")
			}
		})
	}
}

func TestVMMDiagnosticUnknownWaitNeverBecomesExitZero(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	for _, p := range []*ownedProcess{nil, {done: make(chan struct{}), cmd: &exec.Cmd{}},
		{done: closed, cmd: &exec.Cmd{}}, {done: closed, cmd: &exec.Cmd{}, waitErr: errors.New(diagnosticSecret)}} {
		h := diagnosticVM()
		h.process = p
		record := diagnosticRecord(t, h.failure("guest_ready", errors.New(diagnosticSecret), ErrCleanupPending))
		if record.Process.ExitCode != nil || record.Process.Signal != "unknown" || record.Process.IOComplete || record.Cleanup != "pending" || !errors.Is(h.failure("guest_ready", nil, ErrCleanupPending), ErrCleanupPending) {
			t.Fatal("unknown owner/wait was promoted to completed exit or lost ambiguity", record.Process)
		}
		if strings.Contains(errors.Join(h.failure("guest_ready", errors.New(diagnosticSecret), ErrCleanupPending), ErrCleanupPending).Error(), diagnosticSecret) {
			t.Fatal("internal error leaked through errors.Join")
		}
	}
}

func TestVMMDiagnosticSanitizationAndBootOutputBound(t *testing.T) {
	h := diagnosticVM()
	h.diagnostics.Write([]byte(strings.Repeat(diagnosticSecret+"\n", 1000)))
	h.diagnostics.Write([]byte("[    0.000001] Kernel panic - not syncing: " + diagnosticSecret + "\nreboot: Restarting system\n"))
	h.logs.Write([]byte(strings.Repeat(diagnosticSecret, 40000)))
	err := h.failure("guest_ready", errors.New(diagnosticSecret), errors.New(diagnosticSecret))
	record := diagnosticRecord(t, err)
	if record.Console.RejectedLines == 0 || !record.Console.Untrusted || len(record.Console.Events) != 2 || strings.Contains(err.Error(), diagnosticSecret) {
		t.Fatal("non-allowlisted console leaked or trusted", record.Console)
	}
	public := bootFailure(h, runtimes.Exit{Code: 137}, 1048576, err, errors.New(diagnosticSecret))
	if len(public) > 8192 || strings.Contains(public, diagnosticSecret) || !strings.Contains(public, `"kind":"vmm-failure-v1"`) {
		t.Fatal("boot failure can leak or displace diagnostic")
	}
	// Maximal invalid bindings, arbitrary phases and unterminated lines never
	// become public free-form fields. Tenant prefix retention remains unchanged.
	h.driver.manifest.SourceSHA = strings.Repeat(diagnosticSecret, 1000)
	h.profile.Spec.RunID = diagnosticSecret
	h.diagnostics.Write([]byte(strings.Repeat("x", 20000)))
	unknown := diagnosticRecord(t, h.failure(diagnosticSecret, errors.New(diagnosticSecret), nil))
	if unknown.Source != "unknown" || unknown.RunID != "unknown" || unknown.Phase != "unknown" || len(unknown.Console.Events) != 0 || unknown.Console.PartialBytes == 0 {
		t.Fatal("invalid binding or partial console accepted")
	}
	reader := h.Logs()
	raw, _ := io.ReadAll(reader)
	reader.Close()
	if len(raw) != 1048576 || !strings.HasPrefix(string(raw), diagnosticSecret) {
		t.Fatal("tenant prefix semantics changed")
	}
}

type diagnosticBrokenWriter struct{}

func (diagnosticBrokenWriter) Write([]byte) (int, error) {
	return 0, errors.New(diagnosticSecret)
}

func TestVMMDiagnosticOriginalIOWaitErrorRemainsUnknown(t *testing.T) {
	h := diagnosticVM()
	cmd := exec.Command(os.Args[0], "-test.run=^TestVMMDiagnosticChild$")
	cmd.Env = []string{"WARDEN_VMM_DIAGNOSTIC_CHILD=ok", "GOMAXPROCS=2"}
	cmd.Stdout = diagnosticBrokenWriter{}
	p, err := startOwned(cmd)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture alone owns the actual already-reaped child descriptor. The
	// production Stop must still refuse a non-exit Wait error without retiring it.
	defer unix.Close(p.pidfd)
	h.process = p
	diagnosticAwait(t, p)
	var exit *exec.ExitError
	if p.waitErr == nil || errors.As(p.waitErr, &exit) || cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("fixture did not produce an original non-exit I/O Wait error")
	}
	err = h.retire()
	if err == nil || !errors.Is(err, ErrCleanupPending) || strings.Contains(err.Error(), diagnosticSecret) {
		t.Fatal("retire lost pending state or leaked original I/O error")
	}
	record := diagnosticRecord(t, err)
	if record.Process.State != "unknown" || record.Process.ExitCode != nil || record.Process.IOComplete || !record.Process.WaitComplete || record.Phase != "retire" || h.retired.Load() {
		t.Fatal("non-exit Wait error promoted to exit0 or retirement", record.Process)
	}
}
