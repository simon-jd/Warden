// Package conformance runs the same real guest behaviors against each driver.
// A skipped lab test is an unfulfilled external acceptance gate, never a pass.
package conformance

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"warden/runtimes"
)

// Run requires a pre-imported image containing /warden-probe built from guest/.
// Callers must provide a dedicated lab runtime, never a shared host daemon.
func Run(t *testing.T, rt runtimes.Runtime) {
	for _, tc := range []struct {
		name, mode            string
		memory, pids, timeout int
		oom, timedOut         bool
	}{
		{"ForkBombCappedByPids", "fork", 128, 32, 15, false, false},
		{"RootfsReadOnly", "readonly", 128, 32, 10, false, false},
		{"NoNetworkByDefault", "network", 128, 32, 10, false, false},
		{"RunsAsNonRoot", "uid", 128, 32, 10, false, false},
		{"TimeoutKillsProcessGroup", "timeout", 128, 32, 2, false, true},
		{"MemoryLimitOOMKilled", "oom", 64, 32, 15, true, false},
		{"SeccompBlocksMountAndPtrace", "seccomp", 128, 32, 10, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getenv("WARDEN_LAB_ACK") != "dedicated-warden-lab" {
				t.Skip("live lab test: needs WARDEN_LAB_ACK=dedicated-warden-lab on the dedicated lab daemon (never the shared host)")
			}
			digest := os.Getenv("WARDEN_LAB_IMAGE_DIGEST")
			if digest == "" || rt == nil {
				t.Fatal("dedicated lab runtime and immutable probe image digest required")
			}
			var random [16]byte
			if _, e := rand.Read(random[:]); e != nil {
				t.Fatal(e)
			}
			spec := runtimes.Spec{RunID: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:]), ImageDigest: digest, Cmd: []string{"/warden-probe", tc.mode}, Limits: runtimes.Limits{CPU: 1, MemoryMiB: tc.memory, Pids: tc.pids, TimeoutS: tc.timeout}, Network: "none"}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			h, e := rt.Start(ctx, spec)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := h.Kill(); e != nil {
					t.Errorf("cleanup: %v", e)
				}
			}()
			out, e := h.Wait(ctx)
			logs := h.Logs()
			raw, readErr := io.ReadAll(logs)
			closeErr := logs.Close()
			t.Logf("real guest mode=%s exit=%+v logs=%s", tc.mode, out, raw)
			if e != nil || readErr != nil || closeErr != nil {
				t.Fatalf("runtime/log error: %v %v %v", e, readErr, closeErr)
			}
			if tc.mode == "fork" && (out.PidsMaxEvents == 0 || out.PeakPids != uint64(tc.pids)) {
				t.Fatalf("fork did not demonstrate target pids controller limit: %+v", out)
			}
			if out.LogsTruncated {
				t.Fatalf("guest evidence logs truncated: dropped=%d", out.DroppedLogBytes)
			}
			if !out.CgroupEmpty {
				t.Fatal("entire cgroup subtree must be empty after every exit")
			}
			if out.OOMKilled != tc.oom || out.TimedOut != tc.timedOut {
				t.Fatalf("wrong termination: %+v", out)
			}
			if tc.oom || tc.timedOut {
				if out.Code == 0 || !strings.Contains(string(raw), "READY "+tc.mode) {
					t.Fatalf("guest did not reach attack behavior: %+v %q", out, raw)
				}
			} else if out.Code != 0 || strings.TrimSpace(string(raw)) != "PASS "+tc.mode {
				t.Fatalf("guest behavior failed: %+v %q", out, raw)
			}
		})
	}
}
