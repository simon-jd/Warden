package firecracker

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"warden/attacks/matrix"
	"warden/runtimes"
	"warden/runtimes/conformance"
	"warden/runtimes/gate"
)

func reviewedLab(t *testing.T, mode string) (*Driver, *gate.Gate) {
	t.Helper()
	if os.Getenv("WARDEN_FC_REVIEWED") != "controller-reviewed" || os.Getenv("WARDEN_FC_MODE") != mode {
		t.Skip("live KVM test: runs only inside the Firecracker lab node (scripts/firecracker_lab.py sets WARDEN_FC_REVIEWED and WARDEN_FC_MODE)")
	}
	d, g, e := Open()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := d.Close(); e != nil {
			t.Errorf("original process/FD/data retirement: %v", e)
		}
	})
	t.Setenv("WARDEN_LAB_ACK", "dedicated-warden-lab")
	t.Setenv("WARDEN_LAB_IMAGE_DIGEST", d.manifest.ImageDigest)
	return d, g
}
func labSpec(t *testing.T, d *Driver, mode string) runtimes.Spec {
	t.Helper()
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		t.Fatal(e)
	}
	return runtimes.Spec{RunID: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]), ImageDigest: d.manifest.ImageDigest, Cmd: []string{"/warden-probe", mode}, Network: "none"}
}
func TestFirecrackerConformance(t *testing.T) {
	_, g := reviewedLab(t, "conformance")
	conformance.Run(t, g)
	if _, err := os.Stat(inputPath + "/corpus"); err == nil {
		out := sessionPath + "/node/matrix"
		if err := os.Mkdir(out, 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("WARDEN_MATRIX_CORPUS", inputPath+"/corpus")
		t.Setenv("WARDEN_MATRIX_OUT", out)
		// Metadata retirement requires private files even on a failing matrix.
		defer func() {
			if err := os.Chmod(filepath.Join(out, "firecracker.json"), 0600); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}()
	}
	matrix.RunFromEnv(t, g, "firecracker")
}
func TestFirecrackerBoot(t *testing.T) {
	d, g := reviewedLab(t, "boot")
	s := labSpec(t, d, "uid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, e := g.Start(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	out, e := h.Wait(ctx)
	logs := h.Logs()
	raw, re := io.ReadAll(logs)
	logs.Close()
	if e != nil || re != nil || out.Code != 0 || !out.CgroupEmpty || string(raw) != "PASS uid\n" {
		t.Fatal(bootFailure(h.(*vm), out, len(raw), e, re))
	}
	if e = g.Reap(ctx, s.RunID); e != nil {
		t.Fatal(e)
	}
	if _, e = g.Start(ctx, s); !errors.Is(e, gate.ErrConsumed) {
		t.Fatalf("RunID replay: %v", e)
	}
	ready, start := h.(*vm).Timings()
	t.Logf("actual agent_ready_ns=%d driver_start_EXEC_ack_ns=%d uid=%d exit=%+v", ready, start, h.(*vm).uid, out)
}
func TestSnapshotRestoreFasterThanBoot(t *testing.T) {
	d, g := reviewedLab(t, "snapshot")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	key, e := d.PrepareBaseline(ctx, labSpec(t, d, "uid"), false)
	if e != nil {
		t.Fatal(e)
	}
	cold, restored, readyCold, readyRestore := []time.Duration{}, []time.Duration{}, []time.Duration{}, []time.Duration{}
	for i := 0; i < 20; i++ {
		for _, restore := range []bool{false, true} {
			s := labSpec(t, d, "uid")
			var handle runtimes.Handle
			if restore {
				handle, e = d.StartRestored(ctx, s, false, key)
			} else {
				handle, e = g.Start(ctx, s)
			}
			if e != nil {
				t.Fatal(e)
			}
			out, e := handle.Wait(ctx)
			logs := handle.Logs()
			raw, re := io.ReadAll(logs)
			logs.Close()
			if e != nil || re != nil || out.Code != 0 || !out.CgroupEmpty || string(raw) != "PASS uid\n" {
				t.Fatalf("pair=%d restore=%v exit=%+v logs=%q err=%v %v", i, restore, out, raw, e, re)
			}
			if e = g.Reap(ctx, s.RunID); e != nil {
				t.Fatal(e)
			}
			ready, start := handle.(*vm).Timings()
			if restore {
				restored = append(restored, start)
				readyRestore = append(readyRestore, ready)
			} else {
				cold = append(cold, start)
				readyCold = append(readyCold, ready)
			}
			t.Logf("pair=%d restore=%v agent_ready_ns=%d driver_start_EXEC_ack_ns=%d", i, restore, ready, start)
		}
	}
	summary, e := CompareStarts(cold, restored)
	t.Logf("actual driverStart paired20 p50/p95=%+v agentReadyCold_ns=%v agentReadyRestore_ns=%v", summary, readyCold, readyRestore)
	if e != nil {
		t.Fatal(e)
	}
}
