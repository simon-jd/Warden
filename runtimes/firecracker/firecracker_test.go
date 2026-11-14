package firecracker

import (
	"math"
	"testing"
	"warden/runtimes"
)

func spec() runtimes.Spec {
	return runtimes.Spec{RunID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", ImageDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Cmd: []string{"/warden-probe", "uid"}}
}

// Catches silently applying the obsolete 128MiB VM default to a 512MiB workload.
func TestDefaultReservesKernelOutsideWorkload(t *testing.T) {
	p, err := Normalize(spec(), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.Limits != (runtimes.Limits{CPU: 1, MemoryMiB: 512, Pids: 128, TimeoutS: 300}) || p.Spec.Network != "none" || p.VMMemoryMiB != 640 || p.HostMemoryMiB != 768 || p.AgentMemoryMiB != 64 {
		t.Fatalf("unsafe default: %+v", p)
	}
	bench, err := Normalize(spec(), true)
	if err != nil || bench.Spec.Limits.MemoryMiB != 64 || bench.VMMemoryMiB != 128 || bench.HostMemoryMiB != 256 {
		t.Fatalf("benchmark: %+v %v", bench, err)
	}
	s := spec()
	s.Limits.MemoryMiB = 128
	p, err = Normalize(s, false)
	if err != nil || p.VMMemoryMiB != 256 || p.Spec.Limits.MemoryMiB != 128 {
		t.Fatalf("explicit workload limit changed: %+v %v", p, err)
	}
}

// Catches admitting unsupported egress, overflow, or user-selected host commands.
func TestRejectUnsupportedSpec(t *testing.T) {
	for _, mutate := range []func(*runtimes.Spec){
		func(s *runtimes.Spec) { s.Network = "host" }, func(s *runtimes.Spec) { s.AllowDomains = []string{"example.com"} },
		func(s *runtimes.Spec) { s.Limits.CPU = math.NaN() }, func(s *runtimes.Spec) { s.Limits.CPU = math.Inf(1) }, func(s *runtimes.Spec) { s.Limits.CPU = 2 },
		func(s *runtimes.Spec) { s.Limits.MemoryMiB = 513 }, func(s *runtimes.Spec) { s.Limits.MemoryMiB = -1 }, func(s *runtimes.Spec) { s.Limits.Pids = 129 },
		func(s *runtimes.Spec) { s.Limits.TimeoutS = 301 }, func(s *runtimes.Spec) { s.RunID = "../../bad" },
		func(s *runtimes.Spec) { s.ImageDigest = "probe:latest" }, func(s *runtimes.Spec) { s.Cmd = []string{"/bin/sh", "-c", "id"} },
		func(s *runtimes.Spec) { s.Cmd = []string{"/warden-probe", "uid", "extra"} }, func(s *runtimes.Spec) { s.Cmd = []string{"/warden-probe", "bad"} },
	} {
		s := spec()
		mutate(&s)
		if _, err := Normalize(s, false); err == nil {
			t.Fatalf("accepted unsupported spec: %+v", s)
		}
	}
	s := spec()
	s.Limits.MemoryMiB = 512
	if _, err := Normalize(s, true); err == nil {
		t.Fatal("128 profile admitted 512MiB payload")
	}
}

func TestExplicitBenchmarkKeepsMachineShapeWithoutEnlargingPayload(t *testing.T) {
	s := spec()
	s.Limits.MemoryMiB = 32
	s.Limits.Pids = 7
	s.Limits.TimeoutS = 2
	p, e := Normalize(s, true)
	if e != nil {
		t.Fatal(e)
	}
	if p.VMMemoryMiB != 128 || p.HostMemoryMiB != 256 || p.Spec.Limits.MemoryMiB != 32 || p.Spec.Limits.Pids != 7 || p.Spec.Limits.TimeoutS != 2 {
		t.Fatalf("explicit small payload must retain the reviewed128MiB machine and exact entitlement: %+v", p)
	}
}

// Idle guests never reached outer memory pressure within the reviewed VM caps
// (2026-11-10: 32 benchmark VMs used 2.5 GB of 15 GB). The pressure capacity
// mode runs the fixed fill probe, which holds 48 MiB inside a 128 MiB VM.
func TestBenchmarkProfileAdmitsFixedFillProbe(t *testing.T) {
	s := spec()
	s.Cmd = []string{"/warden-probe", "fill"}
	p, e := Normalize(s, true)
	if e != nil || p.VMMemoryMiB != 128 || p.Spec.Limits.MemoryMiB != 64 {
		t.Fatalf("fill probe in the 128 MiB profile: %+v %v", p, e)
	}
}

// The shell exists solely to execute the reviewed corpus helper. Shell syntax,
// unknown IDs and argument injection must never enlarge this command profile.
func TestFixedCorpusCommands(t *testing.T) {
	for _, id := range []string{"fork-bomb", "memory-exhaustion", "disk-fill", "proc-leak", "sys-leak", "metadata-ip", "metadata-host", "raw-socket", "arp-spoof", "ptrace", "mount-unshare", "kernel-module", "dns-exfil", "reverse-shell"} {
		s := spec()
		s.Cmd = []string{"/bin/sh", "-c", "exec /warden-attack " + id}
		if _, err := Normalize(s, false); err != nil {
			t.Fatalf("fixed corpus command %s: %v", id, err)
		}
	}
	for _, script := range []string{"exec /warden-attack unknown", "exec /warden-attack ptrace; id", "exec /warden-attack ptrace extra", " exec /warden-attack ptrace", "exec /warden-attack ptrace\n", "exec /warden-attack $(id)"} {
		s := spec()
		s.Cmd = []string{"/bin/sh", "-c", script}
		if _, err := Normalize(s, false); err == nil {
			t.Fatalf("accepted non-corpus shell: %q", script)
		}
	}
}
