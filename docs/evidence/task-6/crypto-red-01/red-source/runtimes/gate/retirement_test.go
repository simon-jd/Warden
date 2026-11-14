package gate_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"warden/runtimes"
	"warden/runtimes/gate"
)

// Break caught: another process admits a new launch after permanent retirement
// began (including a crash before the quiescence proof was completed).
func TestRetirementFenceRejectsNewStartsAcrossInstances(t *testing.T) {
	dir := privateDir(t)
	d := &driver{}
	a, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "retirement"), []byte("retiring\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := gate.New(dir, "node-A", d)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []*gate.Gate{a, b} {
		if _, err := g.Start(context.Background(), runtimes.Spec{RunID: id}); err == nil {
			t.Error("retired authority admitted Start")
		}
	}
	if d.starts.Load() != 0 {
		t.Fatal("retired authority reached runtime")
	}
}

// Break caught: caller-selected root/shared cgroups become kill targets, or a
// caller's empty/forged receipt clears an ambiguous launch.
func TestRetirementRejectsUnboundTargetsAndForgedProof(t *testing.T) {
	daemon := exec.Command("/bin/sleep", "30")
	worker := exec.Command("/bin/sleep", "30")
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { daemon.Process.Kill(); daemon.Wait() }()
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { worker.Process.Kill(); worker.Wait() }()
	for _, path := range []string{"/sys/fs/cgroup", "/tmp/warden-lab", "/sys/fs/cgroup/warden-lab/../"} {
		dir := privateDir(t)
		g, err := gate.New(dir, "node-A", &targetDriver{path: path, daemon: daemon.Process.Pid, session: filepath.Dir(dir)})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := g.BindRetirement(context.Background(), worker.Process.Pid)
		if binding != nil {
			binding.Close()
		}
		if err == nil {
			t.Fatal("unsafe retirement target accepted", path)
		}
		if proof, err := g.Reconciliation(context.Background(), id); err == nil || proof != nil {
			t.Fatal("absent proof accepted")
		}
	}
	proof := new(gate.Reconciliation)
	if proof.ValidFor(id, "node-A/fake") {
		t.Fatal("zero proof accepted")
	}
}

type targetDriver struct {
	driver
	path    string
	daemon  int
	session string
}

func (d *targetDriver) RetirementTarget() (int, string, string) { return d.daemon, d.path, d.session }

// Break caught: a partial, malformed or different-node retirement record is
// treated as sufficient quiescence and an absent Reap clears original ambiguity.
func TestUnprovenRetirementKeepsAmbiguity(t *testing.T) {
	for _, record := range []string{"", `{"state":"retiring"}`, `{"state":"retired","authority":"other-node","cgroup_inode":123,"daemon_pid":12,"worker_pid":13,"data":[{"device":1,"inode":1},{"device":1,"inode":2},{"device":1,"inode":3}]}`, "malformed"} {
		dir := privateDir(t)
		g, err := gate.New(dir, "node-A", &driver{})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, id), []byte("launching\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "retirement"), []byte(record), 0600); err != nil {
			t.Fatal(err)
		}
		if proof, err := g.Reconciliation(context.Background(), id); err == nil || proof != nil {
			t.Fatal("unproven retirement accepted")
		}
		if err = g.Reap(context.Background(), id); !errors.Is(err, gate.ErrAmbiguous) {
			t.Fatal("uncertainty cleared", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, id))
		if err != nil || string(raw) != "revoked-uncertain\n" {
			t.Fatal("uncertain marker lost")
		}
	}
}
