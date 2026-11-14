package scheduler_test

import (
	"strings"
	"testing"
	"warden/controlplane/internal/scheduler"
)

// Break caught: malformed or unsupported operator configuration enables a default runtime.
func TestSchedulerConfigurationFailsClosed(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"node":"node-A","gate_dir":"/private/gate","drivers":{"gvisor":{}}}`,
		`{"node":"node-A","gate_dir":"relative","drivers":{"runc":{}}}`,
		`{"node":"node-A","gate_dir":"/private/gate","concurrency":100,"drivers":{"runc":{}}}`,
		`{"node":"node-A","gate_dir":"/private/gate","concurrency":2,"unknown":true,"drivers":{"runc":{}}}`,
		`{"node":"node-A","gate_dir":"/private/gate","drivers":{"runc":{"socket":"/lab/socket","expected_daemon_pid":0}}}`,
	} {
		if _, err := scheduler.ParseConfig(strings.NewReader(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

// Break caught: safe operator settings are silently discarded before runtime construction.
func TestSchedulerConfigurationPreservesExplicitRuntimeBinding(t *testing.T) {
	c, err := scheduler.ParseConfig(strings.NewReader(`{"node":"home-ubuntu","gate_dir":"/private/warden/gate","drivers":{"runc":{"socket":"/private/warden-lab/containerd.sock","expected_daemon_pid":1234,"trusted_owner_uid":1000,"cgroup_root":"/sys/fs/cgroup/warden-lab","images":{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":"probe:owned"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	d := c.Drivers["runc"]
	if c.Node != "home-ubuntu" || c.Concurrency != 2 || c.PollMS != 250 || c.OperationTimeoutS != 30 || d.ExpectedDaemonPID != 1234 || d.TrustedOwnerUID != 1000 || d.Images["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] != "probe:owned" {
		t.Fatalf("operator settings lost %+v", c)
	}
}
