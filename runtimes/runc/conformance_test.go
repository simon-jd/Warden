package runc_test

import (
	"os"
	"strconv"
	"testing"
	"warden/attacks/matrix"
	"warden/runtimes"
	"warden/runtimes/conformance"
	"warden/runtimes/runc"
)

func TestConformance(t *testing.T) {
	var rt runtimes.Runtime
	if os.Getenv("WARDEN_LAB_ACK") == "dedicated-warden-lab" {
		pid, e := strconv.Atoi(os.Getenv("WARDEN_LAB_DAEMON_PID"))
		if e != nil {
			t.Fatal(e)
		}
		owner, e := strconv.Atoi(os.Getenv("WARDEN_LAB_OWNER_UID"))
		if e != nil {
			t.Fatal(e)
		}
		images := map[string]string{os.Getenv("WARDEN_LAB_IMAGE_DIGEST"): os.Getenv("WARDEN_LAB_IMAGE_NAME")}
		if digest := os.Getenv("WARDEN_MATRIX_IMAGE_DIGEST"); digest != "" {
			images[digest] = os.Getenv("WARDEN_MATRIX_IMAGE_NAME")
		}
		d, e := runc.New(runc.Config{Socket: os.Getenv("WARDEN_LAB_SOCKET"), ExpectedDaemonPID: pid, TrustedOwnerUID: owner, CgroupRoot: "/sys/fs/cgroup/warden-lab", Images: images})
		if e != nil {
			t.Fatal(e)
		}
		rt = d
	}
	conformance.Run(t, rt)
	matrix.RunFromEnv(t, rt, "runc")
}
