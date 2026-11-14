package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeHost records mounts and answers access(W_OK) from a table.
type fakeHost struct {
	mounts   []step
	failAt   string
	writable map[string]error
}

func (h *fakeHost) mount(src, dst, fstype string, flags uintptr, data string) error {
	if fstype != "" || data != "" {
		return errors.New("unexpected fstype or data")
	}
	h.mounts = append(h.mounts, step{src, dst, flags})
	if dst == h.failAt {
		return unix.EPERM
	}
	return nil
}

func (h *fakeHost) access(path string, mode uint32) error {
	if mode != unix.W_OK {
		return errors.New("unexpected mode")
	}
	if err, ok := h.writable[path]; ok {
		return err
	}
	return unix.EROFS
}

func goodHost() *fakeHost {
	return &fakeHost{writable: map[string]error{"/proc/sys/net/ipv4/conf/all/forwarding": nil}}
}

func TestSetupMakesRootSharedAndProcSysReadOnlyExceptNet(t *testing.T) {
	h := goodHost()
	if err := setup(h.mount, h.access); err != nil {
		t.Fatal(err)
	}
	want := []step{
		{"", "/", unix.MS_REC | unix.MS_SHARED},
		{"/proc/sys/net", "/proc/sys/net", unix.MS_BIND},
		{"/proc/sys", "/proc/sys", unix.MS_BIND | unix.MS_REC},
		{"", "/proc/sys", unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
	}
	if !reflect.DeepEqual(h.mounts, want) {
		t.Fatalf("mounts:\n got %v\nwant %v", h.mounts, want)
	}
}

func TestSetupRefusesWhenAKernelSysctlStaysWritable(t *testing.T) {
	for _, p := range readOnly {
		h := goodHost()
		h.writable[p] = nil
		err := setup(h.mount, h.access)
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s writable: err = %v, want an error naming it", p, err)
		}
	}
}

func TestSetupRefusesWhenNetIsNotWritable(t *testing.T) {
	h := goodHost()
	h.writable[writable] = unix.EROFS
	if err := setup(h.mount, h.access); err == nil || !strings.Contains(err.Error(), "/proc/sys/net") {
		t.Fatalf("err = %v, want /proc/sys/net not writable", err)
	}
}

func TestSetupStopsAtTheFirstFailedMount(t *testing.T) {
	h := goodHost()
	h.failAt = "/proc/sys/net"
	if err := setup(h.mount, h.access); err == nil || !strings.Contains(err.Error(), "/proc/sys/net") {
		t.Fatalf("err = %v", err)
	}
	if len(h.mounts) != 2 {
		t.Fatalf("went on after the failed mount: %v", h.mounts)
	}
}

func TestArgvExecsK3sWithTheNodesArguments(t *testing.T) {
	got := argv([]string{"/warden-node-init", "server", "--node-ip", "10.0.0.10"})
	want := []string{"/bin/k3s", "server", "--node-ip", "10.0.0.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}
