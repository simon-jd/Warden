package firecracker

import (
	"fmt"
	"os"
	"testing"
)

func TestSupervisorRefusesOrdinaryProcessBeforeDeviceOrMount(t *testing.T) {
	if e := Supervise("boot"); e == nil {
		t.Fatal("ordinary process admitted as privileged supervisor")
	}
}
func TestOuterLimitsMustMatchFixedMode(t *testing.T) {
	for _, mode := range []string{"boot", "conformance", "snapshot"} {
		if e := validateOuterLimits(mode, "3999997952", "0", "512", "200000 100000"); e != nil {
			t.Fatal(e)
		}
		if e := validateOuterLimits(mode, "max", "0", "512", "200000 100000"); e == nil {
			t.Fatal("unbounded outer admitted")
		}
	}
	if e := validateOuterLimits("capacity-default", "14999998464", "0", "512", "200000 100000"); e != nil {
		t.Fatal(e)
	}
	if e := validateOuterLimits("capacity-default", "16000000000", "0", "512", "200000 100000"); e == nil {
		t.Fatal("host allowance consumed")
	}
}

// The fixed amd64 lab's 4KiB page readback was observed on this host in Task3.
// Arbitrary lower values are not equivalent to the fixed Docker request.
func TestOuterLimitsOnlyCanonicalPageFloor(t *testing.T) {
	if os.Getpagesize() != 4096 {
		t.Fatal("fixed lab requires observed 4KiB pages")
	}
	for _, tc := range []struct {
		mode     string
		readback int64
	}{{"boot", 3999997952}, {"capacity-default", 14999998464}, {"capacity-benchmark", 14999998464}} {
		memory := fmt.Sprint(tc.readback)
		if e := validateOuterLimits(tc.mode, memory, "0", "512", "200000 100000"); e != nil {
			t.Errorf("canonical %s: %v", tc.mode, e)
		}
		for _, bad := range []string{fmt.Sprint(tc.readback - 4096), fmt.Sprint(tc.readback - 1), fmt.Sprint(tc.readback + 1), fmt.Sprint(tc.readback + 4096), "4000000000", "15000000000", "0", "max", "+" + memory, "0" + memory} {
			if e := validateOuterLimits(tc.mode, bad, "0", "512", "200000 100000"); e == nil {
				t.Errorf("noncanonical %s memory %s accepted", tc.mode, bad)
			}
		}
		for _, v := range [][3]string{{"1", "512", "200000 100000"}, {"0", "511", "200000 100000"}, {"0", "512", "199999 100000"}} {
			if e := validateOuterLimits(tc.mode, memory, v[0], v[1], v[2]); e == nil {
				t.Errorf("nonmemory limits changed: %v", v)
			}
		}
	}
	for _, mode := range []string{"", "capacity-other", "shell"} {
		if e := validateOuterLimits(mode, "3999997952", "0", "512", "200000 100000"); e == nil {
			t.Errorf("unknown mode %q", mode)
		}
	}
}
