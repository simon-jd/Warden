package firecracker

import "testing"

func TestKernelCountersFailClosed(t *testing.T) {
	for _, tc := range []struct {
		raw, key string
		want     uint64
	}{{"populated 0\nfrozen 0\n", "populated", 0}, {"low 0\noom 3\noom_kill 2\n", "oom_kill", 2}, {"max 7\n", "max", 7}} {
		n, e := Counter(tc.raw, tc.key)
		if e != nil || n != tc.want {
			t.Fatalf("counter %d %v", n, e)
		}
	}
	for _, raw := range []string{"", "max -1\n", "max 18446744073709551616\n", "max 0\nmax 1\n", "max 1 extra\n", "other 3\n"} {
		if _, e := Counter(raw, "max"); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
