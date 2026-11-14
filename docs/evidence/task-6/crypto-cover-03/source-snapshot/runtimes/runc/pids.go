package runc

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

func pidsMax(cgroup *os.Root) (uint64, error) {
	data, e := readRoot(cgroup, "pids.events")
	if e != nil {
		return 0, e
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "max" {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, errors.New("missing pids.events max counter")
}
func pidsEvidence(cgroup *os.Root, baseline uint64) (events, peak uint64, err error) {
	current, e := pidsMax(cgroup)
	if e != nil {
		return 0, 0, e
	}
	if current < baseline {
		return 0, 0, errors.New("pids.events counter moved backwards")
	}
	data, e := readRoot(cgroup, "pids.peak")
	if e != nil {
		return 0, 0, e
	}
	peak, e = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if e != nil {
		return 0, 0, e
	}
	return current - baseline, peak, nil
}
