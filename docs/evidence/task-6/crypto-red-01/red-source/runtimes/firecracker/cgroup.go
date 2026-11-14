package firecracker

import (
	"errors"
	"strconv"
	"strings"
)

func Counter(raw, key string) (uint64, error) {
	if len(raw) > 4096 {
		return 0, errors.New("kernel counter too large")
	}
	found := false
	var result uint64
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, errors.New("invalid kernel counter row")
		}
		if fields[0] == key {
			if found {
				return 0, errors.New("duplicate kernel counter")
			}
			n, e := strconv.ParseUint(fields[1], 10, 64)
			if e != nil {
				return 0, e
			}
			result = n
			found = true
		}
	}
	if !found {
		return 0, errors.New("required kernel counter missing")
	}
	return result, nil
}
