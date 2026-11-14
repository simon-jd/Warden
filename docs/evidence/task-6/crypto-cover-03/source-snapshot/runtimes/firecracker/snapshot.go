package firecracker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

type SnapshotKey struct {
	Kernel, Agent, RootFS, Payload, Firecracker, Policy string
	MemoryMiB                                           int
	VCPUs                                               int
}

func (k SnapshotKey) Digest() (string, error) {
	for _, h := range []string{k.Kernel, k.Agent, k.RootFS, k.Payload, k.Firecracker, k.Policy} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h) {
			return "", errors.New("immutable snapshot hashes required")
		}
	}
	if k.VCPUs != 1 || k.MemoryMiB < 128 || k.MemoryMiB > 640 {
		return "", errors.New("unsupported snapshot machine shape")
	}
	b, _ := json.Marshal(k)
	sum := sha256.Sum256(append([]byte("warden-firecracker-virgin-snapshot-v1\n"), b...))
	return hex.EncodeToString(sum[:]), nil
}

type Measurements struct{ ColdP50, ColdP95, RestoreP50, RestoreP95 time.Duration }

// P50 is the arithmetic median; P95 uses nearest rank. Inputs are observed
// durations supplied by the separately gated real benchmark, never a clock here.
func CompareStarts(cold, restored []time.Duration) (Measurements, error) {
	var m Measurements
	if len(cold) < 20 || len(cold) > 1000 || len(restored) != len(cold) {
		return m, errors.New("20..1000 matched observations required")
	}
	quantiles := func(in []time.Duration) (time.Duration, time.Duration, error) {
		a := append([]time.Duration(nil), in...)
		for _, v := range a {
			if v <= 0 || v > time.Hour {
				return 0, 0, errors.New("invalid observed duration")
			}
		}
		sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
		mid := a[len(a)/2]
		if len(a)%2 == 0 {
			lo := a[len(a)/2-1]
			mid = lo + (mid-lo)/2
		}
		return mid, a[(95*len(a)+99)/100-1], nil
	}
	var e error
	m.ColdP50, m.ColdP95, e = quantiles(cold)
	if e != nil {
		return m, e
	}
	m.RestoreP50, m.RestoreP95, e = quantiles(restored)
	if e != nil {
		return m, e
	}
	if m.RestoreP50 >= m.ColdP50 {
		return m, errors.New("restore median is not faster than cold boot")
	}
	return m, nil
}
