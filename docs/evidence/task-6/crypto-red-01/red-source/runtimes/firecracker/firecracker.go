// Package firecracker implements the dedicated, locally owned microVM boundary.
package firecracker

import (
	"errors"
	"math"
	"regexp"
	"warden/runtimes"
)

type Profile struct {
	Spec                                       runtimes.Spec
	VMMemoryMiB, HostMemoryMiB, AgentMemoryMiB int
}

func Normalize(s runtimes.Spec, benchmark128 bool) (Profile, error) {
	if !regexp.MustCompile(`^[A-Z2-7]{26}$`).MatchString(s.RunID) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(s.ImageDigest) || len(s.Cmd) != 2 || s.Cmd[0] != "/warden-probe" {
		return Profile{}, errors.New("only an immutable owned probe and valid RunID are supported")
	}
	switch s.Cmd[1] {
	case "fork", "readonly", "network", "uid", "timeout", "oom", "seccomp":
	default:
		return Profile{}, errors.New("unsupported fixed probe")
	}
	if (s.Network != "" && s.Network != "none") || len(s.AllowDomains) > 0 {
		return Profile{}, errors.New("network none required")
	}
	s.Network = "none"
	s.Cmd = append([]string(nil), s.Cmd...)
	l := s.Limits
	maxMemory, overhead := 512, 128
	if benchmark128 {
		maxMemory, overhead = 64, 64
	}
	if l.CPU == 0 {
		l.CPU = 1
	}
	if l.MemoryMiB == 0 {
		l.MemoryMiB = maxMemory
	}
	if l.Pids == 0 {
		l.Pids = 128
	}
	if l.TimeoutS == 0 {
		l.TimeoutS = 300
	}
	if math.IsNaN(l.CPU) || math.IsInf(l.CPU, 0) || l.CPU < 0.001 || l.CPU > 1 || l.MemoryMiB < 16 || l.MemoryMiB > maxMemory || l.Pids < 1 || l.Pids > 128 || l.TimeoutS < 1 || l.TimeoutS > 300 {
		return Profile{}, errors.New("limits exceed reviewed profile")
	}
	s.Limits = l
	vmMemory := l.MemoryMiB + overhead
	if benchmark128 {
		vmMemory = 128
	}
	return Profile{Spec: s, VMMemoryMiB: vmMemory, HostMemoryMiB: vmMemory + 128, AgentMemoryMiB: 64}, nil
}
