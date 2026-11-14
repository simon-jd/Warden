// Package runc executes sandboxes through the containerd Go client.
package runc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"warden/policies/seccomp"
	"warden/runtimes"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var runPattern = regexp.MustCompile(`^[A-Z2-7]{26}$`)

func ptr[T any](x T) *T { return &x }

// BuildSpec enforces runtime invariants independently of API normalization.
// Resource authorization belongs to the caller's trusted tenant policy.
func BuildSpec(s runtimes.Spec, path string) (*specs.Spec, error) {
	if !digestPattern.MatchString(s.ImageDigest) || !runPattern.MatchString(s.RunID) || len(s.Cmd) == 0 || s.Cmd[0] == "" {
		return nil, errors.New("invalid immutable image, run ID or command")
	}
	for _, arg := range s.Cmd {
		if strings.ContainsRune(arg, 0) {
			return nil, errors.New("NUL in command")
		}
	}
	if (s.Network != "" && s.Network != "none") || len(s.AllowDomains) > 0 {
		return nil, errors.New("egress isolation unavailable: only network none supported")
	}
	l := s.Limits
	if math.IsNaN(l.CPU) || math.IsInf(l.CPU, 0) || l.CPU < 0.001 || l.CPU > 10000 || l.MemoryMiB <= 0 || int64(l.MemoryMiB) > math.MaxInt64/(1024*1024) || l.Pids <= 0 || l.TimeoutS <= 0 || int64(l.TimeoutS) > int64((24*time.Hour)/time.Second) {
		return nil, errors.New("invalid or overflowing resource limits")
	}
	if path != "/warden-lab/warden-"+s.RunID {
		return nil, errors.New("uncontrolled cgroup path")
	}
	out, err := oci.GenerateSpec(namespaces.WithNamespace(context.Background(), "warden-lab"), nil, &containers.Container{}, oci.WithDefaultSpec())
	if err != nil {
		return nil, err
	}
	out.Root.Readonly = true
	out.Process.Args = append([]string(nil), s.Cmd...)
	out.Process.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	out.Process.Cwd = "/"
	out.Process.User = specs.User{UID: 65534, GID: 65534}
	out.Process.NoNewPrivileges = true
	out.Process.Capabilities = &specs.LinuxCapabilities{}
	out.Process.Rlimits = []specs.POSIXRlimit{{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024}}
	out.Hostname = "warden"
	out.Linux.CgroupsPath = path
	out.Linux.Namespaces = []specs.LinuxNamespace{{Type: specs.PIDNamespace}, {Type: specs.IPCNamespace}, {Type: specs.UTSNamespace}, {Type: specs.MountNamespace}, {Type: specs.NetworkNamespace}, {Type: specs.CgroupNamespace}}
	out.Linux.Resources = &specs.LinuxResources{Devices: out.Linux.Resources.Devices, Memory: &specs.LinuxMemory{Limit: ptr(int64(l.MemoryMiB) * 1024 * 1024), Swap: ptr(int64(l.MemoryMiB) * 1024 * 1024)}, Pids: &specs.LinuxPids{Limit: ptr(int64(l.Pids))}, CPU: &specs.LinuxCPU{Period: ptr(uint64(100000)), Quota: ptr(int64(l.CPU * 100000))}, Unified: map[string]string{"memory.oom.group": "1"}}
	out.Linux.Seccomp = &specs.LinuxSeccomp{}
	if err = json.Unmarshal(seccomp.Default, out.Linux.Seccomp); err != nil {
		return nil, err
	}
	// No host bind mounts, no writable sysfs, and no cgroupfs inside the guest.
	out.Mounts = []specs.Mount{{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}}, {Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}}, {Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}}, {Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}}, {Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}}}
	return out, nil
}

type logBuffer struct {
	mu      sync.Mutex
	data    []byte
	limit   int
	dropped uint64
}

func newLogBuffer(n int) *logBuffer { return &logBuffer{limit: n} }

// Write always consumes the whole input; excess output cannot block exit.
func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), b.limit-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.dropped += uint64(len(p) - n)
	return len(p), nil
}
func (b *logBuffer) reader() io.ReadCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	return io.NopCloser(bytes.NewReader(bytes.Clone(b.data)))
}

// openCgroup rejects symlinks in both the trusted root and the run directory;
// os.Root then confines all subsequent operations despite path races.
func openCgroup(root, id string) (*os.Root, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != "warden-lab" || id != "warden-"+strings.TrimPrefix(id, "warden-") || !runPattern.MatchString(strings.TrimPrefix(id, "warden-")) {
		return nil, errors.New("invalid cgroup root or run ID")
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if real != root {
		return nil, errors.New("symlink cgroup root")
	}
	parent, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	st, err := parent.Lstat(id)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symlink or non-directory cgroup")
	}
	return parent.OpenRoot(id)
}
func readRoot(r *os.Root, name string) ([]byte, error) {
	f, e := r.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4096))
}
func populated(r *os.Root) (bool, error) {
	b, e := readRoot(r, "cgroup.events")
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 0" {
			return false, nil
		}
		if line == "populated 1" {
			return true, nil
		}
	}
	return false, errors.New("missing populated in cgroup.events")
}
func killCgroup(ctx context.Context, r *os.Root) error {
	f, e := r.OpenFile("cgroup.kill", os.O_WRONLY, 0)
	if e != nil {
		return fmt.Errorf("open cgroup.kill: %w", e)
	}
	_, e = f.WriteString("1")
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		busy, e := populated(r)
		if e != nil {
			return e
		}
		if !busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (b *logBuffer) droppedBytes() uint64 { b.mu.Lock(); defer b.mu.Unlock(); return b.dropped }
