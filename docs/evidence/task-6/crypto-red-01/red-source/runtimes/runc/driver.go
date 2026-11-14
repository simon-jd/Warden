package runc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"warden/runtimes"
)

// Config is trusted operator configuration. This driver never pulls images:
// images must already exist in the dedicated daemon's warden-lab namespace.
type Config struct {
	Socket string
	// ExpectedDaemonPID must come from the owned child daemon process, never
	// from a tenant or a PID guessed from a socket pathname.
	ExpectedDaemonPID int
	TrustedOwnerUID   int
	CgroupRoot        string
	// Images maps a bare digest to a pre-imported image name. Target digest is
	// verified even for trusted names, preventing a moved tag from executing.
	Images map[string]string
}
type Driver struct{ config Config }

func New(cfg Config) (*Driver, error) {
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket || !strings.Contains(cfg.Socket, "/warden-lab/") {
		return nil, errors.New("dedicated warden-lab containerd socket required")
	}
	if cfg.CgroupRoot != "/sys/fs/cgroup/warden-lab" {
		return nil, errors.New("dedicated cgroup v2 warden-lab root required")
	}
	owned := make(map[string]string, len(cfg.Images))
	for k, v := range cfg.Images {
		if !digestPattern.MatchString(k) || v == "" {
			return nil, errors.New("invalid trusted image mapping")
		}
		owned[k] = v
	}
	cfg.Images = owned
	if err := validateSocket(cfg); err != nil {
		return nil, err
	}
	return &Driver{config: cfg}, nil
}

func (d *Driver) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	id := "warden-" + s.RunID
	spec, err := BuildSpec(s, "/warden-lab/"+id)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Each client dial/reconnect authenticates the explicitly owned lab daemon.
	client, err := newClient(d.config)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			client.Close()
		}
	}()
	setup := namespaces.WithNamespace(ctx, "warden-lab")
	name := s.ImageDigest
	if mapped, ok := d.config.Images[name]; ok {
		name = mapped
	}
	image, err := client.GetImage(setup, name)
	if err != nil {
		return nil, fmt.Errorf("immutable image must be pre-imported: %w", err)
	}
	if image.Target().Digest.String() != s.ImageDigest {
		return nil, errors.New("pre-imported image target digest mismatch")
	}
	container, err := client.NewContainer(setup, id, containerd.WithImage(image), containerd.WithNewSnapshot(id, image), containerd.WithSpec(spec), containerd.WithRuntime("io.containerd.runc.v2", nil))
	if err != nil {
		return nil, err
	}
	// Cleanup uses its own context, never the HTTP/worker request context.
	detached := namespaces.WithNamespace(context.Background(), "warden-lab")
	cleanupContainer := func() error {
		c, cancel := context.WithTimeout(detached, 15*time.Second)
		defer cancel()
		return container.Delete(c, containerd.WithSnapshotCleanup)
	}
	logs := newLogBuffer(1 << 20)
	task, err := container.NewTask(setup, cio.NewCreator(cio.WithFIFODir(filepath.Join(filepath.Dir(d.config.Socket), "io")), cio.WithStreams(nil, logs, logs)))
	if err != nil {
		return nil, errors.Join(err, cleanupContainer())
	}
	deleteTask := func() error {
		c, cancel := context.WithTimeout(detached, 15*time.Second)
		defer cancel()
		ioErr := drainIO(c, task.IO())
		if ioErr != nil {
			return ioErr
		}
		_, e := task.Delete(c, containerd.WithProcessKill)
		return errors.Join(ioErr, e)
	}
	cg, err := openCgroup(d.config.CgroupRoot, id)
	if err != nil {
		return nil, errors.Join(err, deleteTask(), cleanupContainer())
	}
	baseline, err := pidsMax(cg)
	if err != nil {
		c, cancel := context.WithTimeout(detached, 10*time.Second)
		killErr := killCgroup(c, cg)
		cancel()
		cg.Close()
		return nil, errors.Join(err, killErr, deleteTask(), cleanupContainer())
	}
	statuses, err := task.Wait(detached)
	if err != nil {
		cg.Close()
		return nil, errors.Join(err, deleteTask(), cleanupContainer())
	}
	if err = task.Start(setup); err != nil {
		c, cancel := context.WithTimeout(detached, 10*time.Second)
		killErr := killCgroup(c, cg)
		cancel()
		cg.Close()
		return nil, errors.Join(err, killErr, deleteTask(), cleanupContainer())
	}
	exits := make(chan processExit, 1)
	go func() {
		status, ok := <-statuses
		if !ok {
			exits <- processExit{code: 255, err: errors.New("containerd wait channel closed without status")}
			return
		}
		code, _, waitErr := status.Result()
		b, e := readRoot(cg, "memory.events")
		oom := false
		if e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				var key string
				var count uint64
				if _, scanErr := fmt.Sscan(line, &key, &count); scanErr == nil && key == "oom_kill" && count > 0 {
					oom = true
				}
			}
		}
		events, peak, pidsErr := pidsEvidence(cg, baseline)
		exits <- processExit{code: code, oom: oom, pidsMaxEvents: events, peakPids: peak, err: errors.Join(waitErr, e, pidsErr)}
	}()
	h := newHandle(time.Duration(s.Limits.TimeoutS)*time.Second, logs, exits, func(c context.Context) (bool, error) {
		empty, e := populated(cg)
		empty = !empty
		// Preserve task/snapshot if the subtree is still populated: do not hide leaked
		// processes by removing the evidence. The scheduler must surface this failure.
		if e != nil || !empty {
			return false, errors.Join(e, errors.New("sandbox cgroup not empty; task preserved for recovery"), cg.Close(), client.Close())
		}
		taskErr := deleteTask()
		var containerErr error
		if taskErr == nil {
			containerErr = cleanupContainer()
		}
		return true, errors.Join(taskErr, containerErr, cg.Close(), client.Close())
	}, func(c context.Context) error { return killCgroup(c, cg) })
	failed = false
	return h, nil
}

// RetirementTarget exposes only the operator-owned daemon and the fixed lab
// subtree already validated by New. It is never populated from a run request.
func (d *Driver) RetirementTarget() (int, string, string) {
	return d.config.ExpectedDaemonPID, d.config.CgroupRoot, filepath.Dir(d.config.Socket)
}
