package runc

import (
	"context"
	"errors"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"os"
	"time"
)

// Reap removes a crashed worker's deterministic sandbox without ever restarting
// a command. The scheduler must own the durable run claim before calling Reap.
// Lost in-memory logs must be recorded by the scheduler as an interrupted run.
func (d *Driver) Reap(ctx context.Context, runID string) error {
	if !runPattern.MatchString(runID) {
		return errors.New("invalid recovery run ID")
	}
	client, e := newClient(d.config)
	if e != nil {
		return e
	}
	defer client.Close()
	ctx = namespaces.WithNamespace(ctx, "warden-lab")
	id := "warden-" + runID
	container, containerErr := client.LoadContainer(ctx, id)
	if containerErr != nil && !errdefs.IsNotFound(containerErr) {
		return containerErr
	}
	cg, e := openCgroup(d.config.CgroupRoot, id)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		defer cg.Close()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if e = killCgroup(bounded, cg); e != nil {
			return e
		}
	}
	if errdefs.IsNotFound(containerErr) {
		return nil
	}
	task, e := container.Task(ctx, nil)
	if e != nil && !errdefs.IsNotFound(e) {
		return e
	}
	if e == nil {
		if cg == nil {
			return errors.New("existing task has no controlled cgroup; refusing unsafe recovery")
		}
		if _, e = task.Delete(ctx, containerd.WithProcessKill); e != nil {
			return e
		}
	}
	return container.Delete(ctx, containerd.WithSnapshotCleanup)
}
