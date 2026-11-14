package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
	"warden/runtimes"
)

type snapshotRecord struct {
	Key, MemorySHA, StateSHA string
	MemoryBytes, StateBytes  int64
}

func validateSnapshot(root *os.Root, r snapshotRecord, key string, memory int) error {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) || r.Key != key || memory < 128 || memory > 640 {
		return errors.New("snapshot key/shape mismatch")
	}
	for _, v := range []struct {
		name, sha   string
		size, limit int64
	}{{"memory", r.MemorySHA, r.MemoryBytes, int64(memory) << 20}, {"state", r.StateSHA, r.StateBytes, 16 << 20}} {
		f, e := verifiedArtifact(root, v.name, v.sha, v.limit)
		if e != nil {
			return e
		}
		st, e := f.Stat()
		f.Close()
		if e != nil || st.Size() != v.size {
			return errors.New("snapshot size changed")
		}
	}
	return nil
}
func (d *Driver) snapshotKey(p Profile) (string, error) {
	return (SnapshotKey{Kernel: d.manifest.Artifacts["kernel"], Agent: d.manifest.AgentSHA, RootFS: d.manifest.Artifacts["agent.ext4"], Payload: d.manifest.Artifacts["payload.ext4"], Firecracker: d.manifest.Artifacts["firecracker"], Policy: d.manifest.PolicySHA, MemoryMiB: p.VMMemoryMiB, VCPUs: 1}).Digest()
}
func (d *Driver) readSnapshot(key string, memory int) (*os.Root, snapshotRecord, error) {
	var r snapshotRecord
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		return nil, r, errors.New("invalid snapshot key")
	}
	root, e := d.root.OpenRoot("snapshots/" + key)
	if e != nil {
		return nil, r, e
	}
	fail := func(e error) (*os.Root, snapshotRecord, error) { root.Close(); return nil, r, e }
	f, e := root.OpenFile("record", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return fail(e)
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0400 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return fail(errors.New("unsafe snapshot record"))
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	f.Close()
	if e != nil || len(raw) > 4096 {
		return fail(errors.New("snapshot record oversized"))
	}
	if e = json.Unmarshal(raw, &r); e != nil {
		return fail(e)
	}
	if e = validateSnapshot(root, r, key, memory); e != nil {
		return fail(e)
	}
	return root, r, nil
}

// PrepareBaseline boots a dedicated never-bound VM, consumes its durable RunID
// and UID, and captures only the trusted agent before any nonce or workload.
// It is a lab operation, not a tenant Runtime.Start or scheduler reconciliation.
func (d *Driver) PrepareBaseline(ctx context.Context, s runtimes.Spec, benchmark bool) (key string, err error) {
	if d == nil || d.root == nil {
		return "", ErrCleanupPending
	}
	p, e := Normalize(s, benchmark)
	if e != nil {
		return "", e
	}
	if p.Spec.ImageDigest != d.manifest.ImageDigest {
		return "", errors.New("baseline image mismatch")
	}
	key, e = d.snapshotKey(p)
	if e != nil {
		return "", e
	}
	// Serialize cache creation independently of the per-VM capacity reservation.
	d.snapshotMu.Lock()
	defer d.snapshotMu.Unlock()
	if _, e := d.root.Lstat("snapshots/" + key); e == nil {
		root, _, e := d.readSnapshot(key, p.VMMemoryMiB)
		if e != nil {
			return "", e
		}
		root.Close()
		return key, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	dir, e := d.root.Open("snapshots")
	if e != nil {
		return "", e
	}
	entries, e := dir.ReadDir(-1)
	dir.Close()
	if e != nil {
		return "", e
	}
	if len(entries) >= 2 {
		return "", errors.New("two-baseline retention bound reached")
	}
	h, e := d.reserve(p)
	if e != nil {
		return "", e
	}
	defer d.wg.Done()
	defer close(h.startDone)
	defer close(h.done)
	defer func() { err = errors.Join(err, h.retire()) }()
	if e = h.boot(ctx, ""); e != nil {
		return "", e
	}
	if h.bound {
		return "", errors.New("bound VM cannot be snapshotted")
	}
	h.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if e = WriteFrame(h.conn, Frame{Version: 1, Kind: "snapshot"}); e != nil {
		return "", e
	}
	f, e := ReadFrame(h.conn)
	if e != nil {
		return "", e
	}
	if f.Version != 1 || f.Kind != "snapshot-ready" || f.Nonce != "" || f.RunID != "" || f.AgentSHA != "" || f.Profile != nil || f.Exit != nil || len(f.Data) > 0 {
		return "", errors.New("guest refused virgin snapshot")
	}
	var one [1]byte
	if n, e := h.conn.Read(one[:]); n != 0 || !errors.Is(e, io.EOF) {
		return "", errors.New("snapshot control channel still active")
	}
	h.conn.Close()
	h.conn = nil
	if e = h.api.call(ctx, "PATCH", "/vm", map[string]string{"state": "Paused"}); e != nil {
		return "", e
	}
	if e = h.api.call(ctx, "PUT", "/snapshot/create", map[string]any{"snapshot_type": "Full", "snapshot_path": "/state", "mem_file_path": "/memory", "sync_snapshot_files": true}); e != nil {
		return "", e
	}
	jail, e := os.OpenRoot(h.jail)
	if e != nil {
		return "", e
	}
	defer jail.Close()
	r := snapshotRecord{Key: key}
	// Only these fresh private output inodes may change owner or permissions.
	for _, v := range []struct {
		name  string
		limit int64
		sha   *string
		size  *int64
	}{{"memory", int64(p.VMMemoryMiB) << 20, &r.MemorySHA, &r.MemoryBytes}, {"state", 16 << 20, &r.StateSHA, &r.StateBytes}} {
		file, e := jail.OpenFile(v.name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return "", e
		}
		st, e := file.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > v.limit || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Uid != h.uid {
			file.Close()
			return "", errors.New("unsafe private snapshot output")
		}
		hash := sha256.New()
		n, e := io.Copy(hash, io.LimitReader(file, v.limit+1))
		if e == nil {
			*v.sha = hex.EncodeToString(hash.Sum(nil))
			*v.size = n
		}
		e = errors.Join(e, file.Chown(os.Geteuid(), os.Getegid()), file.Chmod(0444), file.Sync(), file.Close())
		if e != nil {
			return "", e
		}
	}
	if e = d.root.Mkdir("snapshots/"+key, 0700); e != nil {
		return "", e
	}
	cache, e := d.root.OpenRoot("snapshots/" + key)
	if e != nil {
		return "", e
	}
	defer cache.Close()
	// A crash leaves an incomplete, non-reusable entry; never silently replace it.
	for _, name := range []string{"memory", "state"} {
		if e = os.Link(filepath.Join(h.jail, name), sessionPath+"/node/snapshots/"+key+"/"+name); e != nil {
			return "", e
		}
	}
	record, e := cache.OpenFile("record", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	e = json.NewEncoder(record).Encode(r)
	e = errors.Join(e, record.Chmod(0400), record.Sync(), record.Close(), syncRoot(cache))
	if e != nil {
		return "", e
	}
	parents, e := d.root.OpenRoot("snapshots")
	if e != nil {
		return "", e
	}
	e = errors.Join(syncRoot(parents), parents.Close())
	return key, e
}
func (h *vm) restore(ctx context.Context, key string) error {
	expected, e := h.driver.snapshotKey(h.profile)
	if e != nil || expected != key {
		return errors.New("restore inputs differ from baseline")
	}
	root, _, e := h.driver.readSnapshot(key, h.profile.VMMemoryMiB)
	if e != nil {
		return e
	}
	defer root.Close()
	for _, name := range []string{"memory", "state"} {
		if e = os.Link(sessionPath+"/node/snapshots/"+key+"/"+name, filepath.Join(h.jail, name)); e != nil {
			return e
		}
	}
	return h.api.call(ctx, "PUT", "/snapshot/load", map[string]any{"snapshot_path": "/state", "mem_backend": map[string]string{"backend_path": "/memory", "backend_type": "File"}, "resume_vm": true})
}

// StartRestored preserves the same durable Gate.Start boundary. Run-specific
// options are fixed before admission and cannot be changed or replayed.
func (d *Driver) StartRestored(ctx context.Context, s runtimes.Spec, benchmark bool, key string) (runtimes.Handle, error) {
	if d == nil || d.gate == nil {
		return nil, ErrCleanupPending
	}
	p, e := Normalize(s, benchmark)
	if e != nil {
		return nil, e
	}
	expected, e := d.snapshotKey(p)
	if e != nil || key != expected {
		return nil, errors.New("wrong restore key")
	}
	d.mu.Lock()
	if _, exists := d.options[s.RunID]; exists {
		d.mu.Unlock()
		return nil, fmt.Errorf("RunID options already consumed")
	}
	d.options[s.RunID] = startOptions{benchmark, key}
	d.mu.Unlock()
	return d.gate.Start(ctx, s)
}
