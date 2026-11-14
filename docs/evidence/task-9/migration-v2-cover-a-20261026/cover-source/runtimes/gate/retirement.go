package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const labCgroup = "/sys/fs/cgroup/warden-lab"

// Retirement is a single-use, kernel-bound capability for the fixed dedicated
// lab node. Capture before releasing its only worker. The supervisor must remain
// outside the tree, never migrate node processes out, and reap its child worker.
// This is not an API/operator acknowledgment or a general process executor.
type Retirement struct {
	mu                     sync.Mutex
	gate                   *Gate
	cgroup, daemon, worker int
	record                 retirementRecord
	closed                 bool
	session                int
	data                   []int
}
type retirementRecord struct {
	Authority    string              `json:"authority"`
	CgroupDevice uint64              `json:"cgroup_device"`
	CgroupInode  uint64              `json:"cgroup_inode"`
	DaemonPID    int                 `json:"daemon_pid"`
	WorkerPID    int                 `json:"worker_pid"`
	State        string              `json:"state"`
	Data         []directoryIdentity `json:"data"`
}

type directoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Reconciliation cannot be constructed by consumers. It binds one consumed run
// to the durable original authority and to the exact kernel proof bytes.
type Reconciliation struct{ run, authority, digest string }

func (p *Reconciliation) ValidFor(run, authority string) bool {
	return p != nil && idPattern.MatchString(p.run) && p.run == run && p.authority == authority && len(p.digest) == 64
}
func (p *Reconciliation) Evidence() map[string]string {
	if p == nil {
		return nil
	}
	return map[string]string{"run_id": p.run, "authority": p.authority, "sha256": p.digest}
}

func pidExited(fd int) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	_, err := unix.Poll(fds, 0)
	if err != nil {
		return false, err
	}
	if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errors.New("invalid process identity")
	}
	return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
}
func pidReaped(fd int) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds, 0); err != nil {
		return false, err
	}
	if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errors.New("invalid original process identity")
	}
	return fds[0].Revents&unix.POLLHUP != 0, nil
}
func membership(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "0::/") || strings.Contains(line, "\n") {
		return "", errors.New("unified cgroup membership required")
	}
	return strings.TrimPrefix(line, "0::"), nil
}
func withinLab(path string) bool {
	return path == "/warden-lab" || strings.HasPrefix(path, "/warden-lab/")
}
func readAt(fd int, name string) ([]byte, error) {
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(n), name)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 65536))
}
func treePIDs(fd int) (map[int]bool, error) {
	out := map[int]bool{}
	raw, err := readAt(fd, "cgroup.procs")
	if err != nil {
		return nil, err
	}
	for _, word := range strings.Fields(string(raw)) {
		n, e := strconv.Atoi(word)
		if e != nil || n <= 0 {
			return nil, errors.New("invalid cgroup process")
		}
		out[n] = true
	}
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dup), "cgroup")
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			child, e := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return nil, e
			}
			members, e := treePIDs(child)
			unix.Close(child)
			if e != nil {
				return nil, e
			}
			for p := range members {
				out[p] = true
			}
		}
	}
	return out, nil
}

// BindRetirement accepts no caller-provided daemon PID or cgroup path. They come
// from the already authenticated driver, and every initial tree member must be
// exactly that daemon or the paused fixture worker. Real cgroup2 and pidfds are
// mandatory; a regular-file "empty" assertion is not evidence.
func (g *Gate) BindRetirement(ctx context.Context, workerPID int) (*Retirement, error) {
	target, ok := g.driver.(interface{ RetirementTarget() (int, string, string) })
	if !ok {
		return nil, errors.New("driver does not own a retireable lab node")
	}
	daemonPID, path, sessionPath := target.RetirementTarget()
	if path != labCgroup || sessionPath != filepath.Dir(g.dir) || workerPID <= 1 || daemonPID <= 1 || workerPID == daemonPID || workerPID == os.Getpid() || daemonPID == os.Getpid() {
		return nil, errors.New("invalid dedicated retirement identities")
	}
	self, err := membership(os.Getpid())
	if err != nil || withinLab(self) {
		return nil, errors.New("retirement supervisor must be outside node tree")
	}
	r := &Retirement{gate: g, cgroup: -1, daemon: -1, worker: -1, session: -1}
	success := false
	defer func() {
		if !success {
			r.Close()
		}
	}()
	parent, err := unix.Open("/sys/fs/cgroup", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	r.cgroup, err = unix.Openat(parent, "warden-lab", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var fs unix.Statfs_t
	var st unix.Stat_t
	if err = unix.Fstatfs(r.cgroup, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("real cgroup2 required")
	}
	if err = unix.Fstat(r.cgroup, &st); err != nil {
		return nil, err
	}
	r.daemon, err = unix.PidfdOpen(daemonPID, 0)
	if err != nil {
		return nil, err
	}
	r.worker, err = unix.PidfdOpen(workerPID, 0)
	if err != nil {
		return nil, err
	}
	for _, pid := range []int{daemonPID, workerPID} {
		m, e := membership(pid)
		if e != nil || !withinLab(m) {
			return nil, errors.New("original process outside controlled tree")
		}
	}
	members, err := treePIDs(r.cgroup)
	if err != nil {
		return nil, err
	}
	if len(members) != 2 || !members[daemonPID] || !members[workerPID] {
		return nil, errors.New("unexpected node process before worker release")
	}
	for _, fd := range []int{r.daemon, r.worker} {
		dead, e := pidExited(fd)
		if e != nil || dead {
			return nil, errors.New("node process not alive at binding")
		}
	}
	r.record = retirementRecord{Authority: g.authority, CgroupDevice: st.Dev, CgroupInode: st.Ino, DaemonPID: daemonPID, WorkerPID: workerPID, State: "bound"}
	lock, err := g.lock(ctx, "retirement-binding")
	if err != nil {
		return nil, err
	}
	defer unlock(lock)
	info, err := lock.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != 0 {
		return nil, errors.New("node already bound; cannot replace original identities")
	}
	r.session, err = unix.Openat(int(lock.directory.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"root", "state", "io"} {
		fd, e := unix.Openat(r.session, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		r.data = append(r.data, fd)
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			return nil, e
		}
		if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
			return nil, errors.New("unsafe original daemon data directory")
		}
		r.record.Data = append(r.record.Data, directoryIdentity{Device: st.Dev, Inode: st.Ino})
	}
	raw, _ := json.Marshal(r.record)
	if err = g.mark(lock, string(raw)); err != nil {
		return nil, err
	}
	success = true
	return r, nil
}
func (r *Retirement) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	for _, fd := range append([]int{r.cgroup, r.daemon, r.worker, r.session}, r.data...) {
		if fd >= 0 {
			err = errors.Join(err, unix.Close(fd))
		}
	}
	return err
}

// Retire permanently closes admission before cgroup.kill. Only actual pidfd exit
// and populated=0 of the captured cgroup produce a durable quiescence record.
// Timeout or any failed observation leaves the retiring fence and pending runs.
func (r *Retirement) Retire(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || (r.record.State != "bound" && r.record.State != "retiring") {
		return errors.New("retirement binding unavailable or already quiescent")
	}
	admission, err := r.gate.lock(ctx, "admission")
	if err != nil {
		return err
	}
	defer unlock(admission)
	proof, err := r.gate.lock(ctx, "retirement")
	if err != nil {
		return err
	}
	defer unlock(proof)
	r.record.State = "retiring"
	raw, _ := json.Marshal(r.record)
	if err = r.gate.mark(proof, string(raw)); err != nil {
		return err
	}
	kill, err := unix.Openat(r.cgroup, "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	_, err = unix.Write(kill, []byte("1"))
	closeErr := unix.Close(kill)
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	for {
		daemon, e := pidExited(r.daemon)
		if e != nil {
			return e
		}
		worker, e := pidExited(r.worker)
		if e != nil {
			return e
		}
		events, e := readAt(r.cgroup, "cgroup.events")
		if e != nil {
			return e
		}
		empty := false
		found := false
		for _, line := range strings.Split(string(events), "\n") {
			if line == "populated 0" {
				empty = true
				found = true
			}
			if line == "populated 1" {
				found = true
			}
		}
		if !found {
			return errors.New("missing cgroup populated observation")
		}
		if daemon && worker && empty {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	r.record.State = "kernel_quiescent"
	raw, _ = json.Marshal(r.record)
	return r.gate.mark(proof, string(raw))
}

func (g *Gate) Reconciliation(ctx context.Context, id string) (*Reconciliation, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("invalid run ID")
	}
	f, err := g.lock(ctx, "retirement")
	if err != nil {
		return nil, err
	}
	defer unlock(f)
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	var record retirementRecord
	if json.Unmarshal(raw, &record) != nil || record.Authority != g.authority || record.State != "retired" || record.CgroupInode == 0 || len(record.Data) != 3 || record.DaemonPID <= 1 || record.WorkerPID <= 1 || record.WorkerPID == record.DaemonPID {
		return nil, errors.New("original node quiescence unproven")
	}
	binding, err := g.lock(ctx, "retirement-binding")
	if err != nil {
		return nil, err
	}
	defer unlock(binding)
	original, err := io.ReadAll(io.LimitReader(binding, 4096))
	if err != nil {
		return nil, err
	}
	record.State = "bound"
	expected, _ := json.Marshal(record)
	if string(original) != string(expected) {
		return nil, errors.New("quiescence does not match original binding")
	}
	run, err := g.lock(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock(run)
	marker, err := io.ReadAll(io.LimitReader(run, 128))
	if err != nil {
		return nil, err
	}
	if len(marker) == 0 {
		return nil, errors.New("unconsumed run cannot be reconciled")
	}
	sum := sha256.Sum256(raw)
	return &Reconciliation{run: id, authority: g.authority, digest: hex.EncodeToString(sum[:])}, nil
}

// Finalize produces the accepted proof only after the original Popen owner has
// reaped its daemon and removed the bound daemon data. A supervisor response is
// merely a wakeup: pidfd HUP, cgroup emptiness and original unlinked directory
// descriptors are checked here independently. Failed cleanup stays pending.
func (r *Retirement) Finalize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.record.State != "kernel_quiescent" {
		return errors.New("kernel retirement required")
	}
	if err := r.verifyDiskCleanup(); err != nil {
		return err
	}
	for _, fd := range []int{r.daemon, r.worker} {
		reaped, err := pidReaped(fd)
		if err != nil {
			return err
		}
		if !reaped {
			return errors.New("original process not reaped")
		}
	}
	events, err := readAt(r.cgroup, "cgroup.events")
	if err != nil {
		return err
	}
	if !strings.Contains("\n"+string(events), "\npopulated 0\n") {
		return errors.New("original node not empty")
	}
	proof, err := r.gate.lock(ctx, "retirement")
	if err != nil {
		return err
	}
	defer unlock(proof)
	raw, err := io.ReadAll(io.LimitReader(proof, 4096))
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(r.record)
	if string(raw) != string(expected) {
		return errors.New("retirement identity changed")
	}
	r.record.State = "retired"
	raw, _ = json.Marshal(r.record)
	return r.gate.mark(proof, string(raw))
}
func (r *Retirement) verifyDiskCleanup() error {
	if len(r.data) != 3 || len(r.record.Data) != 3 {
		return errors.New("original data not bound")
	}
	for i, fd := range r.data {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Nlink != 0 || st.Dev != r.record.Data[i].Device || st.Ino != r.record.Data[i].Inode {
			return errors.New("original daemon data not removed")
		}
	}
	for _, name := range []string{"root", "state", "io", "containerd.sock", "containerd.sock.ttrpc"} {
		var st unix.Stat_t
		err := unix.Fstatat(r.session, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, unix.ENOENT) {
			return errors.New("daemon state remains or cannot be inspected")
		}
	}
	return nil
}
