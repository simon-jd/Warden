package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"warden/runtimes"
)

type vm struct {
	driver                       *Driver
	profile                      Profile
	uid                          uint32
	scope                        *scope
	process                      *ownedProcess
	api                          apiClient
	conn                         net.Conn
	jail                         string
	startDone, done              chan struct{}
	retireMu                     sync.Mutex
	retired                      atomic.Bool
	exit                         runtimes.Exit
	err                          error
	logs                         boundedLog
	diagnostics                  vmmTail
	console                      *consoleLog
	diagnosticPhase              string
	readyDuration, startDuration time.Duration
	executionDeadline            time.Time
	tx                           Transcript
	bound                        bool
}
type boundedLog struct {
	mu      sync.Mutex
	data    []byte
	dropped uint64
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), 1048576-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.dropped += uint64(len(p) - n)
	return len(p), nil
}
func (b *boundedLog) reader() io.ReadCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	return io.NopCloser(bytes.NewReader(bytes.Clone(b.data)))
}
func (d *Driver) start(ctx context.Context, s runtimes.Spec, benchmark bool, restore string) (runtimes.Handle, error) {
	if d == nil || d.root == nil || d.gate == nil {
		return nil, ErrCleanupPending
	}
	began := time.Now()
	p, e := Normalize(s, benchmark)
	if e != nil {
		return nil, e
	}
	if p.Spec.ImageDigest != d.manifest.ImageDigest {
		return nil, errors.New("image not in owned immutable manifest")
	}
	h, e := d.reserve(p)
	if e != nil {
		return nil, e
	}
	defer d.wg.Done()
	defer close(h.startDone)
	fail := func(e error) (runtimes.Handle, error) {
		cleanup := h.retire()
		h.err = h.failure(h.diagnosticPhase, e, cleanup)
		close(h.done)
		return h, h.err
	}
	h.diagnosticPhase = "before_boot"
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	if e = h.boot(ctx, restore); e != nil {
		return fail(e)
	}
	h.diagnosticPhase = "bind"
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fail(e)
	}
	h.tx = Transcript{Nonce: hex.EncodeToString(nonce[:]), RunID: s.RunID, AgentSHA: d.manifest.AgentSHA, state: 1}
	if e = WriteFrame(h.conn, Frame{Version: 1, Kind: "bind", Nonce: h.tx.Nonce, RunID: s.RunID, Profile: &p}); e != nil {
		return fail(e)
	}
	h.bound = true
	h.executionDeadline = time.Now().Add(time.Duration(p.Spec.Limits.TimeoutS) * time.Second)
	if e = h.conn.SetDeadline(h.executionDeadline); e != nil {
		return fail(e)
	}
	h.diagnosticPhase = "exec"
	if e = WriteFrame(h.conn, Frame{Version: 1, Kind: "exec", Nonce: h.tx.Nonce, RunID: s.RunID}); e != nil {
		return fail(e)
	}
	ack, e := ReadFrame(h.conn)
	if e != nil {
		return fail(e)
	}
	if e = h.tx.Accept(ack); e != nil {
		return fail(e)
	}
	h.startDuration = time.Since(began)
	h.conn.SetDeadline(h.executionDeadline)
	go h.collect()
	return h, nil
}
func (d *Driver) reserve(p Profile) (*vm, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errors.New("node closed")
	}
	active := 0
	for _, h := range d.handles {
		if !h.retired.Load() {
			active++
		}
	}
	if active >= d.limit {
		return nil, errors.New("sealed node VM reservation full")
	}
	if _, exists := d.handles[p.Spec.RunID]; exists {
		return nil, errors.New("RunID already consumed")
	}
	record, e := checkedFile(d.root, "runs/"+p.Spec.RunID, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return nil, e
	}
	u, e := d.allocator.Allocate(p.Spec.RunID)
	if e != nil {
		record.Close()
		return nil, e
	}
	e = json.NewEncoder(record).Encode(struct {
		Authority string
		UID       uint32
		Profile   Profile
	}{d.gate.Authority(), u, p})
	e = errors.Join(e, record.Sync(), record.Close())
	runs, e2 := d.root.OpenRoot("runs")
	if e2 == nil {
		e = errors.Join(e, syncRoot(runs), runs.Close())
	} else {
		e = errors.Join(e, e2)
	}
	if e != nil {
		return nil, e
	}
	h := &vm{driver: d, profile: p, uid: u, startDone: make(chan struct{}), done: make(chan struct{})}
	d.handles[p.Spec.RunID] = h
	d.wg.Add(1)
	return h, nil
}
func (h *vm) boot(ctx context.Context, restore string) error {
	d := h.driver
	p := h.profile
	// Fresh copies are forbidden here: a sealed node already owns bounded,
	// immutable assets, linked without changing shared inode ownership or mode.
	jailRel := "firecracker/warden-" + p.Spec.RunID + "/root"
	session, e := privateRoot(sessionPath)
	if e != nil {
		return e
	}
	defer session.Close()
	if e = session.MkdirAll("jails/"+jailRel, 0700); e != nil {
		return e
	}
	h.jail = sessionPath + "/jails/" + jailRel
	assets, e := d.root.OpenRoot("assets")
	if e != nil {
		return e
	}
	defer assets.Close()
	for _, name := range []string{"kernel", "agent.ext4", "payload.ext4"} {
		f, e := verifiedArtifact(assets, name, d.manifest.Artifacts[name], 64<<20)
		if e != nil {
			return e
		}
		f.Close()
		if e = os.Link(sessionPath+"/node/assets/"+name, h.jail+"/"+name); e != nil {
			return e
		}
	}
	h.scope, e = makeScope(d.cgroups, p)
	if e != nil {
		return e
	}
	args, e := jailerArgs(p, h.uid)
	if e != nil {
		return e
	}
	console, e := checkedFile(d.root, "console/"+p.Spec.RunID+".log", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	h.console = newConsoleLog(console, 65536)
	output := io.MultiWriter(&h.diagnostics, h.console)
	cmd := exec.Command(inputPath+"/jailer", args...)
	cmd.Env = []string{}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(h.scope.fd.Fd())}
	launched := time.Now()
	h.diagnosticPhase = "jailer_start"
	h.process, e = startOwned(cmd)
	if e != nil {
		return e
	}
	h.api = apiClient{h.jail + "/api.sock", cmd.Process.Pid, h.uid}
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	h.diagnosticPhase = "api_ready"
	for {
		if _, e = os.Lstat(h.api.path); e == nil {
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		select {
		case <-readyCtx.Done():
			return readyCtx.Err()
		case <-h.process.done:
			return errors.New("jailer exited before API readiness")
		case <-time.After(time.Millisecond):
		}
	}
	if restore != "" {
		h.diagnosticPhase = "snapshot_restore"
		if e = h.restore(readyCtx, restore); e != nil {
			return e
		}
	} else {
		for _, op := range []struct {
			path  string
			phase string
			body  any
		}{
			{"/machine-config", "machine_config", map[string]any{"vcpu_count": 1, "mem_size_mib": p.VMMemoryMiB, "smt": false}},
			{"/boot-source", "boot_source", map[string]any{"kernel_image_path": "/kernel", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/agent WARDEN_FC_GUEST=1"}},
			{"/drives/rootfs", "root_drive", map[string]any{"drive_id": "rootfs", "path_on_host": "/agent.ext4", "is_root_device": true, "is_read_only": true}},
			{"/drives/payload", "payload_drive", map[string]any{"drive_id": "payload", "path_on_host": "/payload.ext4", "is_root_device": false, "is_read_only": true}},
			{"/vsock", "vsock", map[string]any{"guest_cid": 3, "uds_path": "/control.sock"}},
			{"/actions", "instance_start", map[string]string{"action_type": "InstanceStart"}},
		} {
			h.diagnosticPhase = op.phase
			if e = h.api.call(readyCtx, "PUT", op.path, op.body); e != nil {
				return e
			}
		}
	}
	h.diagnosticPhase = "guest_ready"
	for {
		if e = readyCtx.Err(); e != nil {
			return e
		}
		select {
		case <-h.process.done:
			return errors.New("VMM exited before guest readiness")
		default:
		}
		c, e := h.connectGuest(readyCtx)
		if e == nil {
			h.conn = c
			h.readyDuration = time.Since(launched)
			return nil
		}
		select {
		case <-readyCtx.Done():
			return errors.Join(readyCtx.Err(), e)
		case <-time.After(5 * time.Millisecond):
		}
	}
}
func (h *vm) connectGuest(ctx context.Context) (net.Conn, error) {
	c, e := (apiClient{h.jail + "/control.sock", h.process.cmd.Process.Pid, h.uid}).dial(ctx)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	if end, yes := ctx.Deadline(); yes && end.Before(deadline) {
		deadline = end
	}
	c.SetDeadline(deadline)
	if _, e = io.WriteString(c, "CONNECT 52\n"); e != nil {
		return nil, e
	}
	reader := bufio.NewReaderSize(c, 256)
	line, e := reader.ReadSlice('\n')
	if e != nil || len(line) > 128 || !strings.HasPrefix(string(line), "OK ") {
		return nil, errors.New("private vsock CONNECT rejected")
	}
	hello, e := ReadFrame(reader)
	if e != nil {
		return nil, e
	}
	if hello.Version != 1 || hello.Kind != "hello" || hello.AgentSHA != h.driver.manifest.AgentSHA || hello.RunID != "" || hello.Nonce != "" || hello.Exit != nil || hello.Profile != nil || len(hello.Data) > 0 {
		return nil, errors.New("trusted agent HELLO mismatch")
	}
	// HELLO is the only guest output before BIND; no unread framed bytes may be
	// silently discarded when handing the connection to the execution reader.
	if reader.Buffered() != 0 {
		return nil, errors.New("unsolicited pre-BIND guest data")
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	ok = true
	return c, nil
}
func (h *vm) collect() {
	defer close(h.done)
	for {
		f, e := ReadFrame(h.conn)
		if e != nil {
			h.err = e
			break
		}
		if e = h.tx.Accept(f); e != nil {
			h.err = e
			break
		}
		if f.Kind == "stdout" || f.Kind == "stderr" {
			h.logs.Write(f.Data)
			continue
		}
		h.exit = *f.Exit
		break
	}
	if h.err != nil && !time.Now().Before(h.executionDeadline) {
		h.exit.TimedOut = true
		h.exit.Code = 137
	}
	cleanup := h.retire()
	if cleanup != nil {
		h.exit.CgroupEmpty = false
	} else if h.err != nil {
		h.err = errors.Join(h.err, errors.New("trusted final guest metrics unavailable"))
	}
	if h.err != nil || cleanup != nil {
		h.err = h.failure("collect", h.err, cleanup)
	}
}
func (h *vm) retire() (retireErr error) {
	h.retireMu.Lock()
	defer h.retireMu.Unlock()
	defer func() {
		if retireErr != nil {
			retireErr = h.failure("retire", nil, retireErr)
		}
	}()
	if h.retired.Load() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if h.conn != nil {
		h.conn.Close()
	}
	var failures []error
	if h.process != nil {
		h.process.noteCleanup()
	}
	if h.scope != nil {
		if e := h.scope.killEmpty(ctx); e != nil {
			failures = append(failures, e)
		}
	}
	if h.process != nil {
		if e := h.process.Stop(); e != nil {
			failures = append(failures, e)
		}
	}
	if len(failures) == 0 && h.console != nil {
		if e := h.console.Close(); e != nil {
			failures = append(failures, e)
		}
	}
	if len(failures) > 0 {
		return errors.Join(append(failures, ErrCleanupPending)...)
	}
	if h.scope != nil {
		if e := h.scope.remove(); e != nil {
			return errors.Join(e, ErrCleanupPending)
		}
	}
	if h.jail != "" {
		session, e := privateRoot(sessionPath)
		if e != nil {
			return e
		}
		defer session.Close()
		rel, err := filepath.Rel(sessionPath, h.jail)
		if err != nil || !strings.HasPrefix(rel, "jails/firecracker/warden-") {
			return ErrCleanupPending
		}
		if e = session.RemoveAll(filepath.Dir(rel)); e != nil {
			return errors.Join(e, ErrCleanupPending)
		}
	}
	h.retired.Store(true)
	return nil
}
func (h *vm) Wait(ctx context.Context) (runtimes.Exit, error) {
	select {
	case <-ctx.Done():
		return runtimes.Exit{}, ctx.Err()
	case <-h.done:
	}
	return h.exit, h.err
}
func (h *vm) Kill() error                             { <-h.startDone; return h.retire() }
func (h *vm) Logs() io.ReadCloser                     { return h.logs.reader() }
func (h *vm) Timings() (time.Duration, time.Duration) { return h.readyDuration, h.startDuration }
