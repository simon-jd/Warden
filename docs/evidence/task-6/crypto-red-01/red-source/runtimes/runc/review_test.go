package runc

import (
	"context"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeIO models only the external cio boundary. Actual bytes travel through an
// OS pipe; Cancel has containerd's documented destructive close behavior.
type pipeIO struct {
	r, w  *os.File
	done  chan struct{}
	logs  *logBuffer
	start chan struct{}
	once  sync.Once
}

func newPipeIO(t *testing.T) *pipeIO {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	p := &pipeIO{r: r, w: w, done: make(chan struct{}), logs: newLogBuffer(1024), start: make(chan struct{})}
	t.Cleanup(func() { p.Close() })
	go func() { defer close(p.done); <-p.start; io.Copy(p.logs, p.r) }()
	return p
}
func (p *pipeIO) Wait()        { <-p.done }
func (p *pipeIO) Cancel()      { p.r.Close() }
func (p *pipeIO) Close() error { p.once.Do(func() { p.r.Close(); p.w.Close() }); return nil }
func TestDrainWaitsForTailAfterExitBeforeCancel(t *testing.T) {
	p := newPipeIO(t)
	if _, e := p.w.WriteString("tail-after-exit"); e != nil {
		t.Fatal(e)
	}
	p.w.Close()
	// Exit has already happened, but FIFO copying has not consumed any bytes.
	go func() { time.Sleep(20 * time.Millisecond); close(p.start) }()
	if e := drainIO(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	raw, _ := io.ReadAll(p.logs.reader())
	if string(raw) != "tail-after-exit" {
		t.Fatalf("exit silently lost buffered tail: %q", raw)
	}
}
func TestDrainTimeoutReturnsTruncationError(t *testing.T) {
	p := newPipeIO(t)
	close(p.start)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := drainIO(ctx, p); e == nil {
		t.Fatal("unfinished FIFO reported complete")
	}
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("drain timeout left FIFO reader blocked")
	}
}
func temporarySocket(t *testing.T) (string, *net.UnixListener) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "warden-lab")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(dir, "containerd.sock")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return name, l
}
func socketConfig(name string) Config {
	return Config{Socket: name, CgroupRoot: "/sys/fs/cgroup/warden-lab", ExpectedDaemonPID: os.Getpid(), TrustedOwnerUID: os.Getuid()}
}
func TestSocketRejectsSymlinkAliases(t *testing.T) {
	name, _ := temporarySocket(t)
	for _, kind := range []string{"socket", "parent", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			alias := filepath.Join(base, "warden-lab")
			if kind == "parent" {
				if e := os.Symlink(filepath.Dir(name), alias); e != nil {
					t.Fatal(e)
				}
				alias = filepath.Join(alias, "containerd.sock")
			} else {
				if e := os.Mkdir(alias, 0700); e != nil {
					t.Fatal(e)
				}
				alias = filepath.Join(alias, "containerd.sock")
				target := name
				if kind == "dangling" {
					target = filepath.Join(base, "missing")
				}
				if e := os.Symlink(target, alias); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := New(socketConfig(alias)); e == nil {
				t.Fatal("dedicated-daemon guard accepted symlink alias")
			}
		})
	}
}
func TestSocketRejectsRegularFileAndWrongDaemon(t *testing.T) {
	name, _ := temporarySocket(t)
	cfg := socketConfig(name)
	cfg.ExpectedDaemonPID = os.Getpid() + 100000
	if _, e := New(cfg); e == nil {
		t.Fatal("shared/wrong daemon PID accepted")
	}
	regular := filepath.Join(filepath.Dir(name), "regular")
	if e := os.WriteFile(regular, []byte("not a socket"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := New(socketConfig(regular)); e == nil {
		t.Fatal("non-socket accepted")
	}
}
func TestSocketAcceptsOwnedDedicatedUnixListener(t *testing.T) {
	name, _ := temporarySocket(t)
	if _, e := New(socketConfig(name)); e != nil {
		t.Fatal(e)
	}
}
func TestLogOverflowReportsDroppedBytes(t *testing.T) {
	exits := make(chan processExit, 1)
	b := newLogBuffer(4)
	b.Write([]byte("1234567"))
	h := newHandle(time.Hour, b, exits, func(context.Context) (bool, error) { return true, nil }, func(context.Context) error { return nil })
	exits <- processExit{}
	out, e := h.Wait(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !out.LogsTruncated || out.DroppedLogBytes != 3 {
		t.Fatalf("overflow silently reported complete logs: %+v", out)
	}
}
func TestPauseIsAllowedWhileMountRemainsDenied(t *testing.T) {
	s, e := BuildSpec(validSpec(), "/warden-lab/warden-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if e != nil {
		t.Fatal(e)
	}
	allowed := false
	for _, rule := range s.Linux.Seccomp.Syscalls {
		for _, name := range rule.Names {
			if name == "pause" && strings.Contains(string(rule.Action), "ALLOW") {
				allowed = true
			}
		}
	}
	if !allowed {
		t.Fatal("fork fixture children cannot block; pause denied")
	}
}

func TestPidsEvidenceNeedsEventsAndRealLimitPeak(t *testing.T) {
	for _, tc := range []struct {
		events, peak         string
		wantEvents, wantPeak uint64
	}{{"max 5\n", "32\n", 3, 32}, {"max 2\n", "4\n", 0, 4}} {
		root := t.TempDir()
		if e := os.WriteFile(filepath.Join(root, "pids.events"), []byte(tc.events), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(root, "pids.peak"), []byte(tc.peak), 0600); e != nil {
			t.Fatal(e)
		}
		fd, e := os.OpenRoot(root)
		if e != nil {
			t.Fatal(e)
		}
		events, peak, e := pidsEvidence(fd, 2)
		fd.Close()
		if e != nil || events != tc.wantEvents || peak != tc.wantPeak {
			t.Fatalf("wrong measured pids evidence events=%d peak=%d err=%v", events, peak, e)
		}
	}
}

func TestSocketRejectsUntrustedOwnershipAndWritableParents(t *testing.T) {
	name, _ := temporarySocket(t)
	cfg := socketConfig(name)
	cfg.TrustedOwnerUID = os.Getuid() + 10000
	if _, e := New(cfg); e == nil {
		t.Fatal("untrusted directory/socket owner accepted")
	}
	if e := os.Chmod(filepath.Dir(name), 0777); e != nil {
		t.Fatal(e)
	}
	if _, e := New(socketConfig(name)); e == nil {
		t.Fatal("world-writable socket parent accepted")
	}
}
func TestSocketRevalidationRejectsAliasAfterConstruction(t *testing.T) {
	name, _ := temporarySocket(t)
	cfg := socketConfig(name)
	if _, e := New(cfg); e != nil {
		t.Fatal(e)
	}
	other, _ := temporarySocket(t)
	if e := os.Remove(name); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(other, name); e != nil {
		t.Fatal(e)
	}
	if connection, e := dialDedicated(context.Background(), cfg); e == nil {
		connection.Close()
		t.Fatal("replacement alias accepted during reconnect")
	}
}
func TestPidsEvidenceRejectsMalformedAndBackwardsCounters(t *testing.T) {
	for _, content := range []string{"max not-a-number\n", "other 4\n", "max 1\n"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "pids.events"), []byte(content), 0600)
		os.WriteFile(filepath.Join(dir, "pids.peak"), []byte("32\n"), 0600)
		root, e := os.OpenRoot(dir)
		if e != nil {
			t.Fatal(e)
		}
		_, _, e = pidsEvidence(root, 2)
		root.Close()
		if e == nil {
			t.Fatalf("untrustworthy pids evidence accepted %q", content)
		}
	}
}

// The external Version RPC is deliberately inert. It exercises the actual
// containerd Go client's gRPC dial configuration without any container daemon.
type inertVersion struct {
	versionapi.UnimplementedVersionServer
}

func (inertVersion) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "dedicated-fixture"}, nil
}
func TestContainerdClientDialsOnlyAuthenticatedListener(t *testing.T) {
	name, listener := temporarySocket(t)
	server := grpc.NewServer()
	versionapi.RegisterVersionServer(server, inertVersion{})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	client, e := newClient(socketConfig(name))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	version, e := client.Version(ctx)
	if e != nil || version.Version != "dedicated-fixture" {
		t.Fatalf("owned listener not reached: %+v %v", version, e)
	}
	wrong := socketConfig(name)
	wrong.ExpectedDaemonPID += 100000
	client2, e := newClient(wrong)
	if e != nil {
		return
	}
	defer client2.Close()
	blocked, cancel2 := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel2()
	if _, e = client2.Version(blocked); e == nil {
		t.Fatal("containerd client bypassed authenticated dialer")
	}
}
