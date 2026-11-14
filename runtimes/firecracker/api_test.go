package firecracker

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// socketPath is name in a fresh 0700 directory under /tmp. A Unix socket path
// must fit sun_path (107 bytes and the NUL), and t.TempDir() below the
// Makefile's private TMPDIR is as long as the checkout path makes it: too long
// in a worktree, and in the main checkout with no byte to spare. Under /tmp
// the length does not depend on the checkout. Only the directory below /tmp
// is ours, as in the runc tests (temporarySocket); the API client's checks
// (no symlink, socket owner, peer credentials) are unchanged.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "wfc")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// A real Unix HTTP server is the API boundary double; no Firecracker/KVM runs.
// Catches hidden mutation retries after the server consumed a request.
func TestLostStartResponseIsNeverRetried(t *testing.T) {
	p := socketPath(t, "api.sock")
	ln, e := net.Listen("unix", p)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	var starts atomic.Int32
	srv := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		starts.Add(1)
		c, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		c.Close()
	})}
	defer srv.Close()
	go srv.Serve(ln)
	c := apiClient{p, os.Getpid(), uint32(os.Geteuid())}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = c.call(ctx, "PUT", "/actions", map[string]string{"action_type": "InstanceStart"}); e == nil {
		t.Fatal("lost response treated as success")
	}
	if starts.Load() != 1 {
		t.Fatalf("mutation attempts=%d", starts.Load())
	}
}
func TestAPIRejectsWrongPeerBeforeMutation(t *testing.T) {
	p := socketPath(t, "api.sock")
	ln, e := net.Listen("unix", p)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	var calls atomic.Int32
	srv := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) })}
	defer srv.Close()
	go srv.Serve(ln)
	for _, c := range []apiClient{{p, os.Getpid() + 99999, uint32(os.Geteuid())}, {p, os.Getpid(), uint32(os.Geteuid() + 1)}} {
		if e = c.call(context.Background(), "PUT", "/actions", map[string]string{"action_type": "InstanceStart"}); e == nil {
			t.Fatal("wrong API peer accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("mutation sent to unauthenticated peer")
	}
	c := apiClient{p, os.Getpid(), uint32(os.Geteuid())}
	if e = c.call(context.Background(), "PUT", "/actions", map[string]string{"action_type": "InstanceStart"}); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("authenticated request not delivered")
	}
}
