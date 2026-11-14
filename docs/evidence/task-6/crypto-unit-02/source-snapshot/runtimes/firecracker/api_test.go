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

// A real Unix HTTP server is the API boundary double; no Firecracker/KVM runs.
// Catches hidden mutation retries after the server consumed a request.
func TestLostStartResponseIsNeverRetried(t *testing.T) {
	p := filepath.Join(private(t), "api.sock")
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
	p := filepath.Join(private(t), "api.sock")
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
