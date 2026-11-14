package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type apiClient struct {
	path string
	pid  int
	uid  uint32
}

func (c apiClient) dial(ctx context.Context) (net.Conn, error) {
	if c.pid <= 0 {
		return nil, errors.New("original process identity required")
	}
	resolved, e := filepath.EvalSymlinks(c.path)
	if e != nil || resolved != c.path {
		return nil, errors.New("redirected API socket")
	}
	st, e := os.Lstat(c.path)
	if e != nil {
		return nil, e
	}
	if st.Mode()&os.ModeSocket == 0 || st.Sys().(*syscall.Stat_t).Uid != c.uid {
		return nil, errors.New("API socket owner/type mismatch")
	}
	conn, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", c.path)
	if e != nil {
		return nil, e
	}
	raw, e := conn.(syscall.Conn).SyscallConn()
	if e != nil {
		conn.Close()
		return nil, e
	}
	var cred *unix.Ucred
	var peerErr error
	e = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || peerErr != nil || cred == nil || cred.Pid != int32(c.pid) || cred.Uid != c.uid {
		conn.Close()
		return nil, errors.New("API peer differs from original VMM")
	}
	return conn, nil
}
func (c apiClient) call(ctx context.Context, method, path string, body any) error {
	if !(method == "PUT" && (path == "/actions" || path == "/machine-config" || path == "/boot-source" || path == "/drives/rootfs" || path == "/drives/payload" || path == "/vsock" || path == "/snapshot/create" || path == "/snapshot/load") || method == "PATCH" && path == "/vm") {
		return errors.New("unsupported fixed API operation")
	}
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	if len(b) > 65536 {
		return errors.New("API request too large")
	}
	// No pooling or automatic retry of a mutation on a dead keepalive socket.
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return c.dial(ctx) }}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("API redirect forbidden") }}
	r, e := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := client.Do(r)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil {
		return e
	}
	if len(raw) > 4096 {
		return errors.New("API response too large")
	}
	if response.StatusCode != 204 {
		return fmt.Errorf("Firecracker API status %d", response.StatusCode)
	}
	return nil
}
