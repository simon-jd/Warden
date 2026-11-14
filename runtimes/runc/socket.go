package runc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

// validateSocketPath opens every component without following symlinks. Only
// root and the explicitly trusted operator may own its directory chain. A root
// sticky temporary directory is safe because unprivileged users cannot replace
// another owner's entries; other writable ancestor directories are rejected.
func validateSocketPath(cfg Config) error {
	if cfg.ExpectedDaemonPID <= 0 || cfg.TrustedOwnerUID < 0 {
		return errors.New("explicit dedicated daemon PID and trusted owner required")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer func() { unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(cfg.Socket, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return fmt.Errorf("unsafe socket ancestor: %w", e)
		}
		unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			return e
		}
		if st.Uid != 0 && int(st.Uid) != cfg.TrustedOwnerUID {
			return errors.New("untrusted socket directory owner")
		}
		if st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			return errors.New("socket ancestor writable by untrusted group/other")
		}
	}
	var st unix.Stat_t
	if e = unix.Fstatat(fd, filepath.Base(cfg.Socket), &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("dedicated endpoint is not a Unix socket")
	}
	if st.Uid != 0 && int(st.Uid) != cfg.TrustedOwnerUID {
		return errors.New("untrusted socket owner")
	}
	return nil
}

func dialDedicated(ctx context.Context, cfg Config) (net.Conn, error) {
	if e := validateSocketPath(cfg); e != nil {
		return nil, e
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", cfg.Socket)
	if e != nil {
		return nil, e
	}
	raw, e := conn.(*net.UnixConn).SyscallConn()
	if e != nil {
		conn.Close()
		return nil, e
	}
	var credential *unix.Ucred
	var credentialErr error
	e = raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if e != nil || credentialErr != nil {
		conn.Close()
		return nil, errors.Join(e, credentialErr)
	}
	if int(credential.Pid) != cfg.ExpectedDaemonPID || (credential.Uid != 0 && int(credential.Uid) != cfg.TrustedOwnerUID) {
		conn.Close()
		return nil, errors.New("Unix peer is not the explicitly owned dedicated daemon")
	}
	return conn, nil
}
func validateSocket(cfg Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, e := dialDedicated(ctx, cfg)
	if e != nil {
		return e
	}
	return conn.Close()
}
func newClient(cfg Config) (*containerd.Client, error) {
	// Every gRPC dial/reconnect checks both no-follow filesystem ownership and
	// peer credentials. Swapping a socket after New cannot target another daemon.
	return containerd.New(cfg.Socket, containerd.WithTimeout(5*time.Second), containerd.WithExtraDialOpts([]grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dialDedicated(ctx, cfg) })}))
}
