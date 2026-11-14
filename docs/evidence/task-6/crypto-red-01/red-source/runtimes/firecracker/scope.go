package firecracker

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"time"
)

type scope struct {
	parent, root *os.Root
	fd           *os.File
	name         string
	closed       bool
}

func makeScope(parent *os.Root, p Profile) (*scope, error) {
	name := "warden-" + p.Spec.RunID
	if !runPattern.MatchString(p.Spec.RunID) {
		return nil, errors.New("invalid scope ID")
	}
	if e := parent.Mkdir(name, 0700); e != nil {
		return nil, e
	}
	root, e := parent.OpenRoot(name)
	if e != nil {
		return nil, e
	}
	fd, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, e
	}
	s := &scope{parent: parent, root: root, fd: fd, name: name}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(fd.Fd()), &fs); e != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		fd.Close()
		root.Close()
		return nil, errors.New("real cgroup scope required")
	}
	for _, item := range [][2]string{{"memory.max", strconv.Itoa(p.HostMemoryMiB * 1048576)}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", "64"}, {"cpu.max", "100000 100000"}} {
		if e = s.write(item[0], item[1]); e != nil {
			return s, e
		}
	}
	return s, nil
}
func (s *scope) write(name, value string) error {
	f, e := s.root.OpenFile(name, os.O_WRONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	_, e = f.WriteString(value)
	return errors.Join(e, f.Close())
}
func (s *scope) killEmpty(ctx context.Context) error {
	if s.closed {
		return nil
	}
	if e := s.write("cgroup.kill", "1"); e != nil {
		return e
	}
	for {
		f, e := s.root.OpenFile("cgroup.events", os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		n, e := Counter(string(b), "populated")
		if e != nil {
			return e
		}
		if n == 0 {
			return nil
		}
		if n != 1 {
			return fmt.Errorf("invalid populated %d", n)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}
func (s *scope) remove() error {
	if s.closed {
		return nil
	}
	if e := s.parent.Remove(s.name); e != nil {
		return e
	}
	s.closed = true
	return errors.Join(s.fd.Close(), s.root.Close())
}
