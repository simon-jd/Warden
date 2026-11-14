package guest

import (
	"errors"
	"io"
	"reflect"
	"regexp"
	"sync"
	"warden/runtimes"
	fc "warden/runtimes/firecracker"
)

type executor func(fc.Profile, func() error, io.Writer, io.Writer) (runtimes.Exit, error)
type session struct {
	hash     string
	consumed bool
	execute  executor
}

func (s *session) serve(c io.ReadWriter) error {
	if s.consumed {
		return errors.New("guest permanently consumed")
	}
	if e := fc.WriteFrame(c, fc.Frame{Version: 1, Kind: "hello", AgentSHA: s.hash}); e != nil {
		return e
	}
	f, e := fc.ReadFrame(c)
	if e != nil {
		return e
	}
	if f.Version == 1 && f.Kind == "snapshot" && f.Nonce == "" && f.RunID == "" && f.Profile == nil && f.Exit == nil && len(f.Data) == 0 && f.AgentSHA == "" {
		return fc.WriteFrame(c, fc.Frame{Version: 1, Kind: "snapshot-ready"})
	}
	// Even a malformed BIND consumes this microVM; the host must retire it.
	s.consumed = true
	if f.Version != 1 || f.Kind != "bind" || f.Profile == nil || f.AgentSHA != "" || f.Exit != nil || len(f.Data) > 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(f.Nonce) || f.RunID != f.Profile.Spec.RunID {
		return errors.New("invalid BIND")
	}
	p, e := fc.Normalize(f.Profile.Spec, f.Profile.VMMemoryMiB == 128)
	if e != nil || !reflect.DeepEqual(p, *f.Profile) {
		return errors.New("unreviewed guest limits")
	}
	command, e := fc.ReadFrame(c)
	if e != nil {
		return e
	}
	if command.Version != 1 || command.Kind != "exec" || command.Nonce != f.Nonce || command.RunID != f.RunID || command.Profile != nil || command.Exit != nil || len(command.Data) > 0 || command.AgentSHA != "" || s.execute == nil {
		return errors.New("invalid one-shot EXEC")
	}
	logs := &logChannel{c: c, nonce: f.Nonce, run: f.RunID}
	started := false
	out, e := s.execute(p, func() error {
		if started {
			return errors.New("duplicate EXEC acknowledgement")
		}
		started = true
		return logs.ack()
	}, logWriter{logs, "stdout"}, logWriter{logs, "stderr"})
	if e != nil || logs.err != nil || !started {
		return errors.Join(e, logs.err, errors.New("guest execution incomplete"))
	}
	out.DroppedLogBytes += logs.dropped
	out.LogsTruncated = out.LogsTruncated || logs.dropped > 0
	return fc.WriteFrame(c, fc.Frame{Version: 1, Kind: "exit", Nonce: f.Nonce, RunID: f.RunID, Exit: &out})
}

type logChannel struct {
	mu            sync.Mutex
	c             io.Writer
	nonce, run    string
	sent, dropped uint64
	err           error
	ready         bool
	pending       []fc.Frame
}
type logWriter struct {
	channel *logChannel
	kind    string
}

func (w logWriter) Write(p []byte) (int, error) {
	l := w.channel
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		take := min(len(p), 32768, int(1048576-l.sent))
		if take == 0 || l.err != nil {
			l.dropped += uint64(len(p))
			break
		}
		frame := fc.Frame{Version: 1, Kind: w.kind, Nonce: l.nonce, RunID: l.run, Data: append([]byte(nil), p[:take]...)}
		if l.ready {
			l.err = fc.WriteFrame(l.c, frame)
		} else {
			l.pending = append(l.pending, frame)
		}
		l.sent += uint64(take)
		p = p[take:]
	}
	return n, nil
}

func (l *logChannel) ack() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ready {
		return errors.New("duplicate ack")
	}
	if e := fc.WriteFrame(l.c, fc.Frame{Version: 1, Kind: "ack", Nonce: l.nonce, RunID: l.run}); e != nil {
		l.err = e
		return e
	}
	l.ready = true
	for _, f := range l.pending {
		if e := fc.WriteFrame(l.c, f); e != nil {
			l.err = e
			return e
		}
	}
	l.pending = nil
	return nil
}
