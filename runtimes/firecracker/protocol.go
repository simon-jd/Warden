package firecracker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"warden/runtimes"
)

type Frame struct {
	Version  int            `json:"version"`
	Kind     string         `json:"kind"`
	Nonce    string         `json:"nonce,omitempty"`
	RunID    string         `json:"run_id,omitempty"`
	AgentSHA string         `json:"agent_sha,omitempty"`
	Profile  *Profile       `json:"profile,omitempty"`
	Data     []byte         `json:"data,omitempty"`
	Exit     *runtimes.Exit `json:"exit,omitempty"`
}

func WriteFrame(w io.Writer, f Frame) error {
	b, e := json.Marshal(f)
	if e != nil {
		return e
	}
	if len(b) == 0 || len(b) > 65536 {
		return errors.New("frame exceeds 64KiB")
	}
	raw := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(raw, uint32(len(b)))
	copy(raw[4:], b)
	for len(raw) > 0 {
		n, e := w.Write(raw)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(raw) {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return f, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > 65536 {
		return f, errors.New("invalid frame size")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return f, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&f); e != nil {
		return f, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return f, errors.New("trailing frame value")
	}
	return f, nil
}

type Transcript struct {
	Nonce, RunID, AgentSHA string
	state                  int
}

func (t *Transcript) Accept(f Frame) error {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(t.Nonce) || !runPattern.MatchString(t.RunID) || f.Version != 1 || f.Profile != nil {
		return errors.New("invalid trusted session")
	}
	if t.state == 0 {
		if f.Kind != "hello" || f.AgentSHA != t.AgentSHA || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(t.AgentSHA) || f.Nonce != "" || f.RunID != "" || len(f.Data) > 0 || f.Exit != nil {
			return errors.New("unexpected agent identity")
		}
		t.state = 1
		return nil
	}
	if f.Nonce != t.Nonce || f.RunID != t.RunID || f.AgentSHA != "" {
		return errors.New("unbound or stale guest frame")
	}
	if t.state == 1 {
		if f.Kind != "ack" || f.Exit != nil || len(f.Data) > 0 {
			return errors.New("EXEC acknowledgement required")
		}
		t.state = 2
		return nil
	}
	if t.state != 2 {
		return errors.New("already terminated")
	}
	switch f.Kind {
	case "stdout", "stderr":
		if f.Exit != nil || len(f.Data) > 32768 {
			return errors.New("invalid log frame")
		}
	case "exit":
		if f.Exit == nil || len(f.Data) > 0 || !f.Exit.CgroupEmpty {
			return errors.New("trusted full-tree exit required")
		}
		t.state = 3
	default:
		return errors.New("unexpected guest frame")
	}
	return nil
}
