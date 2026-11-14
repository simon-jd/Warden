package guest

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"warden/runtimes"
	fc "warden/runtimes/firecracker"
)

type duplex struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (d *duplex) Read(p []byte) (int, error)  { return d.in.Read(p) }
func (d *duplex) Write(p []byte) (int, error) { return d.out.Write(p) }
func wire(t *testing.T, fs ...fc.Frame) *duplex {
	t.Helper()
	var b bytes.Buffer
	for _, f := range fs {
		if e := fc.WriteFrame(&b, f); e != nil {
			t.Fatal(e)
		}
	}
	return &duplex{in: bytes.NewReader(b.Bytes())}
}

// The payload executor is a unit boundary double; no tenant is launched here.
// A second connection must never execute again even after loss of the first.
func TestGuestSessionConsumesBeforeExecutionAndRejectsReplay(t *testing.T) {
	p, e := fc.Normalize(runtimes.Spec{RunID: strings.Repeat("A", 26), ImageDigest: "sha256:" + strings.Repeat("1", 64), Cmd: []string{"/warden-probe", "uid"}}, false)
	if e != nil {
		t.Fatal(e)
	}
	n := strings.Repeat("2", 64)
	calls := 0
	s := session{hash: strings.Repeat("3", 64), execute: func(p fc.Profile, started func() error, out, errout io.Writer) (runtimes.Exit, error) {
		calls++
		if e := started(); e != nil {
			return runtimes.Exit{}, e
		}
		io.WriteString(out, `{"CgroupEmpty":false}`)
		return runtimes.Exit{CgroupEmpty: true}, nil
	}}
	frames := []fc.Frame{{Version: 1, Kind: "bind", Nonce: n, RunID: p.Spec.RunID, Profile: &p}, {Version: 1, Kind: "exec", Nonce: n, RunID: p.Spec.RunID}}
	d := wire(t, frames...)
	if e = s.serve(d); e != nil {
		t.Fatal(e)
	}
	tx := fc.Transcript{Nonce: n, RunID: p.Spec.RunID, AgentSHA: s.hash}
	for i := 0; i < 4; i++ {
		f, e := fc.ReadFrame(&d.out)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Accept(f); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.serve(wire(t, frames...)); e == nil || calls != 1 {
		t.Fatalf("reexecution: calls=%d err=%v", calls, e)
	}
}
func TestGuestSnapshotControlCannotCaptureBoundSession(t *testing.T) {
	s := session{hash: strings.Repeat("3", 64)}
	d := wire(t, fc.Frame{Version: 1, Kind: "snapshot"})
	if e := s.serve(d); e != nil {
		t.Fatal(e)
	}
	if s.consumed {
		t.Fatal("virgin snapshot bound a tenant")
	}
	s.consumed = true
	if e := s.serve(wire(t, fc.Frame{Version: 1, Kind: "snapshot"})); e == nil {
		t.Fatal("tenant state snapshot accepted")
	}
}

func TestGuestACKPrecedesEarlyChildOutput(t *testing.T) {
	p, _ := fc.Normalize(runtimes.Spec{RunID: strings.Repeat("A", 26), ImageDigest: "sha256:" + strings.Repeat("b", 64), Cmd: []string{"/warden-probe", "uid"}}, false)
	nonce := strings.Repeat("c", 64)
	var input bytes.Buffer
	fc.WriteFrame(&input, fc.Frame{Version: 1, Kind: "bind", RunID: p.Spec.RunID, Nonce: nonce, Profile: &p})
	fc.WriteFrame(&input, fc.Frame{Version: 1, Kind: "exec", RunID: p.Spec.RunID, Nonce: nonce})
	s := session{hash: strings.Repeat("d", 64), execute: func(_ fc.Profile, ack func() error, out, errOut io.Writer) (runtimes.Exit, error) {
		out.Write([]byte("early"))
		e := ack()
		return runtimes.Exit{CgroupEmpty: true}, e
	}}
	d := &duplex{in: bytes.NewReader(input.Bytes())}
	if e := s.serve(d); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"hello", "ack", "stdout", "exit"} {
		f, e := fc.ReadFrame(&d.out)
		if e != nil || f.Kind != kind {
			t.Fatalf("wanted %s, got %+v: %v", kind, f, e)
		}
	}
}
