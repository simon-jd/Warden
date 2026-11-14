package firecracker

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"warden/runtimes"
)

func TestProtocolSeparatesTenantLogsAndTrustedExit(t *testing.T) {
	tx := Transcript{Nonce: strings.Repeat("1", 64), RunID: spec().RunID, AgentSHA: strings.Repeat("2", 64)}
	for _, f := range []Frame{{Version: 1, Kind: "hello", AgentSHA: tx.AgentSHA}, {Version: 1, Kind: "ack", Nonce: tx.Nonce, RunID: tx.RunID}, {Version: 1, Kind: "stdout", Nonce: tx.Nonce, RunID: tx.RunID, Data: []byte(`{"OOMKilled":true,"CgroupEmpty":true}`)}, {Version: 1, Kind: "exit", Nonce: tx.Nonce, RunID: tx.RunID, Exit: &runtimes.Exit{Code: 0, CgroupEmpty: true}}} {
		var b bytes.Buffer
		if e := WriteFrame(&b, f); e != nil {
			t.Fatal(e)
		}
		got, e := ReadFrame(&b)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Accept(got); e != nil {
			t.Fatal(e)
		}
	}
	if e := tx.Accept(Frame{Version: 1, Kind: "ack", Nonce: tx.Nonce, RunID: tx.RunID}); e == nil {
		t.Fatal("replayed EXEC acknowledgement accepted")
	}
}
func TestProtocolRejectsAmbiguousOrUnboundFrames(t *testing.T) {
	for _, f := range []Frame{{Version: 1, Kind: "exit", Exit: &runtimes.Exit{CgroupEmpty: true}}, {Version: 2, Kind: "hello"}, {Version: 1, Kind: "hello", AgentSHA: "wrong"}, {Version: 1, Kind: "stdout", Data: []byte("PASS")}} {
		tx := Transcript{Nonce: strings.Repeat("1", 64), RunID: spec().RunID, AgentSHA: strings.Repeat("2", 64)}
		if e := tx.Accept(f); e == nil {
			t.Fatal("unbound frame accepted")
		}
	}
	for _, raw := range [][]byte{{0, 1, 0, 1}, {0, 0, 0, 0}, {0, 0, 0, 5, '{', '}'}} {
		if _, e := ReadFrame(bytes.NewReader(raw)); e == nil {
			t.Fatal("bad framing accepted")
		}
	}
	bad := []byte(`{"version":1,"kind":"hello","unknown":true}`)
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(bad)))
	b.Write(bad)
	if _, e := ReadFrame(&b); e == nil {
		t.Fatal("unknown wire field accepted")
	}
}
func TestProtocolHandlesShortWrites(t *testing.T) {
	var b bytes.Buffer
	if e := WriteFrame(shortWriter{&b}, Frame{Version: 1, Kind: "hello"}); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadFrame(&b); e != nil {
		t.Fatal(e)
	}
}

type shortWriter struct{ io.Writer }

func (w shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Writer.Write(p)
}
