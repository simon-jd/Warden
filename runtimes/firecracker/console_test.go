package firecracker

import (
	"bytes"
	"os"
	"testing"
)

// 10-24 kept only an in-memory console tail, so the line naming the guest
// failure was never saved. Each VM's serial console now also goes to a
// bounded private file; overflow is dropped without failing the VMM pipe.
func TestConsoleLogKeepsBoundedPrefixWithoutError(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "console")
	if e != nil {
		t.Fatal(e)
	}
	c := newConsoleLog(f, 10)
	for _, chunk := range []string{"[ 0.1] a\n", "guest agent failed\n", "more\n"} {
		if n, e := c.Write([]byte(chunk)); e != nil || n != len(chunk) {
			t.Fatalf("console write must never fail the VMM pipe: %d %v", n, e)
		}
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(f.Name())
	if e != nil || !bytes.Equal(raw, []byte("[ 0.1] a\ng")) || c.dropped != uint64(len("uest agent failed\nmore\n")) {
		t.Fatalf("bounded prefix: %q dropped=%d %v", raw, c.dropped, e)
	}
	if n, e := c.Write([]byte("late")); e != nil || n != 4 {
		t.Fatalf("write after close: %d %v", n, e)
	}
}
