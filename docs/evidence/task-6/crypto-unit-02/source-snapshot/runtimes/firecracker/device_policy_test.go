package firecracker

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// A deliberately small test-only interpreter executes the emitted bytes.
// This is not the kernel verifier or evidence that any BPF syscall succeeded.
func evaluateDeviceProgram(t *testing.T, code []deviceInstruction, kind, major, minor, access uint32) uint64 {
	t.Helper()
	var r [11]uint64
	ctx := map[int16]uint32{0: access<<16 | kind, 4: major, 8: minor}
	for pc, steps := 0, 0; pc < len(code) && steps < 64; pc, steps = pc+1, steps+1 {
		ins := code[pc]
		dst, src := ins.Registers&15, ins.Registers>>4
		switch ins.Code {
		case 0x61:
			if src != 1 {
				t.Fatal("unexpected context register")
			}
			r[dst] = uint64(ctx[ins.Offset])
		case 0x54:
			r[dst] = uint64(uint32(r[dst]) & uint32(ins.Immediate))
		case 0x55:
			if r[dst] != uint64(uint32(ins.Immediate)) {
				pc += int(ins.Offset)
			}
		case 0x15:
			if r[dst] == uint64(uint32(ins.Immediate)) {
				pc += int(ins.Offset)
			}
		case 0xb7:
			r[dst] = uint64(ins.Immediate)
		case 0x95:
			return r[0]
		default:
			t.Fatalf("unknown instruction %x", ins.Code)
		}
	}
	t.Fatal("no bounded return")
	return 0
}
func TestDevicePolicyDeniesOnlyTUNReadWrite(t *testing.T) {
	for _, kind := range []uint32{unix.BPF_DEVCG_DEV_CHAR, unix.BPF_DEVCG_DEV_BLOCK} {
		for _, dev := range [][2]uint32{{10, 200}, {10, 232}, {10, 201}, {1, 3}, {1, 9}, {11, 200}} {
			for access := uint32(1); access < 8; access++ {
				deny := kind == unix.BPF_DEVCG_DEV_CHAR && dev == [2]uint32{10, 200} && access&6 != 0
				got := evaluateDeviceProgram(t, fixedDeviceProgram(), kind, dev[0], dev[1], access)
				if (got == 0) != deny {
					t.Errorf("type=%d dev=%v access=%d result=%d", kind, dev, access, got)
				}
			}
		}
	}
}

type fakeDevicePolicy struct {
	t                *testing.T
	queries          int
	failure          string
	loaded, attached bool
	file             *os.File
}

func (f *fakeDevicePolicy) Query(effective bool) (devicePolicySet, error) {
	f.queries++
	if f.failure == "query" || (f.failure == "post-query" && f.attached) {
		return devicePolicySet{}, errors.New("query failed")
	}
	s := devicePolicySet{IDs: []uint32{10}, Flags: unix.BPF_F_ALLOW_MULTI}
	if effective {
		s.IDs = append(s.IDs, 20)
		s.Flags = 0
	}
	if f.failure == "flags" && !effective {
		s.Flags = unix.BPF_F_ALLOW_OVERRIDE
	}
	if f.failure == "duplicate" {
		s.IDs = append(s.IDs, 10)
	}
	if f.attached {
		s.IDs = append(s.IDs, 30)
		if f.failure == "removed" {
			s.IDs = s.IDs[1:]
		}
		if f.failure == "extra" {
			s.IDs = append(s.IDs, 40)
		}
	}
	return s, nil
}
func (f *fakeDevicePolicy) Load() (*os.File, uint32, error) {
	f.loaded = true
	if f.failure == "load" {
		return nil, 0, errors.New("load failed")
	}
	p, e := os.CreateTemp(f.t.TempDir(), "program-fd")
	f.file = p
	return p, 30, e
}
func (f *fakeDevicePolicy) Attach(*os.File) error {
	f.attached = true
	if f.failure == "attach" {
		return errors.New("unknown attach outcome")
	}
	return nil
}
func TestDevicePolicyRequiresAdditiveComposition(t *testing.T) {
	good := &fakeDevicePolicy{t: t}
	fd, id, e := sealDevicePolicy(good)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	if id != 30 || !good.attached || good.queries != 4 {
		t.Fatal("missing exact proof")
	}
	for _, kind := range []string{"query", "flags", "duplicate", "load", "attach", "removed", "extra", "post-query"} {
		t.Run(kind, func(t *testing.T) {
			f := &fakeDevicePolicy{t: t, failure: kind}
			fd, _, e := sealDevicePolicy(f)
			if e == nil || fd != nil {
				t.Fatal("unsafe policy authorized worker")
			}
			if (kind == "query" || kind == "flags" || kind == "duplicate") && f.loaded {
				t.Fatal("loaded before original policy authenticated")
			}
			if f.file != nil {
				if _, e := f.file.Stat(); e == nil {
					t.Fatal("original program FD leaked on failure")
				}
			}
		})
	}
}

func TestDevicePolicyFixedABIAndDigest(t *testing.T) {
	if unsafe.Sizeof(deviceInstruction{}) != 8 || unsafe.Sizeof(bpfLoadAttr{}) != 72 || unsafe.Offsetof(bpfLoadAttr{}.ExpectedAttach) != 68 || unsafe.Sizeof(bpfAttachAttr{}) != 32 || unsafe.Sizeof(bpfQueryAttr{}) != 64 || unsafe.Offsetof(bpfQueryAttr{}.IDs) != 16 || unsafe.Offsetof(bpfQueryAttr{}.Revision) != 56 || unsafe.Sizeof(bpfInfoAttr{}) != 16 {
		t.Fatal("Linux amd64 BPF ABI differs")
	}
	if len(fixedDeviceProgram()) != 14 || devicePolicySHA() != "bd958d0d3ab7193f91cb14013f9ce53ddd88c46ab6cba89337b7e4eeb6e74404" {
		t.Fatal("compiled policy bytes changed without provenance update")
	}
}
func TestDevicePolicySingleACKClosedAndBounded(t *testing.T) {
	for _, raw := range []string{deviceACK, "", deviceACK + deviceACK, "OTHER\n", deviceACK + "x"} {
		input := &closingReader{Reader: strings.NewReader(raw)}
		e := awaitDeviceACK(input, time.Second)
		if (e == nil) != (raw == deviceACK) || !input.closed {
			t.Fatalf("ACK %q error=%v closed=%v", raw, e, input.closed)
		}
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if e = awaitDeviceACK(r, 5*time.Millisecond); e == nil {
		t.Fatal("missing ACK deadline")
	}
	if _, e = r.Stat(); e == nil {
		t.Fatal("timeout left control input open")
	}
}

type closingReader struct {
	io.Reader
	closed bool
}

func (c *closingReader) Close() error { c.closed = true; return nil }
