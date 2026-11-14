package seccomp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxInstructions is the kernel's BPF_MAXINSNS for one classic program.
const maxInstructions = 4096

type profile struct {
	DefaultAction   string  `json:"defaultAction"`
	DefaultErrnoRet *uint32 `json:"defaultErrnoRet"`
	Syscalls        []rule  `json:"syscalls"`
}

type rule struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	ErrnoRet *uint32  `json:"errnoRet"`
	Args     []arg    `json:"args"`
}

type arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

// Compile turns a profile in the JSON shape of default.json (the one runc gets
// through the OCI spec) into a classic seccomp BPF program for x86_64. It is
// for runtimes that install the filter themselves, such as the gVisor
// supervisor. Only what default.json needs is accepted: deny by default,
// ALLOW/ERRNO rules, and SCMP_CMP_MASKED_EQ argument checks
// ((arg & value) == valueTwo, as in the OCI runtime spec). Anything else,
// unknown names and names listed twice are errors, so the compiled program
// can never be more permissive than the JSON. Other architectures and x32
// numbers are killed or denied.
func Compile(raw []byte) ([]unix.SockFilter, error) {
	var p profile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("seccomp profile: %w", err)
	}
	if dec.More() {
		return nil, errors.New("seccomp profile: trailing data")
	}
	if p.DefaultAction != "SCMP_ACT_ERRNO" {
		return nil, fmt.Errorf("seccomp profile: default action %q, only SCMP_ACT_ERRNO is supported", p.DefaultAction)
	}
	deny, err := action(p.DefaultAction, p.DefaultErrnoRet)
	if err != nil {
		return nil, err
	}
	prog := []unix.SockFilter{
		ldAbs(4), // seccomp_data.arch
		jeq(unix.AUDIT_ARCH_X86_64, 1, 0),
		retK(unix.SECCOMP_RET_KILL_PROCESS),
		ldAbs(0), // seccomp_data.nr
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jt: 0, Jf: 1}, // x32 ABI
		retK(deny),
	}
	seen := map[string]bool{}
	for _, r := range p.Syscalls {
		ret, err := action(r.Action, r.ErrnoRet)
		if err != nil {
			return nil, err
		}
		block, err := argBlock(r.Args, ret)
		if err != nil {
			return nil, err
		}
		for _, name := range r.Names {
			nr, ok := syscallNumbers[name]
			if !ok {
				return nil, fmt.Errorf("seccomp profile: unknown syscall %q", name)
			}
			if seen[name] {
				return nil, fmt.Errorf("seccomp profile: syscall %q listed twice", name)
			}
			seen[name] = true
			if len(block) > 255 {
				return nil, errors.New("seccomp profile: argument block too long")
			}
			prog = append(prog, jeq(uint32(nr), 0, uint8(len(block))))
			prog = append(prog, block...)
		}
	}
	prog = append(prog, retK(deny))
	if len(prog) > maxInstructions {
		return nil, fmt.Errorf("seccomp profile: %d instructions, kernel limit %d", len(prog), maxInstructions)
	}
	return prog, nil
}

// argBlock is what runs after the syscall number matched: the argument
// checks, the rule's return, and (if any check fails) a reload of the
// syscall number so evaluation continues with the next name.
func argBlock(args []arg, ret uint32) ([]unix.SockFilter, error) {
	if len(args) == 0 {
		return []unix.SockFilter{retK(ret)}, nil
	}
	var block []unix.SockFilter
	var fails []int
	for _, a := range args {
		if a.Op != "SCMP_CMP_MASKED_EQ" {
			return nil, fmt.Errorf("seccomp profile: unsupported argument op %q", a.Op)
		}
		if a.Index > 5 {
			return nil, fmt.Errorf("seccomp profile: argument index %d", a.Index)
		}
		off := uint32(16 + 8*a.Index) // seccomp_data.args[i], little endian
		for _, w := range []struct{ off, mask, want uint32 }{
			{off + 4, uint32(a.Value >> 32), uint32(a.ValueTwo >> 32)},
			{off, uint32(a.Value), uint32(a.ValueTwo)},
		} {
			block = append(block, ldAbs(w.off), unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: w.mask})
			fails = append(fails, len(block))
			block = append(block, jeq(w.want, 0, 0))
		}
	}
	block = append(block, retK(ret))
	reload := len(block)
	block = append(block, ldAbs(0))
	for _, i := range fails {
		block[i].Jf = uint8(reload - i - 1)
	}
	return block, nil
}

func action(name string, errno *uint32) (uint32, error) {
	switch name {
	case "SCMP_ACT_ALLOW":
		if errno != nil {
			return 0, errors.New("seccomp profile: errnoRet on an ALLOW rule")
		}
		return unix.SECCOMP_RET_ALLOW, nil
	case "SCMP_ACT_ERRNO":
		n := uint32(unix.EPERM)
		if errno != nil {
			n = *errno
		}
		if n == 0 || n > 4095 {
			return 0, fmt.Errorf("seccomp profile: errno %d out of range", n)
		}
		return unix.SECCOMP_RET_ERRNO | n, nil
	}
	return 0, fmt.Errorf("seccomp profile: unsupported action %q", name)
}

func ldAbs(off uint32) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off}
}
func retK(k uint32) unix.SockFilter { return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: k} }
func jeq(k uint32, t, f uint8) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: k, Jt: t, Jf: f}
}

// Install sets no_new_privs and loads prog on every thread of the process
// (TSYNC). It is irreversible for the process and everything it executes.
func Install(prog []unix.SockFilter) error {
	if len(prog) == 0 || len(prog) > maxInstructions {
		return errors.New("seccomp: invalid program length")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	n, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if e != 0 {
		return e
	}
	if n != 0 {
		return fmt.Errorf("seccomp: thread %d could not be synchronized", n)
	}
	return nil
}
