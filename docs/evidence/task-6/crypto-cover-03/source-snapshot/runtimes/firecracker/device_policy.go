package firecracker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"unsafe"
)

const devicePolicyVersion = "warden-tun-deny-v1"

type deviceInstruction struct {
	Code, Registers uint8
	Offset          int16
	Immediate       int32
}

// Linux bpf_cgroup_dev_ctx: access<<16|type at0, major at4, minor at8.
// Fourteen amd64 eBPF instructions, no helpers/maps/loops/caller input.
func fixedDeviceProgram() []deviceInstruction {
	return []deviceInstruction{
		{0x61, 0x12, 0, 0}, {0x54, 2, 0, 0xffff}, {0x55, 2, 9, unix.BPF_DEVCG_DEV_CHAR},
		{0x61, 0x12, 4, 0}, {0x55, 2, 7, 10}, {0x61, 0x12, 8, 0}, {0x55, 2, 5, 200},
		{0x61, 0x12, 0, 0}, {0x54, 2, 0, (unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE) << 16}, {0x15, 2, 2, 0},
		{0xb7, 0, 0, 0}, {0x95, 0, 0, 0}, {0xb7, 0, 0, 1}, {0x95, 0, 0, 0},
	}
}
func devicePolicySHA() string {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, fixedDeviceProgram())
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

type devicePolicySet struct {
	IDs   []uint32
	Flags uint32
}
type devicePolicyCalls interface {
	Query(bool) (devicePolicySet, error)
	Load() (*os.File, uint32, error)
	Attach(*os.File) error
}

func policyIDs(s devicePolicySet, effective bool) (map[uint32]bool, error) {
	want := uint32(unix.BPF_F_ALLOW_MULTI)
	if effective {
		want = 0
	}
	if s.Flags != want || len(s.IDs) == 0 || len(s.IDs) > 64 {
		return nil, errors.New("unknown device policy flags/count")
	}
	ids := map[uint32]bool{}
	for _, id := range s.IDs {
		if id == 0 || ids[id] {
			return nil, errors.New("invalid device program ID")
		}
		ids[id] = true
	}
	return ids, nil
}
func additivePolicy(before, after devicePolicySet, id uint32, effective bool) error {
	a, e := policyIDs(before, effective)
	if e != nil {
		return e
	}
	b, e := policyIDs(after, effective)
	if e != nil {
		return e
	}
	if id == 0 || a[id] || !b[id] || len(b) != len(a)+1 {
		return errors.New("policy composition not exactly additive")
	}
	for old := range a {
		if !b[old] {
			return errors.New("original device policy disappeared")
		}
	}
	return nil
}
func sealDevicePolicy(ops devicePolicyCalls) (program *os.File, id uint32, err error) {
	direct, err := ops.Query(false)
	if err != nil {
		return nil, 0, err
	}
	d, err := policyIDs(direct, false)
	if err != nil {
		return nil, 0, err
	}
	effective, err := ops.Query(true)
	if err != nil {
		return nil, 0, err
	}
	e, err := policyIDs(effective, true)
	if err != nil {
		return nil, 0, err
	}
	if len(e) >= 64 {
		return nil, 0, errors.New("device policy query ceiling")
	}
	for id := range d {
		if !e[id] {
			return nil, 0, errors.New("direct policy missing from effective set")
		}
	}
	program, id, err = ops.Load()
	if err != nil {
		return nil, 0, err
	}
	success := false
	defer func() {
		if !success && program != nil {
			program.Close()
			program = nil
		}
	}()
	if program == nil || id == 0 || e[id] {
		return program, 0, errors.New("new policy identity invalid")
	}
	if err = ops.Attach(program); err != nil {
		return program, 0, err
	} // Never retry or detach an uncertain attachment.
	after, err := ops.Query(false)
	if err != nil {
		return program, 0, err
	}
	if err = additivePolicy(direct, after, id, false); err != nil {
		return program, 0, err
	}
	after, err = ops.Query(true)
	if err != nil {
		return program, 0, err
	}
	if err = additivePolicy(effective, after, id, true); err != nil {
		return program, 0, err
	}
	success = true
	return program, id, nil
}

// Fixed Linux UAPI prefixes. Tests assert size/offsets. No detach/link/pin or
// arbitrary program/target API exists. The cgroup retains the raw attachment.
type bpfLoadAttr struct {
	Type, Count             uint32
	Instructions, License   uint64
	LogLevel, LogSize       uint32
	LogBuffer               uint64
	KernelVersion, Flags    uint32
	Name                    [16]byte
	Ifindex, ExpectedAttach uint32
}
type bpfAttachAttr struct {
	Target, Program, Type, Flags, Replace, Relative uint32
	Revision                                        uint64
}
type bpfQueryAttr struct {
	Target, Type, QueryFlags, Flags            uint32
	IDs                                        uint64
	Count, Padding                             uint32
	ProgramFlags, LinkIDs, LinkFlags, Revision uint64
}
type bpfInfoAttr struct {
	FD, Length uint32
	Info       uint64
}
type kernelDevicePolicy struct {
	target *os.File
	check  func() error
}

func bpfCall(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r, _, e := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	if e != 0 {
		return 0, e
	}
	return r, nil
}
func (k kernelDevicePolicy) Query(effective bool) (devicePolicySet, error) {
	if e := k.check(); e != nil {
		return devicePolicySet{}, e
	}
	var ids [64]uint32
	var pinned runtime.Pinner
	pinned.Pin(&ids[0])
	defer pinned.Unpin()
	attr := bpfQueryAttr{Target: uint32(k.target.Fd()), Type: unix.BPF_CGROUP_DEVICE, IDs: uint64(uintptr(unsafe.Pointer(&ids[0]))), Count: 64}
	if effective {
		attr.QueryFlags = unix.BPF_F_QUERY_EFFECTIVE
	}
	_, e := bpfCall(unix.BPF_PROG_QUERY, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(ids)
	runtime.KeepAlive(k.target)
	if e != nil {
		return devicePolicySet{}, e
	}
	if attr.Count > 64 {
		return devicePolicySet{}, errors.New("device query overflow")
	}
	result := devicePolicySet{IDs: append([]uint32(nil), ids[:attr.Count]...), Flags: attr.Flags}
	raw, _ := json.Marshal(map[string]any{"device_policy_query_effective": effective, "flags": result.Flags, "ids": result.IDs})
	fmt.Println(string(raw))
	return result, nil
}
func (k kernelDevicePolicy) Load() (*os.File, uint32, error) {
	if e := k.check(); e != nil {
		return nil, 0, e
	}
	program := fixedDeviceProgram()
	license := []byte("GPL\x00")
	var log [4096]byte
	var pinned runtime.Pinner
	pinned.Pin(&program[0])
	pinned.Pin(&license[0])
	pinned.Pin(&log[0])
	defer pinned.Unpin()
	attr := bpfLoadAttr{Type: unix.BPF_PROG_TYPE_CGROUP_DEVICE, Count: uint32(len(program)), Instructions: uint64(uintptr(unsafe.Pointer(&program[0]))), License: uint64(uintptr(unsafe.Pointer(&license[0]))), LogLevel: 1, LogSize: uint32(len(log)), LogBuffer: uint64(uintptr(unsafe.Pointer(&log[0]))), ExpectedAttach: unix.BPF_CGROUP_DEVICE}
	copy(attr.Name[:], "warden_tun_deny")
	fd, e := bpfCall(unix.BPF_PROG_LOAD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(program)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if e != nil {
		return nil, 0, fmt.Errorf("device policy load: %w; verifier=%q", e, bytes.TrimRight(log[:], "\x00"))
	}
	file := os.NewFile(fd, "owned-device-policy")
	flags, e := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		file.Close()
		return nil, 0, errors.New("program FD must be CLOEXEC")
	}
	var info [16]byte
	pinned.Pin(&info[0])
	query := bpfInfoAttr{FD: uint32(fd), Length: uint32(len(info)), Info: uint64(uintptr(unsafe.Pointer(&info[0])))}
	_, e = bpfCall(unix.BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(info)
	if e != nil || query.Length < 8 || binary.LittleEndian.Uint32(info[:4]) != unix.BPF_PROG_TYPE_CGROUP_DEVICE {
		file.Close()
		return nil, 0, errors.New("device program info mismatch")
	}
	return file, binary.LittleEndian.Uint32(info[4:8]), nil
}
func (k kernelDevicePolicy) Attach(program *os.File) error {
	if e := k.check(); e != nil {
		return e
	}
	attr := bpfAttachAttr{Target: uint32(k.target.Fd()), Program: uint32(program.Fd()), Type: unix.BPF_CGROUP_DEVICE, Flags: unix.BPF_F_ALLOW_MULTI}
	_, e := bpfCall(unix.BPF_PROG_ATTACH, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(program)
	runtime.KeepAlive(k.target)
	return e
}
