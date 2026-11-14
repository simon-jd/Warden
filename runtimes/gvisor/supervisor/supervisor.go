// Package supervisor is warden-gvisor-init, the first process of every
// gVisor run. It is root only inside the gVisor sandbox (the sentry), never
// on the node. Kubernetes cannot give a container its own pids limit and
// runsc does not copy OCI limits into its in-sandbox cgroups, so the
// supervisor does what the Firecracker guest agent does inside its VM: put
// the payload in a cgroup with pids.max, drop to UID/GID 65534 with no
// capabilities and the same seccomp policy runc gets, enforce the timeout
// with cgroup.kill, and report what happened through the container's
// termination message. Memory and CPU are not set here: gVisor does not
// enforce memory.max inside the sandbox, so the pod limits (which runsc
// gives the sentry as its total memory and CPU quota) are the bound.
package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// MaxReportBytes is the kubelet's limit for a termination message.
	MaxReportBytes = 4096
	// TerminationLog is where the report goes (the Kubernetes default path).
	TerminationLog = "/dev/termination-log"
	// MarkerEnv must be "1" in the supervisor's environment; the driver sets it.
	MarkerEnv = "WARDEN_GVISOR_INIT"
	// PayloadUID is the UID and GID the payload runs as, as with runc and Firecracker.
	PayloadUID = 65534
	maxPids    = 4194304
	maxTimeout = 86400
)

// Config is what the supervisor needs from the run spec.
type Config struct {
	Pids, TimeoutS int
	Cmd            []string
}

// Args encodes c as the supervisor's command-line arguments.
func Args(c Config) []string {
	return append([]string{"-pids", strconv.Itoa(c.Pids), "-timeout-s", strconv.Itoa(c.TimeoutS), "--"}, c.Cmd...)
}

// Parse is the inverse of Args and rejects anything Args cannot produce.
func Parse(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("warden-gvisor-init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&c.Pids, "pids", 0, "")
	fs.IntVar(&c.TimeoutS, "timeout-s", 0, "")
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return Config{}, errors.New("missing -- before the payload command")
	}
	if err := fs.Parse(args[:sep]); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	c.Cmd = append([]string(nil), args[sep+1:]...)
	switch {
	case c.Pids < 1 || c.Pids > maxPids:
		return Config{}, fmt.Errorf("pids %d out of range", c.Pids)
	case c.TimeoutS < 1 || c.TimeoutS > maxTimeout:
		return Config{}, fmt.Errorf("timeout %d s out of range", c.TimeoutS)
	case len(c.Cmd) == 0 || !strings.HasPrefix(c.Cmd[0], "/"):
		return Config{}, errors.New("payload command must start with an absolute path")
	}
	for _, a := range c.Cmd {
		if strings.IndexByte(a, 0) >= 0 {
			return Config{}, errors.New("NUL byte in payload command")
		}
	}
	return c, nil
}

// signalled starts Report.Error when the supervisor stopped the payload
// because it got SIGTERM or SIGINT, as kubelet sends when the pod is deleted.
const signalled = "supervisor got "

// Signalled reports whether the supervisor stopped the payload because it
// got SIGTERM or SIGINT, and nothing failed after that.
func (r Report) Signalled() bool { return strings.HasPrefix(r.Error, signalled) }

// Report is the supervisor's result, written as JSON to the termination log.
// Times are CLOCK_REALTIME inside the sandbox, which gVisor derives from the
// host clock, in Unix nanoseconds.
type Report struct {
	Version       int    `json:"v"`
	Code          uint32 `json:"code"`
	TimedOut      bool   `json:"timed_out"`
	PidsMaxEvents uint64 `json:"pids_max_events"`
	PeakPids      uint64 `json:"peak_pids"`
	CgroupEmpty   bool   `json:"cgroup_empty"`
	// InitUnixNano is when the supervisor started; ExecUnixNano is when the
	// payload's execve succeeded (the close-on-exec status pipe closed).
	InitUnixNano int64  `json:"init_ns"`
	ExecUnixNano int64  `json:"exec_ns"`
	Error        string `json:"error,omitempty"`
}

// Encode returns the JSON form, cutting Error so it fits MaxReportBytes.
func (r Report) Encode() ([]byte, error) {
	for {
		b, err := json.Marshal(r)
		if err != nil || len(b) <= MaxReportBytes {
			return b, err
		}
		cut := len(r.Error) - (len(b) - MaxReportBytes) - 16
		if cut < 0 {
			cut = 0
		}
		r.Error = r.Error[:cut] + "...(cut)"
	}
}

// ParseReport accepts exactly one version-1 report and nothing else.
func ParseReport(raw []byte) (Report, error) {
	var r Report
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return r, fmt.Errorf("report of %d bytes", len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Report{}, err
	}
	if dec.More() {
		return Report{}, errors.New("trailing data after report")
	}
	if r.Version != 1 {
		return Report{}, fmt.Errorf("report version %d", r.Version)
	}
	return r, nil
}
