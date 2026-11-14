// Package runtimes defines the common sandbox execution contract.
package runtimes

import (
	"context"
	"io"
)

type Limits struct {
	CPU                       float64
	MemoryMiB, Pids, TimeoutS int
}
type Spec struct {
	RunID, ImageDigest string
	Cmd                []string
	Limits             Limits
	Network            string
	AllowDomains       []string
}
type Exit struct {
	Code                             uint32
	LogsTruncated                    bool
	PidsMaxEvents, PeakPids          uint64
	DroppedLogBytes                  uint64
	OOMKilled, TimedOut, CgroupEmpty bool
}
type Runtime interface {
	Start(context.Context, Spec) (Handle, error)
}
type Handle interface {
	Wait(context.Context) (Exit, error)
	Kill() error
	Logs() io.ReadCloser
}
