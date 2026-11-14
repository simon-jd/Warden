package main

import (
	"fmt"
	"os"
	"syscall"
	fc "warden/runtimes/firecracker"
)

func main() {
	syscall.Umask(0077)
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "fixed reviewed mode required")
		os.Exit(2)
	}
	run := func() error {
		if os.Args[1] == "mount-smoke" {
			return fc.MountSmoke()
		}
		if os.Args[1] == "abi" {
			return fc.ABISmoke()
		}
		return fc.Supervise(os.Args[1])
	}
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
