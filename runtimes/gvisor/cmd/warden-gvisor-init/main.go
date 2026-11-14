// Command warden-gvisor-init is the supervisor at PID 1 of every gVisor run
// (see package supervisor). The lab node serves it read-only to the pod.
package main

import (
	"os"

	"warden/runtimes/gvisor/supervisor"
)

func main() { os.Exit(supervisor.Main(os.Args)) }
