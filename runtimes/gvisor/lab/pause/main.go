// Command pause is the pod sandbox process for the Task 3 k3s lab. In a gVisor
// pod it is the first process of the sandbox; it only waits for SIGTERM/SIGINT.
// The lab builds its own because the node cannot reach a registry.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c
}
