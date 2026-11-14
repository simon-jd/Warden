package main

import (
	"fmt"
	"os"
	"warden/runtimes/firecracker/guest"
)

func main() {
	var err error
	if len(os.Args) == 3 && os.Args[1] == "payload" {
		err = guest.Payload(os.Args[2])
	} else if len(os.Args) == 1 {
		err = guest.Boot()
	} else {
		err = fmt.Errorf("fixed guest init entrypoint required")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest agent failed:", err)
		os.Exit(1)
	}
}
