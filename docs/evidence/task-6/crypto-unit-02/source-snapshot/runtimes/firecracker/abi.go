package firecracker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// ABISmoke runs only official --version commands in the capless, device-free
// immutable image. It is intentionally not VM, guest, or jailer execution proof.
func ABISmoke() error {
	if os.Geteuid() != 65534 || os.Getenv("WARDEN_FC_REVIEWED") != "" {
		return errors.New("capless ABI profile required")
	}
	for _, name := range []string{"firecracker", "jailer"} {
		raw, e := exec.Command(inputPath+"/"+name, "--version").CombinedOutput()
		if e != nil {
			return e
		}
		if len(raw) > 4096 || !bytes.Contains(raw, []byte("v1.17.0")) {
			return errors.New("official binary ABI/version mismatch")
		}
		fmt.Printf("%s", raw)
	}
	fmt.Println("capless official binary ABI only; VM NOT EXECUTED")
	return nil
}
