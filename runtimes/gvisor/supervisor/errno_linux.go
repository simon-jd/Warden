package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNoProcess(err error) bool { return errors.Is(err, unix.ESRCH) }
