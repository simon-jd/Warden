package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Workload is the cgroup the payload runs in, below the in-sandbox root.
const Workload = "workload"

// prepare moves every process of the sandbox root cgroup into "init" (cgroup
// v2 refuses to enable controllers for children of a cgroup that still has
// processes), enables the pids controller and creates the workload cgroup
// with pids.max. It returns the workload directory.
func prepare(root *os.Root, pids int) (*os.Root, error) {
	if err := root.Mkdir("init", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	procs, err := readFile(root, "cgroup.procs")
	if err != nil {
		return nil, err
	}
	for _, pid := range strings.Fields(procs) {
		// A PID can exit between the read and the write; that is fine.
		if err := writeFile(root, "init/cgroup.procs", pid); err != nil && !isNoProcess(err) {
			return nil, fmt.Errorf("move %s to init: %w", pid, err)
		}
	}
	if err := writeFile(root, "cgroup.subtree_control", "+pids"); err != nil {
		return nil, fmt.Errorf("enable pids controller: %w", err)
	}
	if err := root.Mkdir(Workload, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	w, err := root.OpenRoot(Workload)
	if err != nil {
		return nil, err
	}
	if err := writeFile(w, "pids.max", strconv.Itoa(pids)); err != nil {
		w.Close()
		return nil, fmt.Errorf("pids.max: %w", err)
	}
	return w, nil
}

// kill SIGKILLs every process in the workload cgroup and its descendants.
func kill(w *os.Root) error { return writeFile(w, "cgroup.kill", "1") }

func populated(w *os.Root) (bool, error) {
	raw, err := readFile(w, "cgroup.events")
	if err != nil {
		return false, err
	}
	n, err := counter(raw, "populated")
	return n != 0, err
}

// collect copies the pids controller's counters into r.
func collect(w *os.Root, r *Report) error {
	raw, err := readFile(w, "pids.events")
	if err != nil {
		return err
	}
	if r.PidsMaxEvents, err = counter(raw, "max"); err != nil {
		return err
	}
	raw, err = readFile(w, "pids.peak")
	if err != nil {
		return err
	}
	r.PeakPids, err = strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	return err
}

// counter returns the value of key in a flat-keyed cgroup file.
func counter(raw, key string) (uint64, error) {
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			return strconv.ParseUint(f[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("no %q in cgroup file", key)
}

func readFile(r *os.Root, name string) (string, error) {
	f, err := r.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	return string(b), err
}

func writeFile(r *os.Root, name, value string) error {
	f, err := r.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	return errors.Join(err, f.Close())
}
