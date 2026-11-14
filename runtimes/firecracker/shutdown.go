package firecracker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
)

// retirementRuns runs after both admission paths are closed and registered
// starts finish. Gate.Reap subsequently waits on each admitted callback's lock.
// Durable records, never the handle map alone, determine the work to retire.
func (d *Driver) retirementRuns() (map[string]bool, []error) {
	ids := map[string]bool{}
	var failures []error
	d.mu.Lock()
	handles := make(map[string]*vm, len(d.handles))
	for id, h := range d.handles {
		handles[id] = h
		ids[id] = true
	}
	d.mu.Unlock()
	for _, dir := range []string{"gate", "runs", "uids"} {
		directory, e := d.root.OpenRoot(dir)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		f, e := directory.Open(".")
		if e != nil {
			directory.Close()
			failures = append(failures, e)
			continue
		}
		entries, e := f.ReadDir(-1)
		f.Close()
		directory.Close()
		if e != nil {
			failures = append(failures, e)
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !runPattern.MatchString(name) {
				allowed := dir == "gate" && (name == "node" || name == "admission" || name == "retirement" || name == "admission-sealed") || dir == "uids" && (name == "state" || name == "lock")
				if !allowed {
					failures = append(failures, fmt.Errorf("unknown %s journal entry", dir))
					continue
				}
			} else {
				ids[name] = true
			}
			file, e := checkedFile(d.root, dir+"/"+name, os.O_RDONLY|unix.O_NONBLOCK)
			if e != nil {
				failures = append(failures, e)
				continue
			}
			raw, e := io.ReadAll(io.LimitReader(file, 8193))
			file.Close()
			if e != nil || len(raw) > 8192 {
				failures = append(failures, errors.New("unreadable or oversized retirement journal"))
				continue
			}
			if !runPattern.MatchString(name) {
				if (name == "admission" || name == "retirement" || name == "lock") && len(raw) != 0 {
					failures = append(failures, errors.New("unexpected journal control state"))
				}
				if name == "node" {
					prefix := d.gate.Authority() + "\nbackend-v1:"
					binding, err := hex.DecodeString(strings.TrimPrefix(string(raw), prefix))
					if !strings.HasPrefix(string(raw), prefix) || err != nil || len(binding) != 32 {
						failures = append(failures, errors.New("gate authority or binding corrupt"))
					}
				}
				continue
			}
			h := handles[name]
			if h == nil {
				// Even started/revoked cannot restore the missing original Popen owner.
				// Empty gate files precede creation; ambiguous markers are also preserved
				// by Gate.Reap, which returns its explicit ErrAmbiguous below.
				if dir != "gate" || len(raw) > 0 {
					failures = append(failures, ErrCleanupPending)
				}
				continue
			}
			switch dir {
			case "runs":
				expected, _ := json.Marshal(struct {
					Authority string
					UID       uint32
					Profile   Profile
				}{d.gate.Authority(), h.uid, h.profile})
				if !bytes.Equal(raw, append(expected, '\n')) {
					failures = append(failures, errors.New("run journal differs from original owner"))
				}
			case "uids":
				if string(raw) != fmt.Sprintf("%s\n%d\n", d.gate.Authority(), h.uid) {
					failures = append(failures, errors.New("UID journal differs from original owner"))
				}
			}
		}
	}
	for id := range handles {
		for _, dir := range []string{"runs", "uids"} {
			if _, e := d.root.Lstat(dir + "/" + id); e != nil {
				failures = append(failures, e)
			}
		}
	}
	if d.allocator == nil {
		failures = append(failures, ErrCleanupPending)
	} else if len(failures) == 0 {
		if _, e := d.allocator.read(); e != nil {
			failures = append(failures, e)
		}
	}
	return ids, failures
}
