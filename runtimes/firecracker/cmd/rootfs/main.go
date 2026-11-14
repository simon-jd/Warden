package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	fc "warden/runtimes/firecracker"
)

const base = "/workspace/.cache/firecracker-code"

func run() error {
	if os.Geteuid() != 1000 || len(os.Args) != 1 {
		return errors.New("fixed capless image builder required")
	}
	work := base + "/rootfs-staging"
	if e := os.Mkdir(work, 0700); e != nil {
		return e
	}
	for _, name := range []string{"agent", "payload"} {
		if e := os.Mkdir(work+"/"+name, 0700); e != nil {
			return e
		}
	}
	export, e := os.Open(base + "/export.tar")
	if e != nil {
		return e
	}
	provenance, e := fc.ExtractRootFS(export, work+"/payload")
	export.Close()
	if e != nil {
		return e
	}
	for _, name := range []string{"proc", "sys", "sys/fs", "sys/fs/cgroup", "dev", "run", "tmp", "payload"} {
		if e := os.MkdirAll(work+"/agent/"+name, 0755); e != nil {
			return e
		}
		if e := os.Chmod(work+"/agent/"+name, 0755); e != nil {
			return e
		}
	}
	raw, e := os.ReadFile(base + "/agent")
	if e != nil || len(raw) > 16<<20 {
		return errors.New("agent binary missing or oversized")
	}
	if e = os.WriteFile(work+"/agent/agent", raw, 0555); e != nil {
		return e
	}
	if e = os.Chmod(work+"/agent/agent", 0555); e != nil {
		return e
	}
	for _, name := range []string{"agent", "payload"} {
		if e = fc.BuildExt4(work+"/"+name, base+"/"+name+".ext4"); e != nil {
			return e
		}
	}
	hashes := map[string]string{}
	for _, path := range []string{base + "/agent.ext4", base + "/payload.ext4", "/sbin/mke2fs", "/sbin/debugfs"} {
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil {
			return e
		}
		hashes[filepath.Base(path)] = hex.EncodeToString(h.Sum(nil))
	}
	output, e := os.OpenFile(base+"/rootfs.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = json.NewEncoder(output).Encode(struct {
		Export fc.Export
		Hashes map[string]string
	}{provenance, hashes})
	return errors.Join(e, output.Sync(), output.Close())
}
func main() {
	syscall.Umask(0077)
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
