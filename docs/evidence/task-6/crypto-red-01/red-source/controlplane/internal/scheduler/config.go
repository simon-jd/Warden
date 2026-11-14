package scheduler

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"time"

	"warden/controlplane/internal/runs"
	"warden/runtimes/gate"
	"warden/runtimes/runc"
)

// Config is trusted operator input. No field is accepted from an API request.
// The gate directory and its node identity must survive daemon/worker restarts.
type Config struct {
	Node              string                  `json:"node"`
	GateDir           string                  `json:"gate_dir"`
	Concurrency       int                     `json:"concurrency"`
	PollMS            int                     `json:"poll_ms"`
	OperationTimeoutS int                     `json:"operation_timeout_s"`
	Drivers           map[string]DriverConfig `json:"drivers"`
}
type DriverConfig struct {
	Socket            string            `json:"socket"`
	ExpectedDaemonPID int               `json:"expected_daemon_pid"`
	TrustedOwnerUID   int               `json:"trusted_owner_uid"`
	CgroupRoot        string            `json:"cgroup_root"`
	Images            map[string]string `json:"images"`
}

func ParseConfig(reader io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(io.LimitReader(reader, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid scheduler configuration")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("unexpected scheduler configuration data")
	}
	if c.Concurrency == 0 {
		c.Concurrency = 2
	}
	if c.PollMS == 0 {
		c.PollMS = 250
	}
	if c.OperationTimeoutS == 0 {
		c.OperationTimeoutS = 30
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(c.Node) || !filepath.IsAbs(c.GateDir) || filepath.Clean(c.GateDir) != c.GateDir || len(c.Drivers) == 0 || c.Concurrency < 1 || c.Concurrency > 32 || c.PollMS < 10 || c.PollMS > 60000 || c.OperationTimeoutS < 1 || c.OperationTimeoutS > 60 {
		return c, errors.New("invalid scheduler bounds or node configuration")
	}
	for name, driver := range c.Drivers {
		// Additional runtime backends must be implemented and explicitly registered.
		if name != "runc" {
			return c, errors.New("configured runtime unavailable")
		}
		if !filepath.IsAbs(driver.Socket) || driver.ExpectedDaemonPID <= 0 || driver.TrustedOwnerUID < 0 || driver.CgroupRoot != "/sys/fs/cgroup/warden-lab" {
			return c, errors.New("trusted dedicated runtime configuration required")
		}
	}
	return c, nil
}
func (c Config) Scheduler(s *runs.Store) (*Scheduler, error) {
	drivers := map[string]*gate.Gate{}
	for name, cfg := range c.Drivers {
		if name != "runc" {
			return nil, errors.New("configured runtime unavailable")
		}
		d, err := runc.New(runc.Config{Socket: cfg.Socket, ExpectedDaemonPID: cfg.ExpectedDaemonPID, TrustedOwnerUID: cfg.TrustedOwnerUID, CgroupRoot: cfg.CgroupRoot, Images: cfg.Images})
		if err != nil {
			return nil, errors.New("dedicated runtime validation failed")
		}
		guarded, err := gate.New(c.GateDir, c.Node, d)
		if err != nil {
			return nil, errors.New("durable runtime gate validation failed")
		}
		drivers[name] = guarded
	}
	worker := &Scheduler{Store: s, Drivers: drivers, Node: c.Node, Concurrency: c.Concurrency, PollInterval: time.Duration(c.PollMS) * time.Millisecond, OperationTimeout: time.Duration(c.OperationTimeoutS) * time.Second}
	if err := worker.validate(); err != nil {
		return nil, err
	}
	return worker, nil
}
