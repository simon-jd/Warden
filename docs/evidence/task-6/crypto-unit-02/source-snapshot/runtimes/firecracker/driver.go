package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"warden/runtimes"
	"warden/runtimes/gate"
)

var ErrCleanupPending = errors.New("original owner or complete retirement unavailable: cleanup_pending")

type Manifest struct {
	DevicePolicyVersion, DevicePolicySHA                              string
	Version                                                           int
	SourceSHA, ImageDigest, ExportSHA, AgentSHA, PolicySHA            string
	NormalizedExportSHA, NormalizationVersion, NormalizationPolicySHA string
	Artifacts                                                         map[string]string
}
type startOptions struct {
	benchmark bool
	restore   string
}
type Driver struct {
	mu                   sync.Mutex
	closeMu              sync.Mutex
	snapshotMu           sync.Mutex
	options              map[string]startOptions
	wg                   sync.WaitGroup
	root, cgroups, input *os.Root
	allocator            *Allocator
	gate                 *gate.Gate
	manifest             Manifest
	handles              map[string]*vm
	closed               bool
	limit                int
}

// Open is a fixed lab entrypoint, never an API registration hook. Only the
// reviewed root supervisor's worker in its sealed private node can open it.
func Open() (*Driver, *gate.Gate, error) {
	if os.Geteuid() != 0 || os.Getenv("WARDEN_FC_REVIEWED") != "controller-reviewed" {
		return nil, nil, errors.New("reviewed owned Firecracker node required")
	}
	membership, e := os.ReadFile("/proc/self/cgroup")
	if e != nil || strings.TrimSpace(string(membership)) != "0::/warden-lab/service" {
		return nil, nil, errors.New("worker is outside fixed private node")
	}
	hostNS := os.Getenv("WARDEN_FC_HOST_CGROUP_NS")
	actualNS, e := os.Readlink("/proc/self/ns/cgroup")
	if e != nil || !regexp.MustCompile(`^cgroup:\[[0-9]+\]$`).MatchString(hostNS) || hostNS == actualNS {
		return nil, nil, errors.New("private cgroup namespace required")
	}
	input, e := os.OpenRoot(inputPath)
	if e != nil {
		return nil, nil, e
	}
	f, e := input.OpenFile("manifest.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		input.Close()
		return nil, nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0222 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 {
		f.Close()
		input.Close()
		return nil, nil, errors.New("immutable root-owned input manifest required")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	var manifest Manifest
	if e != nil || len(raw) > 65536 {
		input.Close()
		return nil, nil, errors.New("manifest read failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&manifest); e != nil {
		input.Close()
		return nil, nil, e
	}
	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if manifest.Version != 1 || manifest.DevicePolicyVersion != devicePolicyVersion || manifest.DevicePolicySHA != devicePolicySHA() || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(manifest.SourceSHA) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(manifest.ImageDigest) || !sha.MatchString(manifest.ExportSHA) || !sha.MatchString(manifest.NormalizedExportSHA) || manifest.NormalizationVersion != NormalizationVersion || manifest.NormalizationPolicySHA != NormalizationPolicySHA() || !sha.MatchString(manifest.AgentSHA) || !sha.MatchString(manifest.PolicySHA) || len(manifest.Artifacts) != 5 || manifest.Artifacts["kernel"] != "da5e0041fb31fcc7337026da9e2b64fb7694b4eed760cc9b5e8fe54e52fa8188" {
		input.Close()
		return nil, nil, errors.New("unreviewed immutable provenance")
	}
	for name, limit := range map[string]int64{"kernel": 32 << 20, "firecracker": 32 << 20, "jailer": 8 << 20, "agent.ext4": 64 << 20, "payload.ext4": 64 << 20} {
		f, e := verifiedArtifact(input, name, manifest.Artifacts[name], limit)
		if e != nil {
			input.Close()
			return nil, nil, e
		}
		f.Close()
	}
	session, e := privateRoot(sessionPath)
	if e != nil {
		input.Close()
		return nil, nil, e
	}
	defer session.Close()
	if e = session.Mkdir("node", 0700); e != nil {
		input.Close()
		return nil, nil, errors.Join(ErrCleanupPending, e)
	}
	root, e := session.OpenRoot("node")
	if e != nil {
		input.Close()
		return nil, nil, e
	}
	d := &Driver{root: root, input: input, manifest: manifest, handles: map[string]*vm{}, options: map[string]startOptions{}, limit: 1}
	success := false
	defer func() {
		if !success {
			if d.cgroups != nil {
				d.cgroups.Close()
			}
			if d.allocator != nil {
				d.allocator.Close()
			}
			root.Close()
			input.Close()
		}
	}()
	for _, name := range []string{"gate", "uids", "runs", "assets", "snapshots"} {
		if e = root.Mkdir(name, 0700); e != nil {
			return nil, nil, e
		}
	}
	if e = session.Mkdir("jails", 0700); e != nil {
		return nil, nil, e
	}
	owner, e := checkedFile(root, "owner", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return nil, nil, e
	}
	_, e = fmt.Fprintf(owner, "pid=%d\nsource=%s\n", os.Getpid(), manifest.SourceSHA)
	e = errors.Join(e, owner.Sync(), owner.Close(), syncRoot(root))
	if e != nil {
		return nil, nil, e
	}
	d.cgroups, e = os.OpenRoot("/sys/fs/cgroup/warden-lab/vms")
	if e != nil {
		return nil, nil, e
	}
	cg, e := d.cgroups.Open(".")
	if e != nil {
		return nil, nil, e
	}
	var fs unix.Statfs_t
	e = unix.Fstatfs(int(cg.Fd()), &fs)
	cg.Close()
	if e != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, nil, errors.New("real owned cgroup2 subtree required")
	}
	state, e := root.Stat(".")
	if e != nil {
		return nil, nil, e
	}
	identity := state.Sys().(*syscall.Stat_t)
	binding := sha256.Sum256(append(raw, []byte(fmt.Sprintf("\nnode=%d:%d\n", identity.Dev, identity.Ino))...))
	d.gate, e = gate.NewBound(sessionPath+"/node/gate", "warden-fc", d, binding)
	if e != nil {
		return nil, nil, e
	}
	d.allocator, e = OpenAllocator(sessionPath+"/node/uids", d.gate.Authority())
	if e != nil {
		return nil, nil, e
	}
	// Shared cache entries are private to this node, root-owned and immutable.
	// Per-VM hardlinks never receive chown/chmod; only private jail data does.
	for _, name := range []string{"kernel", "agent.ext4", "payload.ext4"} {
		src, e := verifiedArtifact(input, name, manifest.Artifacts[name], 64<<20)
		if e != nil {
			return nil, nil, e
		}
		dst, e := root.OpenFile("assets/"+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			src.Close()
			return nil, nil, e
		}
		_, e = io.Copy(dst, src)
		e = errors.Join(e, src.Close(), dst.Chmod(0444), dst.Sync(), dst.Close())
		if e != nil {
			return nil, nil, e
		}
	}
	if e = syncRoot(root); e != nil {
		return nil, nil, e
	}
	success = true
	return d, d.gate, nil
}
func (d *Driver) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, gate.ErrRetired
	}
	option := d.options[s.RunID]
	d.mu.Unlock()
	return d.start(ctx, s, option.benchmark, option.restore)
}
func (d *Driver) Reap(ctx context.Context, id string) error {
	if d == nil || d.root == nil || d.gate == nil || !runPattern.MatchString(id) {
		return ErrCleanupPending
	}
	d.mu.Lock()
	h := d.handles[id]
	d.mu.Unlock()
	if h == nil {
		if _, e := d.root.Lstat("runs/" + id); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return ErrCleanupPending
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.startDone:
	}
	return h.retire()
}
func (d *Driver) Close() error {
	if d == nil || d.root == nil || d.gate == nil {
		return ErrCleanupPending
	}
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	// This mutex also protects reserve's WaitGroup.Add and direct-driver admission.
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e := d.gate.SealAdmission(ctx); e != nil {
		return errors.Join(ErrCleanupPending, e)
	}
	waited := make(chan struct{})
	go func() { d.wg.Wait(); close(waited) }()
	select {
	case <-ctx.Done():
		return errors.Join(ErrCleanupPending, ctx.Err())
	case <-waited:
	}
	ids, failures := d.retirementRuns()
	for id := range ids {
		if e := d.gate.Reap(ctx, id); e != nil {
			failures = append(failures, e)
			continue
		}
		d.mu.Lock()
		h := d.handles[id]
		d.mu.Unlock()
		if h != nil {
			select {
			case <-h.done:
			case <-ctx.Done():
				failures = append(failures, ctx.Err())
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(append([]error{ErrCleanupPending}, failures...)...)
	}
	if e := errors.Join(d.allocator.Close(), d.cgroups.Close(), d.input.Close()); e != nil {
		return e
	}
	marker, e := checkedFile(d.root, "retired", os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if e != nil {
		return e
	}
	_, e = marker.WriteString("known-owner-retired\n")
	e = errors.Join(e, marker.Sync(), marker.Close(), syncRoot(d.root))
	return errors.Join(e, d.root.Close())
}

func digestBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
