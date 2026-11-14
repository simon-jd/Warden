// Package gvisor runs Warden sandboxes as Kubernetes Jobs on a gVisor
// RuntimeClass (k3s + runsc in the lab). Every run is one Job whose single
// container starts warden-gvisor-init (package supervisor) at PID 1: the node
// serves that binary read-only, and it sets the pids limit, the timeout and
// the uid/capability/seccomp drop for the tenant command, then reports
// through the termination message. The API is plain JSON over HTTPS. Binding
// a deployment's identity (gvisor.Bind) is separate; this driver checks the
// configured namespace, node and cluster UIDs before every mutation.
package gvisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"warden/runtimes"
	"warden/runtimes/gvisor/supervisor"
)

const (
	// InitMount is where the pod sees warden-gvisor-init.
	InitMount = "/.warden/init"
	// DeadlineGraceS is added to TimeoutS for the Job's activeDeadlineSeconds.
	// The supervisor enforces TimeoutS itself; the deadline is a backstop
	// for a supervisor that cannot.
	DeadlineGraceS = 60
	container      = "run"
)

var (
	runIDPattern  = regexp.MustCompile(`^[A-Z2-7]{26}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// Waiting reasons after which the container will not start by itself.
	stuck = map[string]bool{"ErrImageNeverPull": true, "InvalidImageName": true, "ErrImagePull": true, "ImagePullBackOff": true,
		"CreateContainerConfigError": true, "CreateContainerError": true, "RunContainerError": true}
)

// Config describes one dedicated namespace on a cluster with a gVisor
// RuntimeClass and warden-gvisor-init on its nodes.
type Config struct {
	Server string       // API server URL
	HTTP   *http.Client // trusts the cluster CA and, unless Token is set, presents the client certificate
	Token  string       // optional bearer token
	// Namespace is the dedicated namespace for runs.
	Namespace string
	// Repository is the image repository; a run's image is Repository@ImageDigest.
	Repository string
	// NodeName pins runs to one node (nodeSelector kubernetes.io/hostname).
	NodeName string
	// Expect*UID, when set, must match the live kube-system namespace (the
	// cluster's incarnation), run namespace and node before every mutation.
	ExpectClusterUID, ExpectNamespaceUID, ExpectNodeUID string
	RuntimeClass                                        string // default "gvisor"
	InitPath                                            string // node path of warden-gvisor-init, default /opt/warden/gvisor-init
	PullPolicy                                          string // default IfNotPresent
	// OverheadMiB is added to MemoryMiB for the pod memory limit. Under
	// gVisor that limit covers the sentry, the gofer, the supervisor and the
	// payload together (gVisor does not enforce memory.max inside the
	// sandbox), so the payload's own bound is MemoryMiB+OverheadMiB minus
	// what the rest uses. Default 128, as for the Firecracker VM.
	OverheadMiB     int
	Poll            time.Duration // status poll interval, default 50 ms
	LogLimit        int           // bytes of logs kept, default 1 MiB
	TeardownTimeout time.Duration // how long deletion may take, default 60 s
	// APIRetry is how long transient API errors (no answer, 429, 5xx) are
	// retried in a row while a run is followed or torn down, default 10 s.
	APIRetry time.Duration
	// JobConditionWait is how long Wait waits for the Job's condition after
	// the container of a pod that was being deleted ended, default 5 s. At
	// activeDeadlineSeconds the Job controller deletes the pod first and
	// records the condition after that.
	JobConditionWait time.Duration
}

// ErrKilled is Wait's error for a run that Kill deleted before Wait saw its
// container exit. No exit is made up for such a run.
var ErrKilled = errors.New("gvisor: run killed before its exit was observed")

// Driver implements runtimes.Runtime and gate.Driver.
type Driver struct {
	c   Config
	api client
}

func New(c Config) (*Driver, error) {
	u, err := url.Parse(c.Server)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil:
		return nil, errors.New("gvisor: HTTPS API server URL without credentials required")
	case c.HTTP == nil:
		return nil, errors.New("gvisor: HTTP client required")
	case !dnsLabel(c.Namespace):
		return nil, errors.New("gvisor: invalid namespace")
	case c.Repository == "" || strings.ContainsAny(c.Repository, "@ \t\n") || strings.Contains(c.Repository[strings.LastIndex(c.Repository, "/")+1:], ":"):
		return nil, errors.New("gvisor: image repository without tag or digest required")
	case c.ExpectNodeUID != "" && c.NodeName == "":
		return nil, errors.New("gvisor: ExpectNodeUID needs NodeName")
	}
	if c.RuntimeClass == "" {
		c.RuntimeClass = "gvisor"
	}
	if c.InitPath == "" {
		c.InitPath = "/opt/warden/gvisor-init"
	}
	if c.PullPolicy == "" {
		c.PullPolicy = "IfNotPresent"
	}
	if c.PullPolicy != "Never" && c.PullPolicy != "IfNotPresent" {
		return nil, errors.New("gvisor: pull policy must be Never or IfNotPresent (images are pinned by digest)")
	}
	if c.OverheadMiB == 0 {
		c.OverheadMiB = 128
	}
	if c.Poll <= 0 {
		c.Poll = 50 * time.Millisecond
	}
	if c.LogLimit <= 0 {
		c.LogLimit = 1 << 20
	}
	if c.TeardownTimeout <= 0 {
		c.TeardownTimeout = 60 * time.Second
	}
	if c.APIRetry <= 0 {
		c.APIRetry = 10 * time.Second
	}
	if c.JobConditionWait <= 0 {
		c.JobConditionWait = 5 * time.Second
	}
	return &Driver{c: c, api: client{server: c.Server, http: c.HTTP, token: c.Token}}, nil
}

func dnsLabel(s string) bool { return labelPattern.MatchString(s) } // binding.go

// JobName is the Job of a run. RunIDs are 26 base32 characters.
func JobName(runID string) string { return "warden-run-" + strings.ToLower(runID) }

func (d *Driver) validate(s runtimes.Spec) error {
	l := s.Limits
	switch {
	case !runIDPattern.MatchString(s.RunID):
		return errors.New("gvisor: run ID must be 26 base32 characters")
	case !digestPattern.MatchString(s.ImageDigest):
		return errors.New("gvisor: image must be a sha256 digest")
	case s.Network != "" && s.Network != "none":
		// runsc on the node runs with --network=none for every sandbox.
		return fmt.Errorf("gvisor: network %q is not supported, only none", s.Network)
	case len(s.AllowDomains) > 0 || s.EgressSource.IsValid():
		return errors.New("gvisor: network none forbids domains and egress sources")
	case math.IsNaN(l.CPU) || math.IsInf(l.CPU, 0) || l.CPU < 0.001 || l.CPU > 10000,
		l.MemoryMiB <= 0 || l.MemoryMiB > 1<<20, l.Pids <= 0, l.TimeoutS <= 0 || l.TimeoutS > 86400:
		return errors.New("gvisor: invalid or overflowing resource limits")
	}
	_, err := supervisor.Parse(supervisor.Args(supervisor.Config{Pids: l.Pids, TimeoutS: l.TimeoutS, Cmd: s.Cmd}))
	return err
}

// verify compares the live backend with the configured identity.
func (d *Driver) verify(ctx context.Context) error {
	for _, c := range []struct{ path, want, what string }{
		{"/api/v1/namespaces/kube-system", d.c.ExpectClusterUID, "cluster (kube-system)"},
		{"/api/v1/namespaces/" + d.c.Namespace, d.c.ExpectNamespaceUID, "namespace " + d.c.Namespace},
		{"/api/v1/nodes/" + d.c.NodeName, d.c.ExpectNodeUID, "node " + d.c.NodeName},
	} {
		if c.want == "" {
			continue
		}
		var o object
		if err := d.api.do(ctx, "GET", c.path, nil, nil, &o); err != nil {
			return fmt.Errorf("gvisor: verify %s: %w", c.what, err)
		}
		if o.Metadata.UID != c.want {
			return fmt.Errorf("gvisor: %s has UID %q, configured %q: not the bound backend", c.what, o.Metadata.UID, c.want)
		}
	}
	return nil
}

func (d *Driver) job(s runtimes.Spec) map[string]any {
	run := strings.ToLower(s.RunID)
	labels := map[string]any{"app.kubernetes.io/managed-by": "warden", "warden.dev/run": run}
	// warden.dev/sandbox is what policies/cilium/*.yaml select: without it a
	// sandbox pod would be outside default deny, the egress-proxy rule and
	// quarantine on a Cilium node.
	podLabels := map[string]any{"app.kubernetes.io/managed-by": "warden", "warden.dev/run": run, "warden.dev/network": "none",
		"warden.dev/sandbox": "true"}
	res := map[string]any{"cpu": strconv.Itoa(int(math.Ceil(s.Limits.CPU*1000))) + "m", "memory": strconv.Itoa(s.Limits.MemoryMiB+d.c.OverheadMiB) + "Mi"}
	podSpec := map[string]any{
		"runtimeClassName":              d.c.RuntimeClass,
		"restartPolicy":                 "Never",
		"automountServiceAccountToken":  false,
		"enableServiceLinks":            false,
		"terminationGracePeriodSeconds": 1,
		"dnsPolicy":                     "Default",
		"volumes":                       []any{map[string]any{"name": "warden-init", "hostPath": map[string]any{"path": d.c.InitPath, "type": "File"}}},
		"containers": []any{map[string]any{
			"name":            container,
			"image":           d.c.Repository + "@" + s.ImageDigest,
			"imagePullPolicy": d.c.PullPolicy,
			"command":         []string{InitMount},
			"args":            supervisor.Args(supervisor.Config{Pids: s.Limits.Pids, TimeoutS: s.Limits.TimeoutS, Cmd: s.Cmd}),
			"env":             []any{map[string]any{"name": supervisor.MarkerEnv, "value": "1"}},
			"resources":       map[string]any{"limits": res, "requests": res},
			"volumeMounts":    []any{map[string]any{"name": "warden-init", "mountPath": InitMount, "readOnly": true}},
			// Root and these capabilities exist only inside the gVisor
			// sentry; the supervisor needs them to set up the cgroup and
			// drops all of them before the payload runs.
			"securityContext": map[string]any{
				"runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": false, "privileged": false,
				"readOnlyRootFilesystem": true,
				"capabilities":           map[string]any{"drop": []string{"ALL"}, "add": []string{"SETGID", "SETPCAP", "SETUID", "SYS_ADMIN"}},
				"seccompProfile":         map[string]any{"type": "RuntimeDefault"},
			},
			"terminationMessagePath":   supervisor.TerminationLog,
			"terminationMessagePolicy": "File",
		}},
	}
	if d.c.NodeName != "" {
		podSpec["nodeSelector"] = map[string]any{"kubernetes.io/hostname": d.c.NodeName}
	}
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{"name": JobName(s.RunID), "namespace": d.c.Namespace, "labels": labels},
		"spec": map[string]any{
			"backoffLimit":            0,
			"completions":             1,
			"parallelism":             1,
			"activeDeadlineSeconds":   s.Limits.TimeoutS + DeadlineGraceS,
			"ttlSecondsAfterFinished": 600, // backstop if the driver dies before teardown
			"template":                map[string]any{"metadata": map[string]any{"labels": podLabels}, "spec": podSpec},
		},
	}
}

// Start submits the run's Job and returns once the API server accepted it.
func (d *Driver) Start(ctx context.Context, s runtimes.Spec) (runtimes.Handle, error) {
	started := time.Now()
	if err := d.validate(s); err != nil {
		return nil, err
	}
	if err := d.verify(ctx); err != nil {
		return nil, err
	}
	var created object
	if err := d.api.do(ctx, "POST", "/apis/batch/v1/namespaces/"+d.c.Namespace+"/jobs", nil, d.job(s), &created); err != nil {
		return nil, fmt.Errorf("gvisor: create job: %w", err)
	}
	if created.Metadata.UID == "" || created.Metadata.Name != JobName(s.RunID) {
		return nil, errors.New("gvisor: API server returned an unexpected job")
	}
	return &Run{d: d, spec: s, job: created.Metadata.UID, started: started, done: make(chan struct{})}, nil
}

// Reap deletes whatever Job and Pod a RunID left and waits until both are
// gone. It needs no handle, so a restarted controller can call it.
func (d *Driver) Reap(ctx context.Context, runID string) error {
	if !runIDPattern.MatchString(runID) {
		return errors.New("gvisor: run ID must be 26 base32 characters")
	}
	var j object
	err := d.api.do(ctx, "GET", "/apis/batch/v1/namespaces/"+d.c.Namespace+"/jobs/"+JobName(runID), nil, nil, &j)
	if isStatus(err, http.StatusNotFound) {
		return d.waitNoPods(ctx, url.Values{"labelSelector": {"warden.dev/run=" + strings.ToLower(runID)}})
	}
	if err != nil {
		return err
	}
	return d.teardown(ctx, JobName(runID), j.Metadata.UID, nil)
}

// teardown deletes the Job in the foreground and waits until the Job, the
// pinned Pod (if known) and every Pod of the Job are gone. kubelet removes a
// Pod object only after its containers are stopped and the pod cgroup is
// removed, so "gone" also means no process of the sandbox is left on the node.
func (d *Driver) teardown(ctx context.Context, name, jobUID string, pinned *pod) error {
	ctx, cancel := context.WithTimeout(ctx, d.c.TeardownTimeout)
	defer cancel()
	opts := map[string]any{"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Foreground", "preconditions": map[string]any{"uid": jobUID}}
	retry := d.retry()
	for {
		err := d.verify(ctx)
		if err == nil {
			// Repeating it is harmless: a Job already being deleted
			// accepts the same DELETE, and a gone one answers 404.
			err = d.api.do(ctx, "DELETE", "/apis/batch/v1/namespaces/"+d.c.Namespace+"/jobs/"+name, nil, opts, nil)
			if isStatus(err, http.StatusNotFound) {
				err = nil
			}
		}
		if err == nil {
			break
		}
		if !retry.again(ctx, err) {
			return fmt.Errorf("gvisor: delete job: %w", err)
		}
		if err := d.sleep(ctx); err != nil {
			return fmt.Errorf("gvisor: delete job: %w", err)
		}
	}
	retry = d.retry()
	for {
		gone, err := d.gone(ctx, name, jobUID, pinned)
		if !retry.again(ctx, err) {
			return fmt.Errorf("gvisor: teardown of %s not confirmed: %w", name, err)
		}
		if err == nil && gone {
			return nil
		}
		if err := d.sleep(ctx); err != nil {
			return fmt.Errorf("gvisor: teardown of %s not confirmed: %w", name, err)
		}
	}
}

// sleep waits one poll interval, or returns ctx's error.
func (d *Driver) sleep(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d.c.Poll):
		return nil
	}
}

// transient reports whether an API error can go away by itself: no HTTP
// answer (connection refused or reset, a client timeout, a cut body), 429,
// or a 5xx. Everything else, such as 403, 404 or a UID mismatch, is final.
func transient(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	var ue *url.Error
	return errors.As(err, &ue) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retry decides in a poll loop whether an API error is tried again:
// transient ones are, while they have lasted less than Config.APIRetry in a
// row. One retry value belongs to one loop.
type retry struct {
	limit time.Duration
	since time.Time
}

func (d *Driver) retry() *retry { return &retry{limit: d.c.APIRetry} }

// again is called with each error of the loop; a nil error resets the count.
func (r *retry) again(ctx context.Context, err error) bool {
	if err == nil {
		r.since = time.Time{}
		return true
	}
	if ctx.Err() != nil || !transient(err) {
		return false
	}
	if r.since.IsZero() {
		r.since = time.Now()
	}
	return time.Since(r.since) < r.limit
}

func (d *Driver) gone(ctx context.Context, name, jobUID string, pinned *pod) (bool, error) {
	var j object
	err := d.api.do(ctx, "GET", "/apis/batch/v1/namespaces/"+d.c.Namespace+"/jobs/"+name, nil, nil, &j)
	if err == nil && j.Metadata.UID == jobUID {
		return false, nil
	}
	if err != nil && !isStatus(err, http.StatusNotFound) {
		return false, err
	}
	if pinned != nil {
		var p pod
		err := d.api.do(ctx, "GET", "/api/v1/namespaces/"+d.c.Namespace+"/pods/"+pinned.Metadata.Name, nil, nil, &p)
		if err == nil && p.Metadata.UID == pinned.Metadata.UID {
			return false, nil
		}
		if err != nil && !isStatus(err, http.StatusNotFound) {
			return false, err
		}
	}
	var l podList
	if err := d.api.do(ctx, "GET", "/api/v1/namespaces/"+d.c.Namespace+"/pods", url.Values{"labelSelector": {"batch.kubernetes.io/controller-uid=" + jobUID}}, nil, &l); err != nil {
		return false, err
	}
	return len(l.Items) == 0, nil
}

func (d *Driver) waitNoPods(ctx context.Context, q url.Values) error {
	ctx, cancel := context.WithTimeout(ctx, d.c.TeardownTimeout)
	defer cancel()
	retry := d.retry()
	left := 0
	for {
		var l podList
		err := d.api.do(ctx, "GET", "/api/v1/namespaces/"+d.c.Namespace+"/pods", q, nil, &l)
		if err == nil && len(l.Items) == 0 {
			return nil
		}
		if !retry.again(ctx, err) {
			return err
		}
		if err == nil {
			left = len(l.Items)
		}
		if err := d.sleep(ctx); err != nil {
			return fmt.Errorf("gvisor: %d pods left without a job: %w", left, err)
		}
	}
}

// Timings are the moments of one run in Unix nanoseconds. Start and Wait are
// the driver's clock (Wait: when the run's exit was ready, after its
// teardown); Init and Exec come from the supervisor's report (CLOCK_REALTIME
// in the sentry, which follows the host clock) and are zero if there was no
// report.
type Timings struct {
	StartUnixNano, InitUnixNano, ExecUnixNano, WaitUnixNano int64
	PodUID                                                  string
}

// Run is the handle of one Job.
type Run struct {
	d       *Driver
	spec    runtimes.Spec
	job     string
	started time.Time

	tracking sync.Once     // the first Wait starts track in a goroutine
	done     chan struct{} // closed once result is set
	// teardownMu lets Kill's and track's teardowns take turns. It is taken
	// before mu, never while mu is held, and mu is never held during a
	// teardown, so Wait, Logs and Timings do not wait for one.
	teardownMu sync.Mutex
	mu         sync.Mutex
	stopTrack  context.CancelFunc // ends track's observation; Kill calls it
	pod        *pod
	logs       []byte
	killed     bool // Kill was called before the run was torn down
	torndown   bool
	result     waitResult
	timings    Timings
}

type waitResult struct {
	exit runtimes.Exit
	err  error
}

func (r *Run) Timings() Timings {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.timings
	t.StartUnixNano = r.started.UnixNano()
	return t
}

func (r *Run) Logs() io.ReadCloser {
	r.mu.Lock()
	defer r.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(r.logs)))
}

// Kill stops following the run, deletes the Job and waits for its Pod to
// disappear, for at most TeardownTimeout. It is a no-op once the run is torn
// down. A Wait that had not seen the container exit returns ErrKilled, but,
// like every result, only after the teardown: once Kill's is confirmed, or,
// if Kill's failed, after the one the run's tracking tries next. The runc
// and Firecracker handles' Wait likewise returns only after their Kill's
// cleanup. Meanwhile a Wait's own ctx still ends it, and Logs and Timings
// answer.
func (r *Run) Kill() error {
	r.teardownMu.Lock()
	defer r.teardownMu.Unlock()
	r.mu.Lock()
	if r.torndown {
		r.mu.Unlock()
		return nil
	}
	r.killed = true
	if r.stopTrack != nil {
		r.stopTrack()
	}
	pinned := r.pod
	r.mu.Unlock()
	if err := r.d.teardown(context.Background(), JobName(r.spec.RunID), r.job, pinned); err != nil {
		return err
	}
	r.mu.Lock()
	r.torndown = true
	r.mu.Unlock()
	return nil
}

// Wait returns the run's result. The run is followed until its container
// terminated, its logs are kept, it is torn down, and the result is the exit.
// CgroupEmpty requires both the supervisor's view (the workload cgroup
// emptied and removed) when it reported, and the confirmed deletion of the
// Pod.
//
// The first Wait starts following the run in the background, where it goes
// on whatever happens to that Wait, as the runc and Firecracker handles
// follow theirs. Each Wait returns that result or, if its ctx ends first,
// ctx.Err() at once; a ctx error is never the run's result, so a later Wait
// still gets it. A caller that gives up on the run calls Kill (the scheduler
// does); otherwise the run is torn down when it ends.
//
// The result comes only after the teardown, on every path, also when
// following the run failed: the scheduler marks such a run cleanup-pending
// and counts on the attempt. The teardown has its own TeardownTimeout. An
// error says whether the teardown was confirmed.
//
// The run ends without an exit, without waiting for the container: after
// Kill (ErrKilled, ready once Kill's teardown is done), when the Job was
// deleted otherwise (Reap), and when the Job controller gave up on the Job
// before its pod appeared. Every Wait gets the same result.
func (r *Run) Wait(ctx context.Context) (runtimes.Exit, error) {
	r.tracking.Do(func() {
		tctx, stop := context.WithCancel(context.Background())
		r.mu.Lock()
		r.stopTrack = stop
		r.mu.Unlock()
		go r.track(tctx, stop)
	})
	select {
	case <-r.done:
	default:
		select {
		case <-r.done:
		case <-ctx.Done():
			return runtimes.Exit{}, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result.exit, r.result.err
}

// track observes the run to its end, tears it down and publishes the
// result. Only Kill cancels ctx.
func (r *Run) track(ctx context.Context, stop context.CancelFunc) {
	defer stop()
	r.mu.Lock()
	killed := r.killed
	r.mu.Unlock()
	var out runtimes.Exit
	var rep *supervisor.Report
	err := ErrKilled
	if !killed {
		out, rep, err = r.observe(ctx)
	}
	r.teardownMu.Lock()
	defer r.teardownMu.Unlock()
	r.mu.Lock()
	switch {
	case err == nil || !r.killed || errors.Is(err, ErrKilled):
	case ctx.Err() != nil && errors.Is(err, context.Canceled):
		// Kill stopped the observation; the cancellation says nothing more.
		err = ErrKilled
	default:
		err = fmt.Errorf("%w: %w", ErrKilled, err)
	}
	torndown, pinned := r.torndown, r.pod
	r.mu.Unlock()
	if !torndown {
		if terr := r.d.teardown(context.Background(), JobName(r.spec.RunID), r.job, pinned); terr != nil {
			err = errors.Join(err, terr)
		} else {
			torndown = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer close(r.done)
	r.torndown = torndown
	if err != nil {
		r.result = waitResult{err: err}
		return
	}
	if rep != nil {
		r.timings.InitUnixNano, r.timings.ExecUnixNano = rep.InitUnixNano, rep.ExecUnixNano
	}
	r.timings.WaitUnixNano = time.Now().UnixNano()
	out.CgroupEmpty = rep == nil || rep.CgroupEmpty
	r.result = waitResult{exit: out}
}

// ended says why a run ended without an exit: Kill, or what happened.
func (r *Run) ended(what string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.killed {
		return ErrKilled
	}
	return errors.New("gvisor: " + what)
}

// jobEnded returns why the run's Job no longer runs, or nil while it does:
// the Job was deleted or replaced, or the Job controller gave up on it
// (condition FailureTarget or Failed, as at activeDeadlineSeconds). err is
// the API's error.
func (r *Run) jobEnded(ctx context.Context, before string) (why, err error) {
	var j job
	err = r.d.api.do(ctx, "GET", r.jobPath(), nil, nil, &j)
	switch {
	case isStatus(err, http.StatusNotFound), err == nil && j.Metadata.UID != r.job:
		return r.ended("job was deleted " + before), nil
	case err != nil:
		return nil, err
	}
	if c, ok := j.failed(); ok {
		return fmt.Errorf("gvisor: job %s %s: %s: %s", strings.ToLower(c.Type), before, c.Reason, c.Message), nil
	}
	return nil, nil
}

func (r *Run) jobPath() string {
	return "/apis/batch/v1/namespaces/" + r.d.c.Namespace + "/jobs/" + JobName(r.spec.RunID)
}

// deadlineExceeded reports whether the Job controller ended the run at
// activeDeadlineSeconds: a FailureTarget or Failed condition with reason
// DeadlineExceeded. The pod's status never says so (its reason
// DeadlineExceeded belongs to a pod-level deadline, which runs do not
// have). The controller deletes the pod before it records the condition, so
// for a pod that was being deleted the condition gets JobConditionWait to
// appear. A Job that is gone was deleted (Kill, Reap), not timed out.
func (r *Run) deadlineExceeded(ctx context.Context, deleting bool) (bool, error) {
	limit := time.Now().Add(r.d.c.JobConditionWait)
	retry := r.d.retry()
	for {
		var j job
		err := r.d.api.do(ctx, "GET", r.jobPath(), nil, nil, &j)
		if isStatus(err, http.StatusNotFound) || err == nil && j.Metadata.UID != r.job {
			return false, nil
		}
		if !retry.again(ctx, err) {
			return false, err
		}
		if err == nil {
			if c, ok := j.failed(); ok {
				return c.Reason == "DeadlineExceeded", nil
			}
			if !deleting || !time.Now().Before(limit) {
				return false, nil
			}
		}
		if err := r.d.sleep(ctx); err != nil {
			return false, err
		}
	}
}

// observe follows the run until its container terminated and reads the logs
// and the supervisor's report. It changes nothing on the cluster.
func (r *Run) observe(ctx context.Context) (runtimes.Exit, *supervisor.Report, error) {
	p, err := r.find(ctx)
	if err != nil {
		return runtimes.Exit{}, nil, err
	}
	term, err := r.follow(ctx, p)
	if err != nil {
		return runtimes.Exit{}, nil, err
	}
	logs, dropped, err := r.fetchLogs(ctx)
	// The API server serves the logs only while the pod exists. At
	// activeDeadlineSeconds the Job controller deletes the pod, and on the
	// lab the pod was gone right after it turned Failed (job-deadline/
	// timeline.txt), so the logs can be lost before they are read. The Job
	// still says whether that was the deadline; only then is there an exit,
	// with the lost logs counted as truncated (DroppedLogBytes cannot count
	// them). Any other lost logs stay an error.
	lost, timedOut := isStatus(err, http.StatusNotFound), false
	if lost {
		var jerr error
		if timedOut, jerr = r.deadlineExceeded(ctx, true); jerr != nil {
			return runtimes.Exit{}, nil, fmt.Errorf("gvisor: logs: %w; job: %w", err, jerr)
		}
		if timedOut {
			err = nil
		}
	}
	if err != nil {
		return runtimes.Exit{}, nil, fmt.Errorf("gvisor: logs: %w", err)
	}
	r.mu.Lock()
	r.logs = logs
	r.mu.Unlock()
	out := runtimes.Exit{Code: uint32(term.state.ExitCode), OOMKilled: term.state.Reason == "OOMKilled",
		LogsTruncated: dropped > 0 || lost, DroppedLogBytes: dropped}
	var rep *supervisor.Report
	if term.state.Message != "" {
		parsed, err := supervisor.ParseReport([]byte(term.state.Message))
		if err != nil {
			return runtimes.Exit{}, nil, fmt.Errorf("gvisor: supervisor report: %w", err)
		}
		if parsed.Code != uint32(term.state.ExitCode) {
			return runtimes.Exit{}, nil, fmt.Errorf("gvisor: supervisor reported exit code %d, kubelet %d", parsed.Code, term.state.ExitCode)
		}
		rep = &parsed
	}
	// The Job controller ends a run at activeDeadlineSeconds by deleting its
	// pod. kubelet then stops the supervisor with SIGTERM (it reports that)
	// or a supervisor that cannot report. Only the Job says it was the
	// deadline.
	if rep == nil || rep.Signalled() {
		if !lost {
			if timedOut, err = r.deadlineExceeded(ctx, term.deleting); err != nil {
				return runtimes.Exit{}, nil, fmt.Errorf("gvisor: job: %w", err)
			}
		}
		out.TimedOut = timedOut
		if rep == nil {
			return out, nil, nil
		}
		if timedOut {
			out.PidsMaxEvents, out.PeakPids = rep.PidsMaxEvents, rep.PeakPids
			return out, rep, nil
		}
	}
	if rep.Error != "" {
		return runtimes.Exit{}, nil, fmt.Errorf("gvisor: supervisor: %s", rep.Error)
	}
	out.TimedOut, out.PidsMaxEvents, out.PeakPids = rep.TimedOut, rep.PidsMaxEvents, rep.PeakPids
	return out, rep, nil
}

// find waits for the one Pod the Job controller creates and pins its UID.
func (r *Run) find(ctx context.Context) (*pod, error) {
	q := url.Values{"labelSelector": {"batch.kubernetes.io/controller-uid=" + r.job}}
	retry := r.d.retry()
	for {
		var l podList
		err := r.d.api.do(ctx, "GET", "/api/v1/namespaces/"+r.d.c.Namespace+"/pods", q, nil, &l)
		if err == nil && len(l.Items) == 0 {
			// The Job controller may never create the pod (admission
			// rejects it, a quota is full); the Job tells.
			var why error
			if why, err = r.jobEnded(ctx, "before its pod appeared"); why != nil {
				return nil, why
			}
		}
		if !retry.again(ctx, err) {
			return nil, err
		}
		switch {
		case err != nil, len(l.Items) == 0:
		case len(l.Items) == 1:
			p := l.Items[0]
			if p.Metadata.UID == "" || p.Metadata.Labels["batch.kubernetes.io/controller-uid"] != r.job {
				return nil, errors.New("gvisor: pod does not belong to the job")
			}
			r.mu.Lock()
			r.pod = &p
			r.timings.PodUID = p.Metadata.UID
			r.mu.Unlock()
			return &p, nil
		default:
			return nil, fmt.Errorf("gvisor: job has %d pods, want 1", len(l.Items))
		}
		if err := r.d.sleep(ctx); err != nil {
			return nil, err
		}
	}
}

type termination struct {
	state struct {
		ExitCode        int32
		Reason, Message string
	}
	deleting bool // the pod had a deletionTimestamp when its container ended
}

func (r *Run) follow(ctx context.Context, pinned *pod) (termination, error) {
	var t termination
	retry := r.d.retry()
	for {
		var p pod
		err := r.d.api.do(ctx, "GET", "/api/v1/namespaces/"+r.d.c.Namespace+"/pods/"+pinned.Metadata.Name, nil, nil, &p)
		if isStatus(err, http.StatusNotFound) {
			// At activeDeadlineSeconds the Job controller deletes the
			// pod; the Job says if it did.
			if why, err := r.jobEnded(ctx, "before Wait saw its container end"); err == nil && why != nil {
				return t, why
			}
			return t, r.ended("pod was deleted before its container terminated")
		}
		if !retry.again(ctx, err) {
			return t, err
		}
		if err != nil {
			if err := r.d.sleep(ctx); err != nil {
				return t, err
			}
			continue
		}
		if p.Metadata.UID != pinned.Metadata.UID {
			return t, errors.New("gvisor: pod was replaced")
		}
		if r.d.c.NodeName != "" && p.Spec.NodeName != "" && p.Spec.NodeName != r.d.c.NodeName {
			return t, fmt.Errorf("gvisor: pod scheduled on %q", p.Spec.NodeName)
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name != container {
				continue
			}
			if s := cs.State.Terminated; s != nil {
				t.state.ExitCode, t.state.Reason, t.state.Message = s.ExitCode, s.Reason, s.Message
				t.deleting = p.Metadata.DeletionTimestamp != nil
				return t, nil
			}
			if w := cs.State.Waiting; w != nil && stuck[w.Reason] {
				return t, fmt.Errorf("gvisor: container cannot start: %s: %s", w.Reason, w.Message)
			}
		}
		if p.Status.Phase == "Failed" || p.Status.Phase == "Succeeded" {
			return t, fmt.Errorf("gvisor: pod %s before its container ran: %s %s", p.Status.Phase, p.Status.Reason, p.Status.Message)
		}
		if err := r.d.sleep(ctx); err != nil {
			return t, err
		}
	}
}

// fetchLogs keeps the first LogLimit bytes and counts the rest. A transient
// failure reads them again from the start.
func (r *Run) fetchLogs(ctx context.Context) ([]byte, uint64, error) {
	retry := r.d.retry()
	for {
		kept, rest, err := r.readLogs(ctx)
		if err == nil || !retry.again(ctx, err) {
			return kept, rest, err
		}
		if err := r.d.sleep(ctx); err != nil {
			return nil, 0, err
		}
	}
}

func (r *Run) readLogs(ctx context.Context) ([]byte, uint64, error) {
	resp, err := r.d.api.request(ctx, "GET", "/api/v1/namespaces/"+r.d.c.Namespace+"/pods/"+r.pod.Metadata.Name+"/log", url.Values{"container": {container}}, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	kept, err := io.ReadAll(io.LimitReader(resp.Body, int64(r.d.c.LogLimit)))
	if err != nil {
		return nil, 0, err
	}
	rest, err := io.Copy(io.Discard, resp.Body)
	return kept, uint64(rest), err
}
