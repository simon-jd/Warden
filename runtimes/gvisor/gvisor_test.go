package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/runtimes"
	"warden/runtimes/gvisor/supervisor"
)

const (
	testRunID  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	testDigest = "sha256:42fedc571cfbd07bc8e8cc2077b6f8a2b0060e36011e8480acf78d0bbd804d66"
	testJob    = "warden-run-abcdefghijklmnopqrstuvwxyz"
)

// fakeAPI is a tiny API server: one Job, the Pod the Job controller would
// create for it, a scripted sequence of Pod statuses, and deletion that
// completes after a few polls, as when kubelet finalizes a terminated pod.
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	nsUID    string
	job      map[string]any
	posts    int
	statuses []map[string]any // returned in order; the last one repeats
	served   int
	logs     string
	deletes  []map[string]any
	deleted  bool
	gonePoll int // pod GETs after DELETE until 404; -1 = never
	podGets  int
	unavail  int // the next GETs of the pod by name answer 503; -1 = all of them
	// noPod: the Job controller never gets a pod created (for example,
	// admission rejects it). failAt: from that GET of the Job on, the Job
	// controller has given up on it (Job conditions FailureTarget and
	// Failed with reason failReason); 0 = never.
	noPod      bool
	failAt     int
	failReason string
	jobGets    int
	// The Job controller's end of a run at activeDeadlineSeconds (see
	// jobDeadline): from status deletingFrom on the pod has a
	// deletionTimestamp, condLag reads of the Job later the Job has
	// FailureTarget (and Failed once the last status was served), and from
	// pod GET vanishAt on the pod is gone. 0 = never.
	deletingFrom    int
	condLag         int
	vanishAt        int
	jobGetsDeleting int
}

func newFake(t *testing.T) (*fakeAPI, *Driver) {
	f := &fakeAPI{t: t, nsUID: "ns-uid", gonePoll: 2}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	d, err := New(Config{Server: srv.URL, HTTP: srv.Client(), Namespace: "warden-lab", Repository: "docker.io/warden-lab/probe",
		NodeName: "warden-gvisor", PullPolicy: "Never", ExpectNamespaceUID: "ns-uid", Poll: time.Millisecond, TeardownTimeout: 2 * time.Second,
		APIRetry: 100 * time.Millisecond, JobConditionWait: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return f, d
}

func terminated(code int, reason, message string) map[string]any {
	return map[string]any{"phase": "Failed", "containerStatuses": []any{map[string]any{"name": "run",
		"state": map[string]any{"terminated": map[string]any{"exitCode": code, "reason": reason, "message": message}}}}}
}

func running() map[string]any {
	return map[string]any{"phase": "Running", "containerStatuses": []any{map[string]any{"name": "run", "state": map[string]any{"running": map[string]any{}}}}}
}

func (f *fakeAPI) pod() map[string]any {
	i := min(f.served, len(f.statuses)-1)
	f.served++
	md := map[string]any{"name": testJob + "-x7k2p", "uid": "pod-uid",
		"labels": map[string]any{"batch.kubernetes.io/controller-uid": "job-uid"}}
	if f.deletingFrom > 0 && i >= f.deletingFrom {
		md["deletionTimestamp"] = "2026-11-11T04:58:39Z"
	}
	return map[string]any{"metadata": md, "spec": map[string]any{"nodeName": "warden-gvisor"}, "status": f.statuses[i]}
}

// vanished: the pod is gone without the driver's DELETE (jobDeadline).
func (f *fakeAPI) vanished() bool { return f.vanishAt > 0 && f.served >= f.vanishAt }

// logsGone: the API server serves a pod's logs only while the pod exists.
// Unlike podGone it counts no poll.
func (f *fakeAPI) logsGone() bool {
	return f.vanished() || f.deleted && f.gonePoll >= 0 && f.podGets > f.gonePoll
}

// jobDeadline scripts the end of a run at activeDeadlineSeconds in the order
// the lab showed (docs/evidence/task-3/review-fixes-20261110/job-deadline):
// the Job controller deletes the pod while its container runs and records
// FailureTarget with reason DeadlineExceeded; kubelet stops the container
// with SIGTERM and the pod turns Failed, its own reason empty; the
// controller records Failed; the pod disappears. lag is how many reads of
// the Job still miss the condition after the deletion.
func (f *fakeAPI) jobDeadline(end map[string]any, lag int) {
	f.statuses = []map[string]any{running(), running(), running(), running(), end}
	f.deletingFrom, f.condLag, f.vanishAt = 2, lag, len(f.statuses)+2
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	notFound := func() { reply(404, map[string]any{"kind": "Status", "code": 404, "reason": "NotFound"}) }
	jobs := "/apis/batch/v1/namespaces/warden-lab/jobs"
	pods := "/api/v1/namespaces/warden-lab/pods"
	switch p := r.URL.Path; {
	case r.Method == "GET" && p == "/api/v1/namespaces/warden-lab":
		reply(200, map[string]any{"metadata": map[string]any{"name": "warden-lab", "uid": f.nsUID}})
	case r.Method == "POST" && p == jobs:
		f.posts++
		if err := json.NewDecoder(r.Body).Decode(&f.job); err != nil {
			f.t.Errorf("job body: %v", err)
		}
		f.job["metadata"].(map[string]any)["uid"] = "job-uid"
		reply(201, f.job)
	case r.Method == "GET" && p == jobs+"/"+testJob:
		if f.job == nil || f.deleted {
			notFound()
			return
		}
		f.jobGets++
		j := map[string]any{}
		for k, v := range f.job {
			j[k] = v
		}
		if f.failAt > 0 && f.jobGets >= f.failAt {
			j["status"] = map[string]any{"conditions": []any{jobCond("FailureTarget", f.failReason), jobCond("Failed", f.failReason)}}
		}
		if f.deletingFrom > 0 && f.served > f.deletingFrom {
			if f.jobGetsDeleting++; f.jobGetsDeleting > f.condLag {
				conds := []any{jobCond("FailureTarget", "DeadlineExceeded")}
				if f.served >= len(f.statuses) {
					conds = append(conds, jobCond("Failed", "DeadlineExceeded"))
				}
				j["status"] = map[string]any{"conditions": conds}
			}
		}
		reply(200, j)
	case r.Method == "DELETE" && p == jobs+"/"+testJob:
		var opts map[string]any
		json.NewDecoder(r.Body).Decode(&opts)
		f.deletes = append(f.deletes, opts)
		if f.job == nil || f.deleted {
			notFound()
			return
		}
		f.deleted = true
		reply(200, map[string]any{"kind": "Status", "status": "Success"})
	case r.Method == "GET" && p == pods:
		if sel := r.URL.Query().Get("labelSelector"); sel != "batch.kubernetes.io/controller-uid=job-uid" && sel != "warden.dev/run=abcdefghijklmnopqrstuvwxyz" {
			f.t.Errorf("pod selector %q", r.URL.RawQuery)
		}
		items := []any{}
		if f.job != nil && !f.noPod && !f.vanished() && !(f.deleted && f.podGone()) {
			items = append(items, f.pod())
		}
		reply(200, map[string]any{"items": items})
	case r.Method == "GET" && p == pods+"/"+testJob+"-x7k2p":
		if f.unavail != 0 {
			f.unavail--
			reply(503, map[string]any{"kind": "Status", "code": 503, "reason": "ServiceUnavailable"})
			return
		}
		if f.vanished() || f.deleted && f.podGone() {
			notFound()
			return
		}
		reply(200, f.pod())
	case r.Method == "GET" && p == pods+"/"+testJob+"-x7k2p/log":
		if r.URL.Query().Get("container") != "run" {
			f.t.Errorf("log query %q", r.URL.RawQuery)
		}
		if f.logsGone() {
			notFound()
			return
		}
		io.WriteString(w, f.logs)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		notFound()
	}
}

func jobCond(typ, reason string) map[string]any {
	msg := map[string]string{"DeadlineExceeded": "Job was active longer than specified deadline",
		"BackoffLimitExceeded": "Job has reached the specified backoff limit"}[reason]
	return map[string]any{"type": typ, "status": "True", "reason": reason, "message": msg}
}

// waitWithin runs Wait with no deadline of its own and fails the test if it
// has not returned within d.
func waitWithin(t *testing.T, h runtimes.Handle, d time.Duration) (runtimes.Exit, error) {
	t.Helper()
	type result struct {
		out runtimes.Exit
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := h.Wait(context.Background())
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return r.out, r.err
	case <-time.After(d):
		t.Fatalf("Wait(context.Background()) still running after %s", d)
		return runtimes.Exit{}, nil
	}
}

func (f *fakeAPI) podGone() bool {
	f.podGets++
	return f.gonePoll >= 0 && f.podGets > f.gonePoll
}

func spec() runtimes.Spec {
	return runtimes.Spec{RunID: testRunID, ImageDigest: testDigest, Cmd: []string{"/warden-probe", "fork"},
		Limits: runtimes.Limits{CPU: 1, MemoryMiB: 128, Pids: 32, TimeoutS: 15}, Network: "none"}
}

func get(t *testing.T, v any, path ...string) any {
	t.Helper()
	for _, k := range path {
		switch x := v.(type) {
		case map[string]any:
			v = x[k]
		case []any:
			if len(x) != 1 {
				t.Fatalf("%v: want one element, have %d", path, len(x))
			}
			v = x[0].(map[string]any)[k]
		default:
			t.Fatalf("%v: no %q in %T", path, k, v)
		}
	}
	return v
}

func TestStartSubmitsGVisorJob(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	if _, err := d.Start(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	j := f.job
	want := map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata.name": testJob, "metadata.namespace": "warden-lab",
		"metadata.labels.warden.dev/run":                                       "abcdefghijklmnopqrstuvwxyz",
		"spec.backoffLimit":                                                    0.0,
		"spec.activeDeadlineSeconds":                                           float64(15 + DeadlineGraceS),
		"spec.template.metadata.labels.warden.dev/network":                     "none",
		"spec.template.metadata.labels.warden.dev/sandbox":                     "true",
		"spec.template.spec.runtimeClassName":                                  "gvisor",
		"spec.template.spec.restartPolicy":                                     "Never",
		"spec.template.spec.automountServiceAccountToken":                      false,
		"spec.template.spec.enableServiceLinks":                                false,
		"spec.template.spec.hostNetwork":                                       nil,
		"spec.template.spec.nodeSelector.kubernetes.io/hostname":               "warden-gvisor",
		"spec.template.spec.volumes.hostPath.path":                             "/opt/warden/gvisor-init",
		"spec.template.spec.volumes.hostPath.type":                             "File",
		"spec.template.spec.containers.name":                                   "run",
		"spec.template.spec.containers.image":                                  "docker.io/warden-lab/probe@" + testDigest,
		"spec.template.spec.containers.imagePullPolicy":                        "Never",
		"spec.template.spec.containers.resources.limits.cpu":                   "1000m",
		"spec.template.spec.containers.resources.limits.memory":                "256Mi",
		"spec.template.spec.containers.resources.requests.memory":              "256Mi",
		"spec.template.spec.containers.securityContext.runAsUser":              0.0,
		"spec.template.spec.containers.securityContext.privileged":             false,
		"spec.template.spec.containers.securityContext.readOnlyRootFilesystem": true,
		"spec.template.spec.containers.securityContext.seccompProfile.type":    "RuntimeDefault",
		"spec.template.spec.containers.volumeMounts.mountPath":                 InitMount,
		"spec.template.spec.containers.volumeMounts.readOnly":                  true,
		"spec.template.spec.containers.terminationMessagePath":                 supervisor.TerminationLog,
	}
	for path, v := range want {
		var keys []string
		for _, k := range strings.Split(path, ".") {
			if n := len(keys); n > 0 && (keys[n-1] == "warden" || keys[n-1] == "kubernetes") {
				keys[n-1] += "." + k // label keys contain dots
				continue
			}
			keys = append(keys, k)
		}
		if got := get(t, j, keys...); got != v {
			t.Errorf("%s = %#v, want %#v", path, got, v)
		}
	}
	c := get(t, j, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)
	if cmd, _ := json.Marshal(c["command"]); string(cmd) != `["`+InitMount+`"]` {
		t.Errorf("command %s", cmd)
	}
	args := []string{}
	for _, a := range c["args"].([]any) {
		args = append(args, a.(string))
	}
	if got, err := supervisor.Parse(args); err != nil || got.Pids != 32 || got.TimeoutS != 15 || strings.Join(got.Cmd, " ") != "/warden-probe fork" {
		t.Errorf("supervisor args %q: %+v %v", args, got, err)
	}
	caps, _ := json.Marshal(get(t, c, "securityContext", "capabilities"))
	if string(caps) != `{"add":["SETGID","SETPCAP","SETUID","SYS_ADMIN"],"drop":["ALL"]}` {
		t.Errorf("capabilities %s", caps)
	}
	env, _ := json.Marshal(c["env"])
	if string(env) != `[{"name":"`+supervisor.MarkerEnv+`","value":"1"}]` {
		t.Errorf("env %s", env)
	}
}

func TestStartRejectsInvalidSpecs(t *testing.T) {
	f, d := newFake(t)
	for name, mutate := range map[string]func(*runtimes.Spec){
		"allowlist network": func(s *runtimes.Spec) { s.Network = "allowlist"; s.AllowDomains = []string{"example.com"} },
		"domains on none":   func(s *runtimes.Spec) { s.AllowDomains = []string{"example.com"} },
		"short run id":      func(s *runtimes.Spec) { s.RunID = "ABC" },
		"lowercase run id":  func(s *runtimes.Spec) { s.RunID = strings.ToLower(testRunID) },
		"tag not digest":    func(s *runtimes.Spec) { s.ImageDigest = "latest" },
		"relative command":  func(s *runtimes.Spec) { s.Cmd = []string{"warden-probe"} },
		"no command":        func(s *runtimes.Spec) { s.Cmd = nil },
		"zero memory":       func(s *runtimes.Spec) { s.Limits.MemoryMiB = 0 },
		"zero pids":         func(s *runtimes.Spec) { s.Limits.Pids = 0 },
		"zero timeout":      func(s *runtimes.Spec) { s.Limits.TimeoutS = 0 },
		"tiny cpu":          func(s *runtimes.Spec) { s.Limits.CPU = 0.0001 },
	} {
		s := spec()
		mutate(&s)
		if _, err := d.Start(context.Background(), s); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	if f.posts != 0 {
		t.Fatalf("%d jobs submitted for invalid specs", f.posts)
	}
}

func TestStartRefusesAnotherNamespaceIncarnation(t *testing.T) {
	f, d := newFake(t)
	f.nsUID = "recreated-namespace"
	if _, err := d.Start(context.Background(), spec()); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("start against a replaced namespace: %v", err)
	}
	if f.posts != 0 {
		t.Fatal("job submitted")
	}
}

func report(t *testing.T, r supervisor.Report) string {
	t.Helper()
	r.Version = 1
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWaitUsesSupervisorReportAndTearsDown(t *testing.T) {
	f, d := newFake(t)
	now := time.Now().UnixNano()
	f.statuses = []map[string]any{running(), running(), terminated(0, "Completed",
		report(t, supervisor.Report{PidsMaxEvents: 1, PeakPids: 32, CgroupEmpty: true, InitUnixNano: now + 1e6, ExecUnixNano: now + 2e6}))}
	f.logs = "PASS fork\n"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != 0 || out.PidsMaxEvents != 1 || out.PeakPids != 32 || !out.CgroupEmpty || out.OOMKilled || out.TimedOut || out.LogsTruncated {
		t.Fatalf("exit %+v", out)
	}
	raw, _ := io.ReadAll(h.Logs())
	if string(raw) != "PASS fork\n" {
		t.Fatalf("logs %q", raw)
	}
	if len(f.deletes) != 1 || get(t, f.deletes[0], "propagationPolicy") != "Foreground" || get(t, f.deletes[0], "preconditions", "uid") != "job-uid" {
		t.Fatalf("teardown deletes %v", f.deletes)
	}
	tm := h.(*Run).Timings()
	if tm.PodUID != "pod-uid" || tm.ExecUnixNano != now+2e6 || tm.StartUnixNano < now || tm.WaitUnixNano < tm.StartUnixNano {
		t.Fatalf("timings %+v", tm)
	}
	if err := h.Kill(); err != nil {
		t.Fatalf("kill after teardown: %v", err)
	}
	if again, err := h.Wait(context.Background()); err != nil || again != out || len(f.deletes) != 1 {
		t.Fatalf("second wait: %+v %v deletes=%d", again, err, len(f.deletes))
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	ok := Config{Server: "https://10.0.0.1:6443", HTTP: http.DefaultClient, Namespace: "warden-lab", Repository: "registry:5000/warden/probe"}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"http server":      func(c *Config) { c.Server = "http://10.0.0.1:6443" },
		"credentials":      func(c *Config) { c.Server = "https://u:p@10.0.0.1:6443" },
		"no client":        func(c *Config) { c.HTTP = nil },
		"bad namespace":    func(c *Config) { c.Namespace = "Warden_Lab" },
		"tagged repo":      func(c *Config) { c.Repository = "warden/probe:latest" },
		"digest repo":      func(c *Config) { c.Repository = "warden/probe@sha256:00" },
		"always pull":      func(c *Config) { c.PullPolicy = "Always" },
		"node uid no name": func(c *Config) { c.ExpectNodeUID = "x" },
	} {
		c := ok
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWaitWithoutReportUsesPodStatus(t *testing.T) {
	f, d := newFake(t)
	// The sentry was OOM-killed together with the supervisor: no report.
	f.statuses = []map[string]any{running(), terminated(137, "OOMKilled", "")}
	f.logs = "READY oom\n"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != 137 || !out.OOMKilled || out.TimedOut || !out.CgroupEmpty || out.PeakPids != 0 {
		t.Fatalf("exit %+v", out)
	}
}

// Every failed Wait still deletes the run, as the runc and Firecracker
// handles do: the scheduler marks such a run cleanup-pending and relies on
// the attempt having been made.
func TestWaitFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		status   map[string]any
		gonePoll int
		unavail  int
		want     string
	}{
		"forged report":       {terminated(0, "Completed", `{"v":1,"code":0,"cgroup_empty":true,"owned":true}`), 2, 0, "report"},
		"code mismatch":       {terminated(1, "Error", report(t, supervisor.Report{CgroupEmpty: true})), 2, 0, "exit code"},
		"image never pulled":  {map[string]any{"phase": "Pending", "containerStatuses": []any{map[string]any{"name": "run", "state": map[string]any{"waiting": map[string]any{"reason": "ErrImageNeverPull"}}}}}, 2, 0, "ErrImageNeverPull"},
		"kubelet rejected":    {map[string]any{"phase": "Failed", "reason": "OutOfcpu", "message": "Pod was rejected: Node didn't have enough resource: cpu"}, 2, 0, "OutOfcpu"},
		"teardown never ends": {terminated(0, "Completed", report(t, supervisor.Report{CgroupEmpty: true})), -1, 0, "teardown"},
		"API keeps failing":   {running(), 2, -1, "503"},
	} {
		t.Run(name, func(t *testing.T) {
			f, d := newFake(t)
			f.statuses, f.gonePoll = []map[string]any{tc.status}, tc.gonePoll
			d.c.TeardownTimeout = 50 * time.Millisecond
			h, err := d.Start(context.Background(), spec())
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.unavail = tc.unavail
			f.mu.Unlock()
			out, err := h.Wait(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error about %q, got %v (%+v)", tc.want, err, out)
			}
			if out.CgroupEmpty {
				t.Fatal("cgroup reported empty on a failed wait")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.deletes) != 1 || !f.deleted || get(t, f.deletes[0], "propagationPolicy") != "Foreground" || get(t, f.deletes[0], "preconditions", "uid") != "job-uid" {
				t.Fatalf("failed Wait left the run: %d DELETE requests %v, job deleted=%v", len(f.deletes), f.deletes, f.deleted)
			}
		})
	}
}

// A few 503s while following the pod (an API server restart, a proxy) do
// not end the run.
func TestWaitRetriesTransientAPIErrors(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running(), running(), terminated(0, "Completed", report(t, supervisor.Report{CgroupEmpty: true}))}
	f.logs = "PASS uid\n"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.unavail = 3
	f.mu.Unlock()
	out, err := h.Wait(context.Background())
	if err != nil || out.Code != 0 || !out.CgroupEmpty {
		t.Fatalf("wait across three 503s: %+v %v", out, err)
	}
}

// A Wait whose context ends returns ctx's error at once and leaves the run
// followed, as the runc and Firecracker handles do: the caller that gives up
// on the run kills it (the scheduler does). Otherwise the run is torn down
// in the background when it ends, and a later Wait gets its exit; the ctx
// error is never the run's result.
func TestWaitWhoseContextEndsLeavesTheRunFollowed(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	f.logs = "PASS uid\n"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err = h.Wait(ctx)
	if took := time.Since(began); !errors.Is(err, context.DeadlineExceeded) || took > 500*time.Millisecond {
		t.Fatalf("wait past its deadline: %v after %s", err, took)
	}
	f.mu.Lock()
	if len(f.deletes) != 0 || f.deleted {
		t.Errorf("the Wait that gave up deleted the run: %d DELETE requests, job deleted=%v", len(f.deletes), f.deleted)
	}
	f.statuses = append(f.statuses, terminated(0, "Completed", report(t, supervisor.Report{CgroupEmpty: true})))
	f.mu.Unlock()
	// The run ended; nobody waits, and it is torn down all the same.
	for limit := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		f.mu.Lock()
		deleted := f.deleted
		f.mu.Unlock()
		if deleted {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("the run ended 2 s ago and is not torn down")
		}
	}
	out, err := waitWithin(t, h, 2*time.Second)
	if err != nil || out.Code != 0 || !out.CgroupEmpty {
		t.Fatalf("a later Wait: %+v %v", out, err)
	}
	if raw, _ := io.ReadAll(h.Logs()); string(raw) != "PASS uid\n" {
		t.Fatalf("logs %q", raw)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deletes) != 1 {
		t.Fatalf("%d DELETE requests, want 1", len(f.deletes))
	}
}

// A Wait whose context has already ended returns at once, not after a
// teardown (here one that would take all of TeardownTimeout).
func TestWaitWithAnEndedContextReturnsAtOnce(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	f.gonePoll = -1
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	_, err = h.Wait(ctx)
	if took := time.Since(began); !errors.Is(err, context.Canceled) || took > 500*time.Millisecond {
		t.Fatalf("wait with an ended context: %v after %s", err, took)
	}
	// Not the run's result: after Kill, Wait says that it was killed.
	f.mu.Lock()
	f.gonePoll = 2
	f.mu.Unlock()
	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := waitWithin(t, h, 2*time.Second); !errors.Is(err, ErrKilled) || errors.Is(err, context.Canceled) {
		t.Fatalf("wait after kill: %v", err)
	}
}

// Concurrent Waits each honour their own context: one that gives up returns
// at once and changes nothing for another, which gets the run's exit.
func TestConcurrentWaitsHonourTheirOwnContexts(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		out runtimes.Exit
		err error
	}
	first := make(chan result, 1)
	go func() {
		out, err := h.Wait(context.Background())
		first <- result{out, err}
	}()
	for following := false; !following; {
		time.Sleep(5 * time.Millisecond)
		f.mu.Lock()
		following = f.served > 3
		f.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() {
		_, err := h.Wait(ctx)
		second <- err
	}()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("second wait: %v", err)
		}
	case <-time.After(time.Second):
		t.Errorf("a Wait with a 50 ms context still blocked after 1 s")
	}
	f.mu.Lock()
	f.statuses = append(f.statuses, terminated(0, "Completed", report(t, supervisor.Report{CgroupEmpty: true})))
	f.mu.Unlock()
	select {
	case r := <-first:
		if r.err != nil || r.out.Code != 0 || !r.out.CgroupEmpty {
			t.Fatalf("first wait: %+v %v", r.out, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Wait still running 2 s after the run ended")
	}
}

func TestLogsAreBoundedAndCounted(t *testing.T) {
	f, d := newFake(t)
	d.c.LogLimit = 8
	f.statuses = []map[string]any{terminated(0, "Completed", report(t, supervisor.Report{CgroupEmpty: true}))}
	f.logs = "0123456789abcdef"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(h.Logs())
	if string(raw) != "01234567" || !out.LogsTruncated || out.DroppedLogBytes != 8 {
		t.Fatalf("logs %q exit %+v", raw, out)
	}
}

func TestReapDeletesTheRunsJob(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	if _, err := d.Start(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := d.Reap(context.Background(), testRunID); err != nil {
		t.Fatal(err)
	}
	if len(f.deletes) != 1 || get(t, f.deletes[0], "propagationPolicy") != "Foreground" {
		t.Fatalf("deletes %v", f.deletes)
	}
	if err := d.Reap(context.Background(), testRunID); err != nil {
		t.Fatalf("second reap: %v", err)
	}
	if err := d.Reap(context.Background(), "lowercase"); err == nil {
		t.Fatal("invalid run ID reaped")
	}
}

// Once Kill has returned, its teardown is confirmed and Wait returns at once
// with an error that says so; no exit is made up for it. A Wait during
// Kill's teardown gets that error only after it
// (TestWaitDuringKillReturnsAfterTheTeardown).
func TestWaitAfterKillReturnsAtOnce(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	out, err := waitWithin(t, h, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "killed") || out.CgroupEmpty {
		t.Fatalf("wait after kill: %+v %v", out, err)
	}
	if again, err2 := waitWithin(t, h, 2*time.Second); err2 == nil || err2.Error() != err.Error() || again != out {
		t.Fatalf("second wait: %+v %v", again, err2)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deletes) != 1 {
		t.Fatalf("%d DELETE requests, want Kill's one", len(f.deletes))
	}
}

// Reap needs no handle, so the handle does not know about it: Wait finds the
// Job gone and ends.
func TestWaitAfterReapReturnsAtOnce(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Reap(context.Background(), testRunID); err != nil {
		t.Fatal(err)
	}
	if out, err := waitWithin(t, h, 2*time.Second); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("wait after reap: %+v %v", out, err)
	}
}

// A Kill while Wait follows the pod ends that Wait with the kill, not with
// the 404 the deleted pod gives.
func TestKillDuringWaitEndsIt(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		out runtimes.Exit
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := h.Wait(context.Background())
		done <- result{out, err}
	}()
	for following := false; !following; {
		time.Sleep(5 * time.Millisecond)
		f.mu.Lock()
		following = f.served > 3
		f.mu.Unlock()
	}
	if err := h.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "killed") || strings.Contains(r.err.Error(), "404") {
			t.Fatalf("wait during kill: %+v %v", r.out, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait still running 2 s after Kill")
	}
}

// When no pod ever appears (admission rejects it, a quota is full), the Job
// controller gives up at activeDeadlineSeconds and so does Wait, which
// reads the Job while it waits for the pod.
func TestWaitEndsWhenTheJobFailsWithoutAPod(t *testing.T) {
	f, d := newFake(t)
	f.noPod, f.failAt, f.failReason = true, 3, "DeadlineExceeded"
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	out, err := waitWithin(t, h, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "DeadlineExceeded") || out.CgroupEmpty {
		t.Fatalf("wait for a pod that never comes: %+v %v", out, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deletes) != 1 || !f.deleted {
		t.Fatalf("%d DELETE requests, job deleted=%v", len(f.deletes), f.deleted)
	}
}

// The report the supervisor writes when kubelet stops it with SIGTERM, as on
// the lab at the Job's deadline (job-deadline/timeline.txt).
func signalledReport(t *testing.T) string {
	return report(t, supervisor.Report{Code: 137, PeakPids: 5, CgroupEmpty: true, InitUnixNano: 1, ExecUnixNano: 2, Error: "supervisor got terminated"})
}

// At activeDeadlineSeconds only the Job says that the run timed out: the
// pod's own reason stays empty (pod.status.reason DeadlineExceeded comes
// only from a pod-level deadline, which the driver does not set). On the lab
// the pod turned Failed and was deleted within the same second, so its logs
// can be gone before Wait reads them; the Job still says it timed out, and
// the lost logs count as truncated.
func TestJobDeadlineMakesTheRunTimedOut(t *testing.T) {
	for name, tc := range map[string]struct {
		end      map[string]any
		lag      int
		code     uint32
		peak     uint64
		logsGone bool
	}{
		"supervisor reported the SIGTERM":                 {terminated(137, "Error", signalledReport(t)), 0, 137, 5, false},
		"no report":                                       {terminated(143, "Error", ""), 0, 143, 0, false},
		"condition recorded late":                         {terminated(143, "Error", ""), 3, 143, 0, false},
		"supervisor reported the SIGTERM, pod gone first": {terminated(137, "Error", signalledReport(t)), 0, 137, 5, true},
		"no report, pod gone first":                       {terminated(143, "Error", ""), 0, 143, 0, true},
		"condition recorded late, pod gone first":         {terminated(143, "Error", ""), 3, 143, 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			f, d := newFake(t)
			f.jobDeadline(tc.end, tc.lag)
			f.logs = "READY sleep\n"
			if tc.logsGone {
				// Gone right after Wait saw the container end.
				f.vanishAt = len(f.statuses)
			}
			h, err := d.Start(context.Background(), spec())
			if err != nil {
				t.Fatal(err)
			}
			out, err := waitWithin(t, h, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if out.Code != tc.code || !out.TimedOut || !out.CgroupEmpty || out.PeakPids != tc.peak || out.OOMKilled ||
				out.LogsTruncated != tc.logsGone || out.DroppedLogBytes != 0 {
				t.Fatalf("exit %+v", out)
			}
			want := "READY sleep\n"
			if tc.logsGone {
				want = ""
			}
			if raw, _ := io.ReadAll(h.Logs()); string(raw) != want {
				t.Fatalf("logs %q, want %q", raw, want)
			}
		})
	}
}

// If the pod is gone before Wait saw its container end, there is no exit,
// and the error is the Job's reason rather than the pod's 404.
func TestJobDeadlineBeforeTheContainerEndWasSeen(t *testing.T) {
	f, d := newFake(t)
	f.jobDeadline(terminated(143, "Error", ""), 0)
	f.vanishAt = f.deletingFrom + 1
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	out, err := waitWithin(t, h, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "DeadlineExceeded") || out.CgroupEmpty {
		t.Fatalf("wait: %+v %v", out, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deletes) != 1 || !f.deleted {
		t.Fatalf("%d DELETE requests, job deleted=%v", len(f.deletes), f.deleted)
	}
}

// A pod deleted by anyone but the Job controller's deadline is no timeout:
// the supervisor's report of the SIGTERM stays an error, a sandbox stopped
// without a report keeps its exit, and Wait waits for a condition no
// longer than JobConditionWait.
func TestDeletedPodWithoutDeadlineIsNoTimeout(t *testing.T) {
	f, d := newFake(t)
	f.jobDeadline(terminated(137, "Error", signalledReport(t)), 1<<30)
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := waitWithin(t, h, 5*time.Second); err == nil || !strings.Contains(err.Error(), "supervisor got terminated") || out.TimedOut {
		t.Fatalf("signalled supervisor, no deadline: %+v %v", out, err)
	}
	f, d = newFake(t)
	f.jobDeadline(terminated(143, "Error", ""), 1<<30)
	if h, err = d.Start(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if out, err := waitWithin(t, h, 5*time.Second); err != nil || out.Code != 143 || out.TimedOut {
		t.Fatalf("stopped sandbox, no deadline: %+v %v", out, err)
	}
	// Without the deadline, logs lost with the pod stay an error.
	f, d = newFake(t)
	f.jobDeadline(terminated(143, "Error", ""), 1<<30)
	f.vanishAt = len(f.statuses)
	if h, err = d.Start(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	if out, err := waitWithin(t, h, 5*time.Second); err == nil || !strings.Contains(err.Error(), "logs") || out.TimedOut || out.CgroupEmpty {
		t.Fatalf("stopped sandbox, no deadline, logs gone: %+v %v", out, err)
	}
}

// killInTeardown starts Kill on a run whose pod never goes away, so Kill's
// teardown takes all of TeardownTimeout, and returns once Kill has sent its
// DELETE. letGo lets the pod disappear; Kill's error arrives on the channel.
func killInTeardown(t *testing.T, f *fakeAPI, h runtimes.Handle) (killed <-chan error, letGo func()) {
	t.Helper()
	f.mu.Lock()
	f.gonePoll = -1
	f.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- h.Kill() }()
	for deleting := false; !deleting; {
		time.Sleep(time.Millisecond)
		f.mu.Lock()
		deleting = len(f.deletes) > 0
		f.mu.Unlock()
	}
	return done, func() {
		f.mu.Lock()
		f.gonePoll = 2
		f.mu.Unlock()
	}
}

// Kill's teardown does not hold up a Wait's own context, even for the first
// Wait, which starts following the run.
func TestWaitDuringKillHonoursItsContext(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	killed, letGo := killInTeardown(t, f, h)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err = h.Wait(ctx)
	if took := time.Since(began); !errors.Is(err, context.DeadlineExceeded) || took > 500*time.Millisecond {
		t.Errorf("Wait with a 50 ms context during Kill's teardown: %v after %s", err, took)
	}
	letGo()
	<-killed
	if _, err := waitWithin(t, h, 3*time.Second); !errors.Is(err, ErrKilled) {
		t.Fatalf("wait after kill: %v", err)
	}
}

// Logs and Timings answer while Kill tears the run down.
func TestLogsAndTimingsDuringKillAnswer(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	killed, letGo := killInTeardown(t, f, h)
	began := time.Now()
	h.Logs().Close()
	h.(*Run).Timings()
	if took := time.Since(began); took > 500*time.Millisecond {
		t.Errorf("Logs and Timings during Kill's teardown took %s", took)
	}
	letGo()
	<-killed
}

// The run's result comes only after its teardown, also after Kill: a Wait
// that follows the run when Kill starts returns ErrKilled once Kill's
// teardown is confirmed, not before. The runc and Firecracker handles' Wait
// likewise returns only after their Kill's cleanup.
func TestWaitDuringKillReturnsAfterTheTeardown(t *testing.T) {
	f, d := newFake(t)
	f.statuses = []map[string]any{running()}
	h, err := d.Start(context.Background(), spec())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		out runtimes.Exit
		err error
		at  time.Time
	}
	waited := make(chan result, 1)
	go func() {
		out, err := h.Wait(context.Background())
		waited <- result{out, err, time.Now()}
	}()
	for following := false; !following; {
		time.Sleep(5 * time.Millisecond)
		f.mu.Lock()
		following = f.served > 3
		f.mu.Unlock()
	}
	killed, letGo := killInTeardown(t, f, h)
	select {
	case r := <-waited:
		t.Fatalf("Wait returned while Kill's teardown was not confirmed: %+v %v", r.out, r.err)
	case <-time.After(200 * time.Millisecond):
	}
	letGo()
	if err := <-killed; err != nil {
		t.Fatal(err)
	}
	confirmed := time.Now()
	select {
	case r := <-waited:
		if !errors.Is(r.err, ErrKilled) || r.out.CgroupEmpty {
			t.Fatalf("wait during kill: %+v %v", r.out, r.err)
		}
		if r.at.Before(confirmed.Add(-50 * time.Millisecond)) {
			t.Fatalf("Wait returned %s before Kill's teardown was confirmed", confirmed.Sub(r.at))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait still running 2 s after Kill returned")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deletes) != 1 {
		t.Fatalf("%d DELETE requests, want Kill's one", len(f.deletes))
	}
}
