package kindlab

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestKindServiceAndDNS checks what STATUS blocker 10 left open. In phase 5
// kube-proxy could not start in the kind node (inotify EMFILE while the
// host allowed about 128 instances), so ClusterIP Services and cluster DNS
// did not work and the other live tests probe pod IPs. This checks that
// kube-proxy and CoreDNS are Ready and kube-proxy logged no "too many open
// files", then has a client pod reach a server pod by pod IP (the control:
// needs no kube-proxy), by the Service's ClusterIP and by the Service's DNS
// name, with no failed probe over a 10 s window. SERVICE_OUT=<file> keeps
// the result JSON.
func TestKindServiceAndDNS(t *testing.T) {
	l := liveLab(t)
	loadStart := loadavg()
	l.setup()
	result := map[string]any{"node": l.node, "host_inotify": inotifyLimits()}

	type systemPod struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			ContainerStatuses []struct {
				RestartCount int `json:"restartCount"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	list := func(app string) []systemPod {
		var pods struct {
			Items []systemPod `json:"items"`
		}
		l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/namespaces/kube-system/pods?labelSelector="+url.QueryEscape("k8s-app="+app),
			"", nil, &pods), "list "+app)
		return pods.Items
	}
	ready := func(p systemPod) bool {
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" {
				return c.Status == "True"
			}
		}
		return false
	}
	allReady := func(app string) (int, int) {
		pods, n := list(app), 0
		for _, p := range pods {
			if ready(p) {
				n++
			}
		}
		return len(pods), n
	}
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		kp, kpReady := allReady("kube-proxy")
		dns, dnsReady := allReady("kube-dns")
		if kp > 0 && kp == kpReady && dns > 0 && dns == dnsReady {
			break
		}
		time.Sleep(time.Second)
	}
	kp, kpReady := allReady("kube-proxy")
	dns, dnsReady := allReady("kube-dns")
	restarts, emfile := 0, 0
	for _, p := range list("kube-proxy") {
		for _, c := range p.Status.ContainerStatuses {
			restarts += c.RestartCount
		}
		var logs []byte
		l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/namespaces/kube-system/pods/"+p.Metadata.Name+"/log", "", nil, &logs), "kube-proxy logs")
		for _, line := range strings.Split(string(logs), "\n") {
			if strings.Contains(strings.ToLower(line), "too many open files") {
				emfile++
			}
		}
	}
	result["kube_proxy"] = map[string]any{"pods": kp, "ready": kpReady, "restarts": restarts, "emfile_log_lines": emfile}
	result["coredns"] = map[string]any{"pods": dns, "ready": dnsReady}
	if kp == 0 || kpReady != kp || restarts > 0 || emfile > 0 {
		t.Errorf("kube-proxy: %d pods, %d ready, %d restarts, %d \"too many open files\" log lines", kp, kpReady, restarts, emfile)
	}
	if dns == 0 || dnsReady != dns {
		t.Errorf("CoreDNS: %d pods, %d ready", dns, dnsReady)
	}

	serverIP := l.podIP("svc-server", nil)
	l.create("/api/v1/namespaces/"+sandboxNS+"/services", map[string]any{
		"apiVersion": "v1", "kind": "Service", "metadata": meta("svc-server", sandboxNS),
		"spec": map[string]any{"selector": map[string]string{"app": "svc-server"},
			"ports": []map[string]any{{"port": 80, "targetPort": 8080, "protocol": "TCP"}}}})
	var svc struct {
		Spec struct {
			ClusterIP string `json:"clusterIP"`
		} `json:"spec"`
	}
	l.must(l.admin.Do(l.ctx, http.MethodGet, "/api/v1/namespaces/"+sandboxNS+"/services/svc-server", "", nil, &svc), "get service")
	name := "svc-server." + sandboxNS + ".svc.cluster.local"
	targets := []string{"pod", "cluster_ip", "dns"}
	l.pod("svc-client", map[string]string{"TARGETS": "pod=" + serverIP + ":8080,cluster_ip=" + svc.Spec.ClusterIP + ":80,dns=" + name + ":80"})
	t.Cleanup(func() {
		for _, p := range []string{"/api/v1/namespaces/" + sandboxNS + "/pods/svc-client", "/api/v1/namespaces/" + sandboxNS + "/pods/svc-server",
			"/api/v1/namespaces/" + sandboxNS + "/services/svc-server"} {
			_ = l.admin.Do(l.ctx, http.MethodDelete, p, "", nil, nil)
		}
	})
	l.waitRunning("svc-client")
	result["service"] = map[string]any{"cluster_ip": svc.Spec.ClusterIP, "name": name}

	// For each target: the first attempt (either result) and the first success.
	firstTry, firstOK := map[string]float64{}, map[string]float64{}
	for start := time.Now(); time.Since(start) < 60*time.Second && len(firstOK) < len(targets); time.Sleep(500 * time.Millisecond) {
		ss := l.samples("svc-client", 120)
		for _, target := range targets {
			if at := first(ss, 0, "probe", target, true); at > 0 {
				firstOK[target] = at
			}
			try := first(ss, 0, "probe", target, false)
			if ok := firstOK[target]; try == 0 || (ok > 0 && ok < try) {
				try = ok
			}
			if try > 0 {
				firstTry[target] = try
			}
		}
	}
	window := map[string]any{}
	if len(firstOK) == len(targets) {
		from := epoch(time.Now())
		time.Sleep(10 * time.Second)
		ss := l.samples("svc-client", 30)
		for _, target := range targets {
			ok, fail := count(ss, from, from+10, "probe", target, true), count(ss, from, from+10, "probe", target, false)
			window[target] = map[string]int{"ok": ok, "fail": fail}
			if ok == 0 || fail > 0 {
				t.Errorf("%s: %d ok, %d failed probes in the 10 s window", target, ok, fail)
			}
		}
	}
	firstMS := map[string]any{}
	for _, target := range targets {
		at, seen := firstOK[target]
		if !seen {
			t.Errorf("%s: no successful probe within 60 s of the client running", target)
			firstMS[target] = nil
			continue
		}
		firstMS[target] = ms(at - firstTry[target])
	}
	result["first_ok_after_first_attempt_ms"] = firstMS
	result["window_10s"] = window
	result["load"] = map[string]any{"nproc": runtime.NumCPU(), "loadavg_start": loadStart, "loadavg_end": loadavg()}
	out, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("%s", out)
	if p := os.Getenv("SERVICE_OUT"); p != "" {
		if err := os.WriteFile(p, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// inotifyLimits reads the host limits blocker 10 is about.
func inotifyLimits() map[string]string {
	out := map[string]string{}
	for _, k := range []string{"max_user_instances", "max_user_watches"} {
		b, err := os.ReadFile("/proc/sys/fs/inotify/" + k)
		if err != nil {
			out[k] = "unreadable: " + err.Error()
			continue
		}
		out[k] = strings.TrimSpace(string(b))
	}
	return out
}
