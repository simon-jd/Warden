.PHONY: test check fmt tools test-tmp-private test-go test-python test-sigma test-vector test-postgres vuln-feeds test-vector-live \
	test-opensearch test-egress test-egress-runc test-vault test-kyverno test-kind test-gvisor test-identity test-cilium test-terraform terraform-plugins test-azure-respond \
	azure-down azure-preflight test-azure-budget \
	aks-probe aks-drill-plan aks-drill-up aks-drill-status aks-drill-down test-aks azure-teardown-check \
	detect-up detect-status detect-down detect-purge detect-smoke detect-seven-day-start \
	kind-audit-up kind-audit-status kind-audit-check-empty kind-audit-down

# One entry point for every offline suite, using project-local toolchains only
# (.tools/, restored by `make tools`). Live, cloud and GPU tests are skipped
# unless their own environment variables are set; see docs/STATUS.md.
#
#   make test     Go + Python + pySigma + Vector unit tests
#   make check    go vet, gofmt -l, shellcheck   (make fmt rewrites)
#   make tools    restore .tools/{go,vector,py,kyverno,kind,terraform} from .cache or official URLs

TOOLS := $(CURDIR)/.tools
GO := $(TOOLS)/go/bin/go
VECTOR := $(TOOLS)/vector/bin/vector
VENV_PY := $(TOOLS)/py/bin/python
KYVERNO := $(TOOLS)/kyverno/kyverno
KIND := $(TOOLS)/kind/kind
TERRAFORM := $(TOOLS)/terraform/terraform
KUBECTL := $(TOOLS)/kubectl/kubectl
# Private temp dir: runc socket tests reject group/other-writable ancestors, so
# a shared host TMPDIR would make results depend on the host.
TEST_TMP := $(CURDIR)/.cache/test-tmp
GOENV := env -u GOFLAGS -u GOPATH -u GOROOT GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly \
	GOCACHE=$(CURDIR)/.cache/go-build GOMODCACHE=$(CURDIR)/.cache/go-mod \
	GOPATH=$(CURDIR)/.cache/go HOME=$(CURDIR)/.cache/home TMPDIR=$(TEST_TMP)
# Every go command below gets -buildvcs=false. Go's VCS stamping only
# recognises a .git directory, so in a git worktree (.git is a file) it walks
# up to whatever .git directory is above the checkout, and an empty or foreign
# one there fails `go list` and every build. Nothing here needs the stamp. It
# is a flag, not part of GOFLAGS, because scripts/test-postgres.sh splits $GO
# on whitespace and GOFLAGS has to stay one word.
GO_NOVCS := -buildvcs=false
# -I: ignore PYTHON* variables, user site-packages and the caller's cwd.
# -E -s keeps the repo root (make's cwd) importable for the detect.* namespace.
PY := python3 -I -B
PY_REPO := python3 -E -s -B

# docs/evidence keeps source snapshots from earlier runs; they are not packages.
# GO_LIST sets $$pkgs and stops the recipe if `go list` fails or nothing is
# left: an empty list would make go test and go vet check "." instead.
GO_EXCLUDE := ^warden/docs/
GO_LIST = pkgs=$$($(GOENV) $(GO) list $(GO_NOVCS) ./...) && pkgs=$$(printf '%s\n' $$pkgs | grep -Ev '^$$|$(GO_EXCLUDE)') || exit 1

test: test-go test-python test-sigma test-vector
	@echo 'make test: all offline suites passed'

tools: $(GO) $(VECTOR) $(TOOLS)/py/.lock-sha256 $(KYVERNO) $(KIND) $(TERRAFORM)

$(GO):
	scripts/restore-tools.sh go
$(VECTOR):
	scripts/restore-tools.sh vector
$(KYVERNO):
	scripts/restore-tools.sh kyverno
$(KIND):
	scripts/restore-tools.sh kind
$(TERRAFORM):
	scripts/restore-tools.sh terraform
$(KUBECTL):
	scripts/restore-tools.sh kubectl
$(TOOLS)/py/.lock-sha256: detect/sigma/requirements.lock
	scripts/restore-tools.sh python

$(TEST_TMP):
	@mkdir -p -m 700 $@ .cache/home

# Stops test-go when TEST_TMP or a directory above it is group- or
# other-writable, as in a clone made with umask 0002: runtimes/firecracker's
# privateRoot rejects such ancestors, so its tests would fail one by one and
# make would stop before the other suites. The message names the directories
# and the chmod that fixes them. It is test-go's first prerequisite, so a
# serial make runs it before any tool is restored.
test-tmp-private: | $(TEST_TMP)
	@scripts/check-test-tmp.sh $(abspath $(TEST_TMP))

test-go: test-tmp-private $(GO) $(KYVERNO) | $(TEST_TMP)
	$(GO_LIST); $(GOENV) WARDEN_KYVERNO=$(KYVERNO) $(GO) test $(GO_NOVCS) -count=1 -shuffle=on $(GOTESTFLAGS) $$pkgs

# Only the Kyverno admission test (also part of test-go), verbose.
# KYVERNO_OUT=<file> keeps the raw `kyverno test` output.
test-kyverno: $(GO) $(KYVERNO) | $(TEST_TMP)
	$(GOENV) WARDEN_KYVERNO=$(KYVERNO) KYVERNO_OUT=$(if $(KYVERNO_OUT),$(abspath $(KYVERNO_OUT)),) \
		$(GO) test $(GO_NOVCS) -count=1 -v -run '^TestKyvernoAdmission$$' ./supplychain/kyvernolab

test-python:
	$(PY) -m unittest discover -s scripts -t scripts
	$(PY_REPO) -m unittest detect.report.test_coverage detect.report.test_detection_metrics detect.report.test_detection_report \
		detect.report.test_alert_import detect.report.test_observation detect.tests.backpressure_test \
		detect.falco.test_collector detect.falco.test_recorder detect.falco.test_bindings detect.falco.test_detector \
		detect.falco.test_benign detect.falco.test_review attacks.atomic.test_emulate attacks.stratus.test_emulate \
		detect.falco.test_audit_collector detect.report.test_audit_alert_import

test-sigma: $(TOOLS)/py/.lock-sha256
	$(VENV_PY) -E -s -B -m unittest detect.sigma.test_contract detect.sigma.test_rules

# Opt-in: starts a throwaway OpenSearch 2.19.1 container (warden-opensearch-*,
# 512 MiB heap, 1.5 GiB limit), indexes every Sigma fixture and asserts each
# rule's real pySigma query hits exactly the expected documents; removed on exit.
# OS_OUT=<file> keeps the raw result JSON.
test-opensearch: $(TOOLS)/py/.lock-sha256
	env -i PATH=/usr/bin:/bin HOME=$(CURDIR)/.cache/home WARDEN_LIVE_OPENSEARCH=1 OS_OUT=$(if $(OS_OUT),$(abspath $(OS_OUT)),) \
		$(VENV_PY) -E -s -B -m unittest -v detect.sigma.test_rules

BP_VALIDATE_ENV := BP_DATA=/nonexistent BP_DATA_AGG=/nonexistent BP_METRICS=/nonexistent BP_METRICS_AGG=/nonexistent \
	BP_LISTEN=127.0.0.1:1 BP_AGG=127.0.0.1:2 BP_URI=http://127.0.0.1:3/ BP_PROM_EXPORT=127.0.0.1:4 \
	BP_AGG_PROM_EXPORT=127.0.0.1:5 BP_LISTEN_AKS=127.0.0.1:6 BP_LISTEN_AZURE=127.0.0.1:7 BP_LISTEN_K3S=127.0.0.1:8 \
	BP_LISTEN_TETRAGON=127.0.0.1:9 BP_LISTEN_VNET=127.0.0.1:10 BP_LISTEN_WARDEN=127.0.0.1:11
test-vector: $(VECTOR)
	env -i PATH=/usr/bin:/bin HOME=$(CURDIR)/.cache/home $(VECTOR) test \
		detect/vector/aggregator.toml detect/ocsf/tests/*.toml
	@for wf in block drop_newest; do for f in detect/tests/backpressure-agent.toml detect/tests/backpressure-agent-6.toml detect/tests/backpressure-aggregator.toml; do \
		env -i PATH=/usr/bin:/bin HOME=$(CURDIR)/.cache/home $(BP_VALIDATE_ENV) BP_WHEN_FULL=$$wf \
			$(VECTOR) validate --no-environment $$f >/dev/null || exit 1; done; done; \
		echo 'backpressure two-hop configs (1 and 6 inputs): valid (block, drop_newest)'

# Opt-in live experiment, about 2.5 minutes and up to ~300 MB scratch in
# .cache/test-tmp: a 10x burst into a stalled sink through a production-sized
# disk buffer. BP_OUT=<file> keeps the raw result JSON; BP_SOURCE=stdin|http_server|vector
# picks the source (default stdin). vector = agent -> aggregator hop plus a
# throwaway Prometheus container (Docker) with the production buffer alerts;
# BP_WHEN_FULL=drop_newest makes the agent buffer drop instead of block;
# BP_INPUTS=6 splits the same traffic over the production agent's six inputs.
test-vector-live: $(VECTOR) | $(TEST_TMP)
	env -i PATH=/usr/bin:/bin HOME=$(CURDIR)/.cache/home TMPDIR=$(TEST_TMP) WARDEN_LIVE_VECTOR=1 \
		VECTOR=$(VECTOR) BP_OUT=$(BP_OUT) BP_SOURCE=$(BP_SOURCE) BP_WHEN_FULL=$(BP_WHEN_FULL) BP_VECTOR_LOG=$(BP_VECTOR_LOG) BP_INPUTS=$(BP_INPUTS) \
		$(PY_REPO) -m unittest -v detect.tests.backpressure_test

# Opt-in: starts a throwaway postgres:18-alpine container (Docker required),
# runs the Postgres-backed Go tests against it, and removes it on exit.
test-postgres: $(GO) | $(TEST_TMP)
	GO="$(GOENV) $(GO)" scripts/test-postgres.sh test $(GO_NOVCS) -count=1 $(GOTESTFLAGS) ./controlplane/...

# Opt-in: Docker egress lab (internal networks, Envoy, two TLS origins, sandbox
# clients with fixed source IPs). Runs the allowlist/block/hot-reload tests and
# removes every warden-egress-* container and network. EGRESS_OUT=<file> keeps
# the raw result JSON.
test-egress: $(GO) | $(TEST_TMP)
	$(GOENV) WARDEN_LIVE_EGRESS=1 EGRESS_OUT=$(if $(EGRESS_OUT),$(abspath $(EGRESS_OUT)),) $(GO) test $(GO_NOVCS) -count=1 -v \
		-run '^(TestAllowlistedDomainReachable|TestNonAllowlistedBlocked|TestEgressHotReload)$$' ./controlplane/internal/scheduler

# Opt-in: the same egress lab, but every probe is a real runc sandbox in
# Network "allowlist" inside the dedicated runc lab container
# (scripts/runtime_lab_docker.py egress, on the lab's sandbox network, plus a
# private PostgreSQL). One test drives the sandbox directly; TestAPIProcessRuncEgress
# goes API → Postgres → Scheduler.Process(EgressPool) → runc → Envoy.
# Disk preflight reserves 5 GB. Rebuilds the lab artifacts first; about 3 minutes.
# EGRESS_OUT=<file> keeps the result JSON and <file>-lab.log.
test-egress-runc: $(GO) | $(TEST_TMP)
	scripts/build-runtime-lab.sh
	$(GOENV) WARDEN_LIVE_EGRESS=1 WARDEN_LIVE_EGRESS_RUNC=1 EGRESS_OUT=$(if $(EGRESS_OUT),$(abspath $(EGRESS_OUT)),) $(GO) test $(GO_NOVCS) -count=1 -v -timeout 15m \
		-run '^TestRuncSandboxEgress$$' ./controlplane/internal/scheduler

# Opt-in: throwaway Vault (raft storage) + Postgres 18 containers
# (warden-vault-*); dynamic DB credentials expire after a 1-minute TTL and die
# on revoke; about 2 minutes. VAULT_OUT=<file> keeps the raw result JSON.
test-vault: $(GO) | $(TEST_TMP)
	$(GOENV) WARDEN_LIVE_VAULT=1 VAULT_OUT=$(if $(VAULT_OUT),$(abspath $(VAULT_OUT)),) $(GO) test $(GO_NOVCS) -count=1 -v ./identity/tests

# Opt-in: throwaway one-node kind cluster (scripts/kind_lab.sh: warden-respond,
# own Docker network, kubeconfig in .cache/kind), deleted on exit. Runs the
# live tests with least-privilege ServiceAccount tokens: respond/kindlab
# (IsolatePod, CordonNode, and TerminatePod with a second approver, through the
# executor) and the JIT RoleBinding test in controlplane/internal/jit, which
# also gets a throwaway Postgres (scripts/test-postgres.sh).
# KIND_OUT / JIT_OUT / TERMINATE_OUT / SERVICE_OUT=<file> keep the raw result
# JSON; KIND_REUSE=1 uses an already running `scripts/kind_lab.sh up`.
KIND_GO = $(GOENV) WARDEN_LIVE_KIND=1 WARDEN_KIND_KUBECONFIG=$(CURDIR)/.cache/kind/kubeconfig \
	KIND_OUT=$(if $(KIND_OUT),$(abspath $(KIND_OUT)),) JIT_OUT=$(if $(JIT_OUT),$(abspath $(JIT_OUT)),) \
	TERMINATE_OUT=$(if $(TERMINATE_OUT),$(abspath $(TERMINATE_OUT)),) \
	SERVICE_OUT=$(if $(SERVICE_OUT),$(abspath $(SERVICE_OUT)),) $(GO)
test-kind: $(GO) | $(TEST_TMP)
	GO="$(KIND_GO)" $(if $(filter 1,$(KIND_REUSE)),,scripts/kind_lab.sh run) scripts/test-postgres.sh \
		test $(GO_NOVCS) -count=1 -v -timeout 20m ./respond/kindlab ./controlplane/internal/jit

# Opt-in: one-node k3s + gVisor lab (scripts/k3s_gvisor_lab.sh: privileged
# node container warden-k3s-gvisor on the internal network warden-k3s, built
# from .tools/{k3s,gvisor} and this tree), removed on exit. Runs the seven-item
# TestGVisorConformance through a bound gate; GVISOR_COLD_STARTS=<n> also runs
# n serial cold starts (TestGVisorColdStarts), GVISOR_OUT=<file> keeps their
# JSON lines. GVISOR_REUSE=1 uses an already running `scripts/k3s_gvisor_lab.sh up`.
# GVISOR_LAB_FLAGS=<options> goes to the lab's `run`, for example
# --without-corpus (no attack helper or corpus image; docs/gvisor-lab.md).
GVISOR_GO = $(GOENV) WARDEN_LIVE_GVISOR=1 WARDEN_GVISOR_COLD_STARTS=$(GVISOR_COLD_STARTS) \
	GVISOR_OUT=$(if $(GVISOR_OUT),$(abspath $(GVISOR_OUT)),) $(GO)
test-gvisor: $(GO) | $(TEST_TMP)
	$(if $(filter 1,$(GVISOR_REUSE)),,scripts/k3s_gvisor_lab.sh run$(if $(strip $(GVISOR_LAB_FLAGS)), $(strip $(GVISOR_LAB_FLAGS)),)) scripts/k3s_gvisor_lab.sh env \
		$(GVISOR_GO) test $(GO_NOVCS) -count=1 -v -timeout 40m -run '^(TestGVisorConformance|TestGVisorColdStarts)$$' ./runtimes/gvisor

# Opt-in: Task 7's identity checks (runtimes/conformance/identity_test.go) on
# the same k3s lab: every token kubelet mounts for the control plane's pod
# spec (identity/kubernetes/controlplane.json) and the sandbox namespace's
# service accounts. IDENTITY_OUT=<file> keeps the JSON lines (claims only,
# never a token); IDENTITY_REUSE=1 uses an already running lab.
IDENTITY_GO = $(GOENV) WARDEN_LIVE_IDENTITY=1 IDENTITY_OUT=$(if $(IDENTITY_OUT),$(abspath $(IDENTITY_OUT)),) $(GO)
test-identity: $(GO) | $(TEST_TMP)
	$(if $(filter 1,$(IDENTITY_REUSE)),,scripts/k3s_gvisor_lab.sh run) scripts/k3s_gvisor_lab.sh env \
		$(IDENTITY_GO) test $(GO_NOVCS) -count=1 -v -timeout 10m -run '^(TestControlPlaneTokenIsShortLived|TestSandboxSAHasNoBindings)$$' ./runtimes/conformance

# Opt-in: the Cilium checks of Tasks 7, 10 and 14 (controlplane/internal/ciliumlab)
# on the k3s lab's Cilium mode, `scripts/k3s_gvisor_lab.sh up --cilium`: gVisor
# sandboxes under policies/cilium, the scheduler's Envoy as egress proxy, and
# the lab's stand-ins for the world and the metadata server. Cilium makes the
# host kernel load modules (allowed by the user on 2026-11-11; the lab lists
# them before and after). CILIUM_OUT=<dir> keeps one JSON result per test,
# CILIUM_RUN=<regexp> picks tests, WARDEN_CILIUM_REPS=<n> sets the quarantine
# reps (default 12); CILIUM_REUSE=1 uses a lab that is already up.
CILIUM_GO = $(GOENV) WARDEN_LIVE_CILIUM=1 CILIUM_OUT=$(if $(CILIUM_OUT),$(abspath $(CILIUM_OUT)),) \
	WARDEN_CILIUM_REPS=$(WARDEN_CILIUM_REPS) $(GO)
test-cilium: $(GO) | $(TEST_TMP)
	$(if $(filter 1,$(CILIUM_REUSE)),,scripts/k3s_gvisor_lab.sh run --cilium) scripts/k3s_gvisor_lab.sh env \
		$(CILIUM_GO) test $(GO_NOVCS) -count=1 -v -timeout 60m -run '$(or $(CILIUM_RUN),.)' ./controlplane/internal/ciliumlab

# Opt-in, live Entra ID (app registrations only, no Azure resources): the
# respond/azurelab test runs its reps in parallel, each on its own throwaway
# app warden-lab-respond-<n> (owned by the signed-in az user, tagged
# project=warden) with one client secret, which it deletes through the
# executor and the real AzureCLI adapter, timing Graph and the token
# endpoint; each app is deleted when its rep ends. Needs `az login`.
# WARDEN_AZURE_REPS=1..10 (default 5; the two 5-rep runs took 1506 s and
# 1606 s, about 25-27 minutes); AZURE_OUT=<file> keeps the raw result JSON
# (tenant, subscription and user IDs redacted).
test-azure-respond: $(GO) | $(TEST_TMP)
	$(GOENV) WARDEN_LIVE_AZURE=1 WARDEN_AZ=$$(command -v az) AZURE_CONFIG_DIR=$(or $(AZURE_CONFIG_DIR),$(HOME)/.azure) \
		WARDEN_AZURE_REPS=$(WARDEN_AZURE_REPS) AZURE_OUT=$(if $(AZURE_OUT),$(abspath $(AZURE_OUT)),) \
		$(GO) test $(GO_NOVCS) -count=1 -v -timeout 150m -run '^TestLiveDisableAzureAppCredential$$' ./respond/azurelab

# Task 7's live AKS drill (docs/aks-drill.md): one free-tier AKS cluster with
# one node in rg-warden-lab, its node resource group rg-warden-lab-aks-nodes,
# and the managed identity the control plane's service account federates
# with. aks-drill-up arms a hard stop (systemd user timers: start + 4 h, then
# 20 and 40 minutes later) before it reserves and creates anything; the
# guard refuses the reservation while an approval in AKS_PENDING_APPROVAL
# (scripts/azure_guard.py) is still False. aks-drill-down deletes both
# groups and runs the teardown check (also on its own: azure-teardown-check).
# test-aks runs the three Task 7 tests against the cluster, each on its own;
# AKS_OUT=<dir> keeps their results (no IDs: raw Azure answers go to
# ~/Desktop/warden-private-scratch/aks-drill).
AKS_DRILL := python3 -B scripts/aks_drill.py
AKS_GO = $(GOENV) AZURE_CONFIG_DIR=$(or $(AZURE_CONFIG_DIR),$(HOME)/.azure) \
	AKS_OUT=$(if $(AKS_OUT),$(abspath $(AKS_OUT)),) IDENTITY_OUT=$(if $(AKS_OUT),$(abspath $(AKS_OUT))/identity.jsonl,) $(GO)
aks-drill-plan:
	$(AKS_DRILL) plan
aks-probe: $(GO) | $(TEST_TMP)
	@mkdir -p .cache/aks-drill
	$(GOENV) CGO_ENABLED=0 $(GO) build $(GO_NOVCS) -tags netgo,osusergo -trimpath -ldflags=-s \
		-o .cache/aks-drill/warden-probe ./runtimes/conformance/guest
aks-drill-up: $(KUBECTL) aks-probe
	$(AKS_DRILL) up
aks-drill-status:
	$(AKS_DRILL) status
aks-drill-down:
	$(AKS_DRILL) down --reason manual
azure-teardown-check:
	python3 -B scripts/azure_guard.py teardown-check
test-aks: $(GO) $(KUBECTL) aks-probe | $(TEST_TMP)
	status=0; \
	$(AKS_DRILL) env -- $(AKS_GO) test $(GO_NOVCS) -count=1 -v -timeout 20m -run '^TestSandboxCannotReachMetadata$$' \
		./controlplane/internal/aksdrill || status=1; \
	$(AKS_DRILL) env -- $(AKS_GO) test $(GO_NOVCS) -count=1 -v -timeout 10m -run '^TestControlPlaneTokenIsShortLived$$' \
		./runtimes/conformance || status=1; \
	$(AKS_DRILL) env -- $(AKS_GO) test $(GO_NOVCS) -count=1 -v -timeout 15m -run '^TestSandboxSAHasNoBindings$$' \
		./runtimes/conformance || status=1; \
	exit $$status

# identity/terraform (Entra app registration for warden.access): fmt and
# validate, no Azure calls and no network. Every terraform call runs in a new
# network namespace (bwrap --unshare-net: only the loopback lo, which bwrap
# brings up with 127.0.0.1/8; no other interface), and init takes the pinned
# azuread provider only from TF_PLUGINS (-plugin-dir: no registry, no
# fallback), checked against the committed .terraform.lock.hcl hashes. If
# the provider is not there, it fails and says so; `make terraform-plugins`
# (networked, once) fetches it. Provider data stays in .cache.
TF_PLUGINS := $(CURDIR)/.cache/terraform/plugins
TF_ENV := env -i PATH=/usr/bin:/bin HOME=$(CURDIR)/.cache/home CHECKPOINT_DISABLE=1 TF_IN_AUTOMATION=1 \
	TF_DATA_DIR=$(CURDIR)/.cache/terraform/data
NO_NET := /usr/bin/bwrap --dev-bind / / --unshare-net --die-with-parent
test-terraform: $(TERRAFORM) | $(TEST_TMP)
	@$(NO_NET) /bin/true 2>/dev/null || { echo 'test-terraform: /usr/bin/bwrap --unshare-net does not work here; not running terraform with network' >&2; exit 1; }
	@test -d $(TF_PLUGINS)/registry.terraform.io/hashicorp/azuread || { \
		echo 'test-terraform: no hashicorp/azuread provider in $(TF_PLUGINS); run `make terraform-plugins` once (networked)' >&2; exit 1; }
	$(NO_NET) $(TF_ENV) $(TERRAFORM) -chdir=identity/terraform fmt -check -diff
	$(NO_NET) $(TF_ENV) $(TERRAFORM) -chdir=identity/terraform init -backend=false -input=false -lockfile=readonly -no-color \
		-plugin-dir=$(TF_PLUGINS)
	$(NO_NET) $(TF_ENV) $(TERRAFORM) -chdir=identity/terraform validate -no-color

# Networked, once: the azuread provider pinned in identity/terraform/.terraform.lock.hcl
# into TF_PLUGINS for test-terraform (the lock file's hashes are checked).
terraform-plugins: $(TERRAFORM) | $(TEST_TMP)
	@mkdir -p $(TF_PLUGINS)
	$(TF_ENV) TF_PLUGIN_CACHE_DIR=$(TF_PLUGINS) $(TERRAFORM) -chdir=identity/terraform init -backend=false -input=false \
		-lockfile=readonly -no-color

# Live (network): downloads the public EPSS and CISA KEV feeds, validates them
# and prints a JSON report. VULN_FINDINGS=<file> also ranks a findings file.
vuln-feeds: $(GO) | $(TEST_TMP)
	@$(GOENV) $(GO) run $(GO_NOVCS) ./vuln/cmd/vulnfeeds $(if $(VULN_FINDINGS),-findings $(VULN_FINDINGS),)

check: $(GO) | $(TEST_TMP)
	$(GO_LIST); $(GOENV) $(GO) vet $(GO_NOVCS) $$pkgs
	@out=$$($(GOENV) $(TOOLS)/go/bin/gofmt -l $$(git ls-files '*.go' ':!docs/**')); \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	shellcheck -S warning scripts/*.sh

fmt: $(GO)
	$(GOENV) $(TOOLS)/go/bin/gofmt -w $$(git ls-files '*.go' ':!docs/**')

# Task 13's online detector on home-ubuntu (docs/falco-detector.md): a pinned
# Falco 0.45.2 container (modern eBPF, privileged) and a collector that keeps
# only Warden containers' alerts and counts the rest, all on CPUs 0-7,16-31.
# It covers runc, and gVisor at host level (runsc's sentry and gofer, the k3s
# node; not the sandboxes' own system calls). DETECT_GVISOR_ENGINE=1 also
# starts the opt-in gVisor-engine instance (Falco 0.43.1), broken upstream
# (falcosecurity/libs#3074). detect-smoke runs the whole chain once on runc
# and gVisor (up, actions, down) and writes the evidence to DETECT_OUT.
# detect-seven-day-start starts the seven-day window only with
# CONFIRM=seven-day and no DRY_RUN (any value); otherwise it is a dry run.
# DETECT_K8SAUDIT=1 also starts the k8saudit instance (Falco 0.45.2 with the
# k8saudit and json plugins and the stock k8s_audit_rules.yaml), which reads
# the kind audit lab's API audit log: bring the lab up first
# (make kind-audit-up). The seven-day window does not use it.
# WARDEN_CPUSET=<cpu list> moves the detector, its units and the window's labs
# to other CPUs (the seven-day timers keep it).
WARDEN_CPUSET ?= 0-7,16-31
export WARDEN_CPUSET
DETECT := taskset -c $(WARDEN_CPUSET) python3 -I -B detect/falco/detector.py
$(TOOLS)/falco/.complete:
	scripts/restore-tools.sh falco
$(TOOLS)/falco-k8saudit/.complete:
	scripts/restore-tools.sh falco-k8saudit
detect-up: $(TOOLS)/falco/.complete $(if $(filter 1,$(DETECT_K8SAUDIT)),$(TOOLS)/falco-k8saudit/.complete,)
	$(DETECT) up$(if $(filter 1,$(DETECT_GVISOR_ENGINE)), --gvisor-engine,)$(if $(filter 1,$(DETECT_K8SAUDIT)), --k8saudit,)
detect-status:
	$(DETECT) status
detect-down:
	$(DETECT) down
detect-purge:
	$(DETECT) purge
detect-smoke: $(TOOLS)/falco/.complete
	taskset -c 0-7,16-31 python3 -I -B detect/falco/smoke.py all --out $(abspath $(or $(DETECT_OUT),.cache/detect/smoke))
detect-seven-day-start: $(TOOLS)/falco/.complete
	$(DETECT) seven-day-start $(if $(and $(filter seven-day,$(CONFIRM)),$(if $(DRY_RUN),,1)),--confirm seven-day,--dry-run)

# Task 13's kind audit lab (scripts/kind_lab.sh --audit, docs/falco-detector.md):
# the cluster warden-lab with API audit logging into
# .cache/kind-warden-lab/audit/audit.log, its node on CPUs 0-7,16-31. down
# deletes the cluster, its network and kubeconfigs and keeps the audit logs.
KIND_AUDIT := taskset -c 0-7,16-31 scripts/kind_lab.sh
kind-audit-up:
	$(KIND_AUDIT) up --audit
kind-audit-status:
	$(KIND_AUDIT) status --audit
# Exit 0 only if the namespace warden-lab holds nothing of an earlier run:
# call it before each run (the audit importer's namespace match ignores who
# made a request).
kind-audit-check-empty:
	$(KIND_AUDIT) check-empty --audit
kind-audit-down:
	$(KIND_AUDIT) down --audit

# rg-mlinfra-westus is always protected. No target/scope override is accepted.
azure-down:
	python3 -B scripts/azure_guard.py down $(if $(filter 1,$(DRY_RUN)),--dry-run,)
azure-preflight:
	python3 -B scripts/azure_guard.py preflight
test-azure-budget:
	$(PY) -m unittest discover -s scripts -t scripts -p test_azure_guard.py -v
