# Task6 Docker 29.9.1 material-only proposal — NEEDS_CONTEXT

2026-10-25. Subagent design/research, not human review/actual/admission. Read brief, D1–D3, metadata MD/JSON. Only this ignored proposal written; no children/Git/index/source/tests/CLI/daemon/private action. Source owner retains implementation/index. Task6/Goal OPEN; original3/5, caps/history/Q5 unchanged.

## Exact conditional candidate

Future constants, not created now:

```
R=/home/postedism/Desktop/Warden
C=/home/postedism/Desktop/Warden/docs/evidence/task-6/controller-cli-material-20261025-config
argv=["/usr/bin/docker","--config",C,"--context","default","--version"]
cwd=R
env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C",
     "DOCKER_CONFIG":C,"DOCKER_CLI_HOOKS":"false"}
```

Fresh complete env, no inheritance; omit HOME without repurposing it. All other variables absent, notably DOCKER_HOST/CONTEXT/AUTH_CONFIG/TLS/TLS_VERIFY/CERT_PATH, proxy/OTEL*/DOCKER_CLI_OTEL*/plugin/LD_*/GODEBUG. Generate C exclusively controller-owned0700 and config.json regular single-link0600, exact public bytes plus LF:

```json
{"auths":{"warden-material.invalid":{}},"credsStore":"","credHelpers":{},"currentContext":"default","aliases":{},"features":{"hooks":"false"}}
```

Sentinel contains no credentials. No context/plugin/TLS files. Refuse preexisting C; no overwrite/reuse/retry. Recheck bytes/inode/owner/mode/ancestry before spawn/after terminal; preserve artifacts. Docker reopens by pathname, requiring exclusive writer/no same-UID/root replacement. stdin EOF, merged bounded output pipe, no PTY, unrelated FDs closed. Never `docker version` or naked `--version`.

## Matching primary-source path

Links are official v29.9.1 source. Source observations do not establish installed-build equivalence.

1. [flags/options.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/flags/options.go): InstallFlags calls config.Dir before parsing --config: DOCKER_CONFIG=C prevents home/NSS lookup. Absent TLS env/flags gives TLSOptions=nil, skipping certificate stat. --tlsverify=false would enable TLS.
2. [config/config.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/config/config.go): Dir uses DOCKER_CONFIG; SetDir fixes parsed override. LoadDefaultConfigFile opens config.json, warns/continues on errors and discovers store when ContainsAuth=false. Exact validated bytes are required; warning is failure. [configfile/file.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/config/configfile/file.go): LoadFromReader retains empty AuthConfig entries; ContainsAuth checks store nonempty OR helper-map length OR auth-map length. One empty object therefore prevents discovery without credentials; empty auths does not. Traced version path does not retrieve credentials.
3. [credentials/default_store.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/config/credentials/default_store.go) and [default_store_linux.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/config/credentials/default_store_linux.go): default discovery LookPaths pass and a docker-credential helper. Discovery itself is path lookup, not helper execution. Sentinel skips both. No generic helper-disable flag is assumed.
4. [command/cli.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/command/cli.go): Initialize loads config/store/resolver/telemetry; default skips stored GODEBUG. Separate lazy initialize constructs API client/pings. HooksEnabled accepts DOCKER_CLI_HOOKS=false. Default endpoint registration is Docker; transitive additions need audit.
5. [defaultcontextstore.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/command/defaultcontextstore.go): GetMetadata(default) resolves memory metadata, containing no otel field. TLSOptions=nil avoids TLS body reads. Resolution constructs host address without connecting. Extra registered endpoint resolvers would run and need exclusion. [store/store.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/context/store/store.go): New constructs path-backed objects; it does not create/read directories.
6. [telemetry_docker.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/command/telemetry_docker.go): dockerExporterOTLPEndpoint reads context metadata and DOCKER_CLI_OTEL_EXPORTER_OTLP_ENDPOINT. Virtual default plus absent override yields empty endpoint; both dockerMetricExporter and dockerSpanExporter return nil before OTLP/gRPC construction. This precise branch is the no-export basis, not an unproven OTEL_SDK_DISABLED/OTEL_*_EXPORTER knob.
7. [telemetry.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/command/telemetry.go): providers/resources still initialize UUID, service name, environment-resource and SDK detectors. No exporter/reader is installed on the above branch, including for deferred meter Shutdown. Entropy/runtime work remains; do not call all telemetry disabled. [telemetry_utils.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/command/telemetry_utils.go): command instrumentation is wrapped inside PersistentPreRunE, bypassed by version.
8. [cmd/docker/docker.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cmd/docker/docker.go): Initialize precedes ExecuteContext. Exact argv leaves no subcommand/completion, skipping plugins; hooks require subcommand+terminal. Help is installed, not invoked. Root version template avoids daemon-querying version subcommand.
9. [cloud.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cmd/docker/cloud.go): unchanged cloud flag returns before discovery/provisioning. [aliases.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cmd/docker/aliases.go): alias map empty. [builder.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cmd/docker/builder.go): forwardBuilder matches build/builder/bake/image-build, not empty args; returns before ServerInfo/buildx lookup.
10. [cli/cobra.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/cli/cobra.go) retains parsed flags. [vendored Cobra command.go](https://raw.githubusercontent.com/docker/cli/v29.9.1/vendor/github.com/spf13/cobra/command.go): execute prints version and returns before preRun initializers, validation, persistent hooks and RunE. Thus root help/isSupported/lazy daemon calls are not reached on this path.

Traced functions prove isolation/sentinel/default/no-exporter/cloud-plugin bypass and version return. Whole linked init/constructor closure is unproved: Go init precedes main, including imported SDK/gRPC/built-ins. Selected command-registration/UUID/resource fetches unavailable. Remaining finite audit: registration entry, extra RegisterDefaultStoreEndpoints callers, linked init/constructor external I/O/build differences; alternatively explicitly accept normal matching upstream-library behavior. If unacceptable, stop without real execution.

Allow ordinary runtime/public mappings/loader metadata, clocks/rlimits, threads/signals, terminal/entropy and possible CPU/cgroup reads; exact linkage unknown. No zero-syscall claim. Excludes old HOME/config/context/credential bodies, daemon/network, helper/plugin children/cloud.

## Minimal later source and exact tool plan

No material product mode/observer-config change. Prefer finished reviewed owner clock/ownership via verified bootstrap without expanding authority. Otherwise a small independently frozen/reviewed stdlib-only controller, no project imports or recursive-loader copy. Self-hash is no external trust anchor.

Future source `docs/evidence/task-6/controller-cli-material-20261025.py`, no arguments; generated mocks `docs/evidence/task-6/test-controller-cli-material-20261025.py`. Interfaces: reviewed conservative D1 clock, secure fixed artifacts, retained child owner, bounded pipe/terminal recorder. Not implemented; freeze/review before exact call.

Future fixed tool skeleton, NOT admitted:

```
exec_command({
 cmd:"exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S -B /home/postedism/Desktop/Warden/docs/evidence/task-6/controller-cli-material-20261025.py",
 workdir:"/home/postedism/Desktop/Warden",shell:"/bin/bash",
 login:false,tty:false,yield_time_ms:1000,max_output_tokens:2000
})
```

Bind JSON, bash/env/Python/controller identities/hash; verify exec preserves PID/birth, charging shell/env startup. Docker receipt does not prove launchers. No preamble/dynamic args/retry. Yield is not timeout. Wait only on returned session; save independent raw tool terminal/exit, never manufacture outer success.

D1 charges full command birth through interpreter/bootstrap/verification/artifacts/spawn/collection/finalization. Reject unknown/exhausted at earliest trusted entry before intent/config/target. No pre-interpreter physical-stop guarantee; queue delay excluded/unbounded. Reviewed integer tick/dual-clock/namespace semantics required; suspend/offset changes never extend phases.

One attempt: from conservative birth run end20s, TERM22s, KILL25s, terminal/record30s. At20 cease target work/enter termination handling; TERM no later22, KILL no later25, reap/record by30. Setup consuming run window means no spawn. Success requires expected 29.9.1 version line, exit0, EOF AND known wait, no warning/overflow/timeout/identity change, and independently known timely outer tool exit. Output alone is insufficient.

Retain owner/spawn_pending before Popen; partial constructor/exec handshake can mean unknown child. Signal only owned handle/group, no PID discovery/killall/retry. Failure retains/stops; unknown is sticky, no cleanup/new charge/observer/private/guard. Never convert late/unknown to success.

Resources: supervisor soft AS128MiB/CPU5/FSIZE64KiB; child AS256MiB/CPU5/FSIZE64KiB before exec. Validate inherited ceilings first; parent hard AS must permit child256, no privileged raise. Candidate aggregate384MiB/CPU10 within native1GB/user16GB/CPU ceilings subject to confirmation; AS is not RSS. Output64KiB/receipt16KiB/tiny config; collector bounds pipe independently of FSIZE. No concurrent observer; viability unknown.

Generated fake clock/proc/resource/Popen/pipe/file cases only: exact argv/env; sentinel/mode/link/inode/ancestry/replacement/preexistence; deficient ceilings; startup20/30/tick/namespace; suspend at each phase; partial Popen/no retry; output65536/65537/EOF-wait ordering; version vs warning/nonzero/signal/late; TERM/KILL/reap unknown; source/binary/config substitution/missing tool terminal. Mocks do not prove Go viability; separate source/mock/exact-call review.

## Decisions and finite alternatives

Receipt proves local /usr/bin/docker47353784B/root0/single-link0755/SHA256 `32d26c4b23b14f4bd223338a10df671b8a247e69d959c2df01a01e94881705d1` and package `5:29.9.1-1~ubuntu.26.04~resolute` correspondence only. Not vendor attestation/source equivalence. Minimal trust choice: accept administrator-controlled installation + matching normal upstream/library behavior, recheck pinned identity/exclusive writer; otherwise obtain authenticated package/build provenance. No infinite supply-chain speculation.

NEEDS_CONTEXT: close/accept provenance+init; freeze controller/D1 clock; bind launcher/tool terminal; confirm ceilings/exclusive writer; source/mock/exact-call review then separate admission. Success means version startup only, not ls/inspect/observer/Task6 completion.

If AS256 fails (hypothetical), stop. Least later envelope candidate is observer256+CLI512+outer128=896MiB, with CPU ceilings retained. Go512 unknown; new source/mock/review/admission, never blind cap ladder.

Root-requested comparison: current ReadOnlyDocker allows scoped image/container list and inspect only list-discovered IDs. Four stdlib Unix HTTP GET forms could replace it: `/vX/images/json?all=1&filters=...`, `/vX/containers/json?all=1&filters=...`, `/vX/images/{id}/json`, `/vX/containers/{id}/json`. [Official API1.45](https://docs.docker.com/reference/api/engine/version/v1.45/) is a schema candidate, not proven host compatibility: freeze X by review; no extra negotiation request/guess from CLI version. Require exact project/OLD_LABELS filters AND response-label binding, per-kind/query-scoped ID provenance, ID/label recheck on inspect, fixed socket/no redirect/proxy/TCP/retry, strict framing/header limits/total1MiB, absolute remaining deadline per I/O, compatible return shapes. No generic mutation/API framework.

Only temporary narrow recovery.docker replacement; shared recovery/guard/eight bindings unchanged. Root reports full_postflight azure_guard is Python in-process/no hidden CLI (not independently checked), so observer CLI can be removed entirely. Trade config/helper/Go-child/terminal gates for socket/framing/schema/label proofs. Choose separate small source/fixtures/review only if materially smaller; no switch authority. No actual daemon/host-network/k3s/iptables/VM/GPU/fees/Q release.
