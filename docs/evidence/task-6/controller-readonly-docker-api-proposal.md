# Four-GET adapter — NEEDS_CONTEXT

2026-10-25. Subagent design, not human/actual/admission. Only ignored proposal written; no source/Git/tests/native/socket/CLI/children. No claim CLI256 failed. Task6/Goal OPEN; original3/5/caps/Q5/history unchanged; invoker owner untouched.

**Contract.** Fix API1.45 as contract floor, not historical minimum. No negotiation/downgrade/_ping/version. [Schema](https://raw.githubusercontent.com/moby/moby/v26.0.0/api/swagger.yaml): four routes/all=true/labels/list arrays/inspect objects; unsupported version400. Not installed-server provenance.

Only existing exact adapter inputs map to:

```
image ls      /v1.45/images/json?all=1&filters=F
container ls  /v1.45/containers/json?all=1&filters=F
image inspect /v1.45/images/sha256:HEX64/json
container inspect /v1.45/containers/HEX64/json
```

F: percent-encoded compact JSON `{"label":["k=v",...]}`, sorted keys, only `{project:warden}`/verified OLD_LABELS. IDs: image `sha256:[0-9a-f]{64}`, container `[0-9a-f]{64}`. [MatchKVList](https://raw.githubusercontent.com/moby/moby/v26.0.0/api/types/filters/parse.go) requires all pairs. Independently require every returned Labels pair; mismatch fails, never silently filters into absence. Lists arrays≤1000, valid IDs/no duplicates; null fails.

Atomically replace per-kind/per-scope ID→query proof after full valid list. Failure invalidates adapter. Inspect requires current same-kind membership, exact Id, Config.Labels matching retained qualifying scopes. No names/prefixes/old IDs;404/change fails. Existing lock/writer assumption remains, not atomic snapshot proof.

Compatibility: scoped_ids `.split()` gets LF-joined IDs/empty string; owned_inspect gets `[validated_object]` JSON≤1MiB. Preserve fields/types, downstream checks. Only temporary recovery.docker replacement; shared recovery/guard/product8 unchanged. full_postflight uses in-process azure_guard.preflight, eliminating observer CLI.

**Transport.** One fresh AF_UNIX SOCK_STREAM/request, no retry/pool/proxy/TCP/TLS/DNS/env/credentials. Exact request bytes:

```
GET <approved URI> HTTP/1.0\r\nHost: docker\r\nConnection: close\r\nAccept: application/json\r\n\r\n
```

No body/CL/TE/Accept-Encoding/auth/upgrade; Host never resolved. Raw header incl.status/delimiter≤65536B; body≤1048576B; total≤1114112B. Read at most remaining+1, never allocate from CL. Strict CRLF/token names/no obs-fold/control/whitespace-before-colon. Accept only HTTP1.0/1.1 status200; reject1xx/redirect/errors. Require unique Content-Type application/json, optionally charset=utf-8. Content-Encoding absent/identity only; Connection absent/close only. Reject all TE/Trailer/Upgrade and duplicate CL/Content-Type/Content-Encoding/Connection case-insensitively. Optional CL must be single `[0-9]+`, bounded, exactly matching body; no commas/signs. Require real EOF even with CL, never timeout/reset. Strict UTF-8, one complete JSON value, no trailing nonwhitespace/duplicate keys/NaN; then shape/label checks. Failure yields no partial result.

[Go1.26 server](https://raw.githubusercontent.com/golang/go/go1.26.0/src/net/http/server.go) chunkWriter.writeHeader closes HTTP1.0/close connections; unknown length for HTTP<1.1 closes without chunking. [Docker WriteJSON](https://raw.githubusercontent.com/moby/moby/v26.0.0/api/server/httputils/httputils.go) sets JSON and encodes one value. Supports subset design, not actual installed-build/middleware compatibility. [RFC9112 §§6–9](https://www.rfc-editor.org/rfc/rfc9112.html) prohibits TE to HTTP1.0 but warns close-delimited success cannot distinguish premature network termination. Absent-CL EOF+complete JSON therefore relies on trusted single-value server behavior; it does NOT prove handler completion. If independent transport-length completeness is required, require CL instead. Closing on timeout does not prove daemon work stopped; retain failure/no retry.

Prefer stdlib socket subset. http.client still needs Unix override, raw-header/duplicate limits, absolute deadlines and EOF-after-CL; adds parser adaptation cost. No generic HTTP/TLS framework.

**Trust/time.** Fix `/run/docker.sock` only after controller verifies original `/var/run/docker.sock` via exact root-owned `/var/run`→`/run`; no arbitrary realpath. Pin non-writable root ancestry/socket dev/ino/uid/gid/mode: socket/uid0/no other-write/approved group-write. Recheck around connect/response; SO_PEERCRED uid0, no PID scans/chmod. UID/inode cannot attest executable or eliminate connect race; trust administrator daemon/no replacement. Source allowlist, not socket permissions, restricts mutation.

Reviewed D1 clock/timeout1..30: end=min(now+timeout,deadline.end-10), require>10s; I/O cutoff=end-10, close/validate=end-5, return=end. Check each connect/send/recv/parse/serialize; nonblocking waits use remaining absolute budget. No makefile/unbounded reads. Suspend/namespace uncertainty refuses. Retain owner before connect/finally close; unknown closure/clock fails. Outer tool terminal proof remains.

**Fake cases only:** URIs/AND/labels/IDs/kind/stale/404; atomic list/1000/format; partial sends/delimiter splits/limits±1; duplicate/TE/CL/encoding/status/JSON; EOF/reset/trickle; deadlines/suspend; inode/peer/mode; close failure/no retry/context restoration. No socketpair/server/process.

**Later material.** Freeze/review source/exact-call first; one controller command30s: I/O20/close22/receipt25/terminal30, CPU5/AS128MiB/output64KiB. Exclusive public material prefix, no preprobe names/private/guard/new charge. Record hashes/counts/shapes/status/peer/clock, never raw inspect Config.Env. Four slots: project image/container lists, inspect deterministic listed image/container. Missing IDs: NOT EXERCISED, not PASS; no creation/old-ID fallback. OLD_LABELS fake-tested; extra requests need separate fixed plan. Failure stops/retains, no cap/version ladder.

NEEDS_CONTEXT: socket/daemon provenance and1.45 compatibility; accept EOF+JSON assumption or require CL; freeze clock/source/tool trust anchor; rule adapter/fixture scope; separately admit material. No actual compatibility or AS viability claim.
