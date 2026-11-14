Task10 DNS score component — implemented, FIRST_GREEN NOT EXECUTED

Implementation-start BASE4cbabd2264d74b73919b61e40ef11b1308b40aa2. ROOT review/freeze attestation1916aad69d310b690cea6ec58212399b6da72f31 is its documentation-only successor. No author Git/index commands or commit. Scope: detect/dns_exfil/score.go only; frozen exfil_test.go remains9433B SHA25678b27d2e00497fd4eefd26e87272b5d9f601ae252f0436a84e784c460817a585. No README or new tests.

Score now validates the complete batch before evaluating any result: one nonempty tenant/run, nonzero type/time, legal ASCII LDH names, one optional root dot, label/wire limits, no IP literals, and PSL registrable suffix required. Case folding follows ASCII validation. Pinned x/net/publicsuffix includes private suffixes. Shannon entropy counts all subdomain characters except dots, excluding registrable domain; no subdomain contributes zero. Every question/type/repetition contributes equally to the mean.

Owned observations are sorted by UTC time and entropy for deterministic ties; original input is untouched. Compensated sliding sums enforce count>30 and mean>3.5 with open lower bound(t-60s,t]. Complete equal-timestamp groups are included before checking. Both arrival and expiration events within the observed interval are checked: expiry of a low-entropy question can itself create the earliest crossing. No extrapolation after the last observation. O(n log n) time/O(n) storage, no network I/O. Collector-side input/storage bounds and invalid/lost telemetry reporting remain external requirements; nil conflates invalid/no-alert by the agreed interface.

TDD RED: ROOT ruling docs/evidence/task-10/score-first-semantic-red-attempt2-20261026/root-ruling.json and complete output.txt/receipt.json read. Native a4a752/session96698 ->58336a known0; actual Go return1; whole12.101651713s, package0.010s. Exact fixture output: SCORING_FIXTURE_OK payload_bytes=4096 queries=128 span=31.75s first31_mean=4.529606776303; then expected DNS score alert, got nil, TestDNSScoreTXT4KiBAlert FAIL. Raw294B SHA256b9f035ef569870515a6b07c9b64021bd0ba89d62225f24907dd16609021cb3e8. ROOT accepted semantic RED with known process cleanup. Earlier18b94d preflight failure remains separate; RED callers2/2 SPENT, no replay. Retained RED namespace60510208B stays charged.

FIRST_GREEN prepared only at task10-dns-score-first-green-20261026/{caller.py,limit_child.py,isolated.go.mod,freeze.json}. Exact nine existing top-level TestDNSScore names are derived from frozen tests and embedded in gate; command selects ^TestDNSScore. Requires each started and PASS exactly once, Go0, single expected package ok, standalone PASS, original fixture marker, and no FAIL/SKIP/panic/fatal/build/no-test marker. Native final0 after fsync and process cleanup also required. No GREEN output/result exists yet.

ROOT-only prospective invocation after FULLREAD/fresh admission:
 timeout --signal=KILL 90s /usr/bin/python3 -I .superpowers/sdd/2-warden-security-plan/task10-dns-score-first-green-20261026/caller.py --root-admitted-first-green
Only fresh paths, selection/result gate/phase/base attestation differ from consumed RED body. WNOWAIT-held signaling/reap, work80/cleanup87/final89/whole90s, Go20s, raw64KiB, AS/CPU/serial child limits, work-owned telemetry off modes, offline fixed SDK/modules, and retained-work charging unchanged. Disk monitoring remains NOT hard quota. No author Go/build/test/formatter/network/Docker/metadata/cloud/children executed.

Self-review: confirmed full-batch rejection before early return, complete ties, exact open lower boundary, private/multi-label PSL handling, case validation and no input writes. Static inspection only; Go compilation/GREEN remains unverified. Mandatory independent review follows actual GREEN before component acceptance. Full Task10 stays OPEN: original packet transport/collector, HTTP Host/TLS SNI, tenant/run binding, Cilium/Envoy/runc network attachment and real bypass/cleanup acceptance are not implemented or replaced by scoring.

Budget: original cumulative196608 of262144, remaining65536 for this source growth/report/new four-file packet and future append/review. No deletion/reset credit; old UNKNOWN9GB/Q5GB and all old holds persist. ROOT must refresh12GB/16GB before any actual. This report will append exact GREEN/covering evidence only after execution. STOP for ROOT review/admission.


## Actual FIRST_GREEN evidence append — 2026-10-26

The original4394-byte preparation prefix is preserved exactly (SHA256675c50072528a940c83afde32977fa11651e4bc5a407ec69fc8d135893ff77dd). This append records subsequent ROOT execution; no author rerun or source change. FIRST_GREEN evidence is accepted, while independent Spec+Quality review and component acceptance remain PENDING.

ROOT native e9ecf9/session13047 ->693170/79e9ca running ->c0f8a7 exit0; actual Go0, package0.011s, whole20.411656372s. Nine top-level/34 including subcases PASS; zero FAIL/SKIP. Complete combined stdout/stderr follows, unchanged4740B. It covers the 4KiB TXT-name scoring fixture, normal CDN controls, strict thresholds/repeats/all types, per-query mean, sliding boundaries, canonical/PSL/private suffixes, no exemption, input immutability/earliest result, invalid/mixed batches and complete timestamp ties. It does not demonstrate actual DNS packet transmission.

Exact admitted caller command (repository cwd, UID1000, /bin/bash, login:false, tty:false, require_escalated):
```sh
timeout --signal=KILL 90s /usr/bin/python3 -I .superpowers/sdd/2-warden-security-plan/task10-dns-score-first-green-20261026/caller.py --root-admitted-first-green
```
Exact underlying Go argv from the owned launch record:
```json
[
  "/home/postedism/Desktop/Warden/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/go",
  "test",
  "-mod=readonly",
  "-p=1",
  "-vet=off",
  "-count=1",
  "-parallel=1",
  "-timeout=20s",
  "-v",
  "-toolexec=/usr/bin/python3 -I -S /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-dns-score-first-green-20261026/limit_child.py tool",
  "-exec=/usr/bin/python3 -I -S /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-dns-score-first-green-20261026/limit_child.py test",
  "-run=^TestDNSScore",
  "./detect/dns_exfil"
]
```

Pins after ROOT verification: score.go0a9e6854c04985ec8dc517191016df2949af5ba8c85849e4b1bbe217f46053d3; tests78b27d2e00497fd4eefd26e87272b5d9f601ae252f0436a84e784c460817a585; caller09f3d88b9053f454a0cef18e7ac326de0fa9906d1a7350fef2b834385b6d61ea; freeze1442cc8e3eb83ad1c764a2c214d0bacc05faf3c23263cafb8d925a99f0a94ef6. All17 frozen inputs, stage, SDK/publicsuffix and both work-owned off-newline modes unchanged.

Complete raw output SHA25600c8db98dc44986dcd0f72f98c094c681629048e8089904a31538f6a168df8f4:
```text
=== RUN   TestDNSScoreTXT4KiBAlert
    exfil_test.go:126: SCORING_FIXTURE_OK payload_bytes=4096 queries=128 span=31.75s first31_mean=4.529606776303
--- PASS: TestDNSScoreTXT4KiBAlert (0.00s)
=== RUN   TestDNSScoreNormalCDNNoAlert
=== RUN   TestDNSScoreNormalCDNNoAlert/d111111abcdef8.cloudfront.net
=== RUN   TestDNSScoreNormalCDNNoAlert/a1.g.akamaiedge.net
=== RUN   TestDNSScoreNormalCDNNoAlert/assets.example.com
=== RUN   TestDNSScoreNormalCDNNoAlert/www.example.co.uk
--- PASS: TestDNSScoreNormalCDNNoAlert (0.00s)
    --- PASS: TestDNSScoreNormalCDNNoAlert/d111111abcdef8.cloudfront.net (0.00s)
    --- PASS: TestDNSScoreNormalCDNNoAlert/a1.g.akamaiedge.net (0.00s)
    --- PASS: TestDNSScoreNormalCDNNoAlert/assets.example.com (0.00s)
    --- PASS: TestDNSScoreNormalCDNNoAlert/www.example.co.uk (0.00s)
=== RUN   TestDNSScoreStrictCountAndRepeatedAllTypes
--- PASS: TestDNSScoreStrictCountAndRepeatedAllTypes (0.00s)
=== RUN   TestDNSScoreStrictEntropyAndPerQueryMean
--- PASS: TestDNSScoreStrictEntropyAndPerQueryMean (0.00s)
=== RUN   TestDNSScoreSlidingWindowBoundary
--- PASS: TestDNSScoreSlidingWindowBoundary (0.00s)
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.EXAMPLE.CO.UK.
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnop.qrstuvwxyz234567.example.com
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnopqrstuvwxyz234567.customer.cloudfront.net
--- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.EXAMPLE.CO.UK. (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnop.qrstuvwxyz234567.example.com (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnopqrstuvwxyz234567.customer.cloudfront.net (0.00s)
=== RUN   TestDNSScoreEarliestWindowAndInputUnchanged
--- PASS: TestDNSScoreEarliestWindowAndInputUnchanged (0.00s)
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_run
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/zero_qtype
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_label
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/double_terminal_dot
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/overlong_label
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/overlong_name
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/unicode
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/trailing_hyphen
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/underscore
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/no_registrable_domain
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/ip_literal
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/mixed_tenant
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/mixed_run
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/zero_time
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_name
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/leading_hyphen
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/whitespace
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_tenant
--- PASS: TestDNSScoreRejectsInvalidOrMixedBatch (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_run (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/zero_qtype (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_label (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/double_terminal_dot (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/overlong_label (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/overlong_name (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/unicode (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/trailing_hyphen (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/underscore (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/no_registrable_domain (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/ip_literal (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/mixed_tenant (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/mixed_run (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/zero_time (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_name (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/leading_hyphen (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/whitespace (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_tenant (0.00s)
=== RUN   TestDNSScoreTimestampTiesUseCompleteWindow
--- PASS: TestDNSScoreTimestampTiesUseCompleteWindow (0.00s)
PASS
ok  	warden/detect/dns_exfil	0.011s
```

Complete caller receipt:
```json
{
  "absence_basis": "ECHILD only under exact new-session + local subreaper + frozen no-setpgid/setsid child chain; no generalized host/quiescence authority; unknown adoption/group escape is STOP",
  "base_head_root_attested": "1916aad69d310b690cea6ec58212399b6da72f31",
  "cleanup_error": null,
  "combined_output_bytes": 4740,
  "elapsed_seconds": 20.411656372016296,
  "go_returncode": 0,
  "leader_reaped_after_all_signals": true,
  "output_sha256": "00c8db98dc44986dcd0f72f98c094c681629048e8089904a31538f6a168df8f4",
  "owned_group_absent": true,
  "peak_observed_work_allocated_bytes": 210771968,
  "process_cleanup_ok": true,
  "reason": null,
  "result": "COMPONENT_GREEN",
  "retained_accounting": "full reserved work allowance until separately bounded inventory",
  "retained_work_path": "/home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-dns-score-first-green-20261026/green-run/work",
  "scope": "DNS scoring only; no full Task10 acceptance",
  "work_removed": false,
  "work_retained_charged": true
}
```

Complete ROOT acceptance ruling and counters:
```json
{
  "at": "2026-10-26T10:01:53.758938+00:00",
  "decision": "ACCEPT_FIRST_GREEN_EVIDENCE_PENDING_INDEPENDENT_REVIEW",
  "native": "e9ecf9/session13047 ->693170/79e9ca running ->c0f8a7 known0",
  "Go_rc": 0,
  "top_level_PASS": 9,
  "PASS_including_subcases": 34,
  "FAIL_SKIP": 0,
  "whole_seconds": 20.411656372016296,
  "package_seconds": 0.011,
  "raw_bytes": 4740,
  "raw_sha256": "00c8db98dc44986dcd0f72f98c094c681629048e8089904a31538f6a168df8f4",
  "all17_frozen_inputs_source_staging_SDK_unchanged": true,
  "work_owned_telemetry_modes_off": true,
  "process_cleanup": "WNOWAIT held leader through all signals, then explicit known reap and same-group ECHILD under frozen new-session/subreaper chain; native0 finalized after fsync, no host/Task16 authority claim",
  "namespace_final_allocated": 107708416,
  "namespace_files": 1481,
  "namespace_dirs": 269,
  "largest_file": 13366088,
  "observed_peak_work": 210771968,
  "namespace_retained": true,
  "new_UNKNOWN_memory": false,
  "old_UNKNOWN9GB_Q5GB_all_holds": "unchanged",
  "counters": {
    "RED_callers": "2/2 SPENT: old preflightfailure and genuineRED preserved",
    "FIRST_GREEN": "1/1 SPENT accepted",
    "independent_review": "not yet performed",
    "author_preparation": 241664,
    "author_original_cap": 262144,
    "remaining": 20480
  },
  "next": "Report append only, root two-pathSOURCE commit, original SDD initial independent Spec+Quality reviewer, no suite replay",
  "full_Task10": "OPEN original network/collector/SNI/Host/Cilium/Envoy/runc actual acceptance; not replaced by scoring",
  "provenance": {
    "source": "root_agent_in_existing_user_scope",
    "human_response": false
  }
}
```

Public evidence directory: docs/evidence/task-10/score-first-green-20261026/. Exact requests/results are retained in native-requests-and-results.json, SHA256b54ea2f4219de735788d30d62b8f7c976534debfa80e9d03fc679df1818a8e33. Receipt SHA256e5d101ab33127b54e0344ed4d5cd5e99d5fd35fb1702cd5e9deff96ab92972c3; ruling SHA256c65c86b39544394734cc15c331bee3daeeb724369c7db097cae11d7bc81b913d. Original report copy is author-preparation-report.md. No raw output omitted above.

Resource/closure limits: admission27d125 counted11,018,805,760B against12GB and15,777,995,264B against16GB. Retained GREEN namespace107,708,416B (1481files/269dirs), peak observed work210,771,968B, largest file13,366,088B. WNOWAIT leader held through all signals, then known reap/scoped ECHILD and final fsync/native0; cleanup_error=null, no new UNKNOWN. This is only the frozen new-session/subreaper child-chain claim, never host/oldTask16 quiescence. Work retained/charged; old UNKNOWN9GB/Q5GB and all holds unchanged. FIRST_GREEN1/1 and RED2/2 SPENT, no replay authorized.

No source/test/formatter/Go/Git/index/child-agent changes in this final-report step. Independent Spec+Quality review is mandatory before component acceptance. Full Task10 remains OPEN: real DNS transport/collector, scheduler egress delivery, HTTP Host/TLS SNI, tenant/run network binding, Cilium/Envoy/runc attachment, direct bypass and lifecycle cleanup acceptance are not closed by these scoring tests. STOP for ROOT commit/review.

ROOT subsequently committed the two verified source files locally as e2fbb97f05f4d062e7a310f23a3907b4be127cc6; independent initial-review BASE1916aad69d310b690cea6ec58212399b6da72f31. Exact source/test pins unchanged; index empty per ROOT. Review is still pending.


R1/5 scoring fix and affected cover (2026-10-26)

INITIAL review:0 Critical/1 Important/1 Minor. I1 was batch suppression by untrusted names; M1 lacked expiration-only coverage. This appendix supersedes the earlier LDH-only/whole-batch name rejection contract. SAME independent reviewer R1 review remains pending; historical evidence is unchanged.

Score retains its API. ScoreDetailed returns Alert, RejectedNames (original zero-based indexes, including rejections after an early alert), and InvalidMetadata. Identity/time/nonzero-QType metadata is validated first; failure rejects the batch explicitly without name classification. Malformed names are excluded from count/entropy without erasing valid evidence. Their trusted times still bound the observed interval. Diagnostic reporting is implemented; collector/monitoring delivery is not.

DNS presentation names now accept byte labels, optional root dot, character/three-digit decimal escapes, ASCII folding, decoded63B-label/255B-wire limits. Root/TLD/underscore, hyphen-edge, spaces, UTF-8 octets and dotted numeric questions are not invalid merely as non-hostnames. No implicit IDNA conversion. Root/public-suffix/no-subdomain names count with zero subdomain entropy. Escaped dots remain label data for PSL and entropy. Private-PSL/no-CDN-exemption semantics remain.

M1:31 zero-entropy questions at t=0, high-entropy questions at t=30, final zero-entropy question at t=61. With31 high questions, earliest crossing is expiration at t=60; with30, count is insufficient at t=60 and the final question first crosses at t=61 (count31,mean150/31). Both assert no alert when the observation horizon still ends at t=30.

Genuine new R1 RED: docs/evidence/task-10/score-fix-r1-red-20261026/{root-ruling.json,output.txt}; c5beff/session1080 ->266e45 known0, Go1,whole20.53815835795831s. Complete742B output SHA256 6b283704d24cf3d21fbe3d27962f1a66221d350316d236af0585fb73e3763fb0 shows both healthy31/entropy5 controls followed by nil-alert assertion failures after _dmarc.example.com/com. It was behavioral RED, not an environment failure. That regression remains unchanged.

Root source commit:f73c1dae4ac47c57a202655f8ca214e76f9dc2a0; FIX_BASE:e2fbb97f05f4d062e7a310f23a3907b4be127cc6. Both source files remain frozen.

Only six directly affected top-level tests ran, named exactly in the command below: original I1 regression; invalid metadata/name distinction; rejection diagnostics with immutable input and rejected endpoint; DNS syntax/suffix controls; existing canonical/private-PSL/no-exemption controls; M1/count30 control. No unrelated prior suite replay.

Exact recorded Go argv from launch.json (JSON preserves argument boundaries):
```json
["/home/postedism/Desktop/Warden/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.10.linux-amd64/bin/go", "test", "-mod=readonly", "-p=1", "-vet=off", "-count=1", "-parallel=1", "-timeout=20s", "-v", "-toolexec=/usr/bin/python3 -I -S /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-dns-score-fix-r1-cover-20261026/limit_child.py tool", "-exec=/usr/bin/python3 -I -S /home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan/task10-dns-score-fix-r1-cover-20261026/limit_child.py test", "-run=^(TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions|TestDNSScoreRejectsInvalidOrMixedBatch|TestDNSScoreRejectedNamesAreObservable|TestDNSScoreQuestionSyntaxAndSuffix|TestDNSScoreCanonicalSuffixAndNoCDNExemption|TestDNSScoreExpirationOnlyCrossing)$", "./detect/dns_exfil"]
```

Affected-cover native:f9bf31/session11134 ->2ffbfe known0; root postflight:b5e1ee known0. Go0,package0.011s,whole20.218045359943062s;6top/19total PASS,0FAIL/SKIP. COMPLETE combined output2873B, SHA256 61a405afec19a2fb9d447148f1289d964dace933f756f506c81b1e60b180691d:
```text
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.EXAMPLE.CO.UK.
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnop.qrstuvwxyz234567.example.com
=== RUN   TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnopqrstuvwxyz234567.customer.cloudfront.net
--- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567.EXAMPLE.CO.UK. (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnop.qrstuvwxyz234567.example.com (0.00s)
    --- PASS: TestDNSScoreCanonicalSuffixAndNoCDNExemption/abcdefghijklmnopqrstuvwxyz234567.customer.cloudfront.net (0.00s)
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/mixed_tenant
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/mixed_run
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_tenant
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/empty_run
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/zero_time
=== RUN   TestDNSScoreRejectsInvalidOrMixedBatch/zero_qtype
--- PASS: TestDNSScoreRejectsInvalidOrMixedBatch (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/mixed_tenant (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/mixed_run (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_tenant (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/empty_run (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/zero_time (0.00s)
    --- PASS: TestDNSScoreRejectsInvalidOrMixedBatch/zero_qtype (0.00s)
=== RUN   TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions
=== RUN   TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions/_dmarc.example.com
    exfil_test.go:256: R1_QUALIFYING_WINDOW_OK count=31 mean=5
=== RUN   TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions/com
    exfil_test.go:256: R1_QUALIFYING_WINDOW_OK count=31 mean=5
--- PASS: TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions (0.00s)
    --- PASS: TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions/_dmarc.example.com (0.00s)
    --- PASS: TestDNSScoreQualifiedWindowSurvivesLegalDNSQuestions/com (0.00s)
=== RUN   TestDNSScoreRejectedNamesAreObservable
--- PASS: TestDNSScoreRejectedNamesAreObservable (0.00s)
=== RUN   TestDNSScoreQuestionSyntaxAndSuffix
--- PASS: TestDNSScoreQuestionSyntaxAndSuffix (0.00s)
=== RUN   TestDNSScoreExpirationOnlyCrossing
=== RUN   TestDNSScoreExpirationOnlyCrossing/high_count_31
=== RUN   TestDNSScoreExpirationOnlyCrossing/high_count_30
--- PASS: TestDNSScoreExpirationOnlyCrossing (0.00s)
    --- PASS: TestDNSScoreExpirationOnlyCrossing/high_count_31 (0.00s)
    --- PASS: TestDNSScoreExpirationOnlyCrossing/high_count_30 (0.00s)
PASS
ok  	warden/detect/dns_exfil	0.011s
```

Public evidence: docs/evidence/task-10/score-fix-r1-cover-20261026/{output.txt,receipt.json,launch.json,root-ruling.json}. These record the full resource/receipt details. Root verified17 inputs/stage/SDK/telemetry-off unchanged. All signals preceded held-leader reap, followed by scoped ECHILD; cleanup_error=null, no new UNKNOWN. Absence applies ONLY to the exact new-session/local-subreaper/frozen no-setpgid/setsid child chain, not host-wide quiescence. Unknown adoption/group escape remains STOP. Work retained/charged, not removed: namespace107728896B; observed work peak210718720B. Original90/80/87/89s deadlines,raw64KiB,AS/CPU bounds remain. Disk monitoring is not a hard aggregate quota. Old UNKNOWN9GB/Q5GB holds remain under root fresh12GB/16GB admission.

Counters SPENT:oldRED2/2 (including buildid preflight failure), FIRST_GREEN1/1, R1 newRED1/1, affectedCOVER1/1. No replay authorized. Original author cap262144B:253952 before appendix; report allocation16384->24576 (+8192); cumulative262144,remaining0. Report draft size assertions5ddb88 and d3fd62 stopped BEFORE opening a write handle; no write/Go/run occurred. This size-checked appendix alone was written; no source/test/packet changes. Original16110B prefix SHA256 5c05e246ab8ef4b8371b2db83e863adce7baeda227b32787c6a4affa9f30c2e2 stays exact.

Full Task10 OPEN: real DNS transport/collector identity, scheduler/network attachment, Cilium/default-deny, Envoy Host/SNI/tenant binding, runc/bypass/lifecycle acceptance. Next is root full-read and SAME reviewer's scoped R1 review. Affected-cover PASS does not accept the component or full Task10.
