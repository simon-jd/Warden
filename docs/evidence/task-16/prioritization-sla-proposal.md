# Task16 PHASE1 — NEEDS_CONTEXT

HEAD970f0844574ec562ee9f69142675f5d2ee767d03. Only this ignored proposal written; no source/index edits, Git/tests/Go/Docker/feeds/services/children. Read brief, last6 docs/STATUS paragraphs, Task6 blocker, go.mod/existing profile; no Finding/Ranked integration found. STATUS.md lookup failed; docs/STATUS.md read.

Queued during root Task6 revision/new namespace; old5/5/consumedattempt untouched. Root owns source/index; PHASE2 approval required.

## API decisions

Only vuln/{prioritize.go,feeds.go,sla.go,prioritize_test.go}, stdlib; unchanged module/dependencies; literal profile extension below. No CLI/persistence/scheduler/dashboard; live integration pending.

Finding fields: ID string(unique finding identity,1..256bytes), CVE string(canonical CVE-year4-4..19digits), Severity string(empty/low/medium/high/critical), CVSS float64(finite0..10), Exposed bool, FirstSeen time.Time, FixedAt *time.Time. IDs unique; repeated CVEs allowed; no normalization. FirstSeen from trusted history, never feed date.

Ranked fields: Finding(value copy incl independent FixedAt), KEV bool, EPSS float64, EPSSKnown bool. Exact exported Prioritize(fs []Finding, epss map[string]float64, kev map[string]bool) []Ranked. Copy inputs; stable comparator EXACTLY KEVtrue first, EPSS descending, CVSS descending, Exposedtrue first. Full ties retain input order. Missing EPSS=0/EPSSKnownfalse, known0=EPSSKnowntrue with equal sort weight. Missing/false KEV means catalog absence only. Nil maps valid.

ValidateInputs(fs,epss,kev) error validates finding shape/CVSS/severity, nonzero FirstSeen, FixedAt>=FirstSeen, unique IDs, canonical map keys and finite EPSS0..1. Prioritize calls same validation and returns nil on invalid inputs since mandated signature cannot return error; callers validate first for reason. Empty input may return nil. Future-time checks belong to SLA. ROOT CHOICE: approve documented nil-on-invalid convention or specify another before code.

Bare maps lack dates: caller must check snapshot Fresh(now) before passing Scores/CVEs. Missing EPSS still ranks with unknown diagnostic; stale/failing sync is explicit error, never a successful empty feed. No stale fallback/cache.

## Feeds

EPSS snapshot: scores, publish UTC date, model version, RetrievedAt, final URL. KEV snapshot: CVEs, catalogVersion/dateReleased, declared/actual count, RetrievedAt/final URL. Parsers take bounded io.Reader/source/retrieval time; whole snapshot or error.

Fixed public HTTPS sources: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz and official publisher mirror https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json . Mirror provenance explicit; no fallback/live success claim. Based on brief research.

Fetch: context total<=20s or earlier caller deadline, TLS handshake<=5s, headers<=1MiB; status200; <=2redirects, HTTPS/original hostname only; no retries/credentials/environment proxies. Close every response. Disable automatic HTTP decompression; handle EPSS gzip explicitly. Compressed<=32MiB, expanded CSV<=128MiB, <=1Mrows, each record<=4KiB via bounded line read before CSV parse. KEV JSON<=16MiB/100kentries. Read limit+1 to detect excess; finish gzip to EOF(checksum/truncation). No CSVReadAll/unboundedReadAll. Reject duplicate CVEs, truncated/empty catalogs, malformed policy fields, multiple trailing JSON values, duplicate required JSON keys, count mismatch. Strings<=4KiB; unknown future KEV fields accepted. Validate all schema-required catalog/entry fields from brief; dates dateAdded/dueDate valid and dueDate>=dateAdded. CISA dueDate never drives local SLA.

EPSS requires model/publish-date comment and cve,epss,percentile header; supports CRLF/BOM/header order; validates finite probability/percentile0..1, never ranks by percentile. Reject repeated/conflicting metadata, invalid CVEs/dates.

Fresh(now): reject zero/future retrieval; both retrieval ages<=48h. EPSS publication valid UTC midnight, not future UTC date, age<=48h. KEV dateReleased is publisher RFC3339 timestamp, <=retrieval; may be older48h because unchanged catalog need not be republished daily. KEV dateAdded cannot exceed release's UTC day. Fresh retrieval cannot rescue stale EPSS; snapshots report provenance, not publisher authenticity.

## SLA/metrics

SLADuration(f,isKEV):7*24h if KEV OR Severitycritical OR CVSS>=9; else30*24h if Severityhigh OR CVSS>=7; else90*24h. Severity/CVSS can independently raise urgency. Local project policy, not CISA deadline/compliance. Current enrichment anchors to FirstSeen.

EvaluateSLA(f,isKEV,now func() time.Time) (SLAResult,error), injected fake clock sampled once. Reject nil clock, zero now/FirstSeen, FirstSeen>now, future FixedAt, FixedAt<FirstSeen; validate normal finding fields. Due=FirstSeen+duration, elapsed24h across DST, UTC output; reject unrepresentable due/overflow. Inclusive deadline: open exactlyDue not breached, Due+1ns breached; fixed exactlyDue meets, later fixed is closed breach. Fixed findings stop accruing open time. Result: due/duration/evaluation/open-or-closed/breach. No hidden clock/sleep.

Summarize(fs,kev,now) validates whole batch, samples clock once; invalid batch errors without partial metrics. Return OpenCount/FixedCount/OpenBreaches/FixedBreaches, MedianRemediation time.Duration and HasMedianfalse without closures. Median uses valid FixedAt-FirstSeen durations only, explicit supplied cohort/denominator, sorted/overflow-safe even midpoint; zero duration valid. No real history: no docs/evidence/vuln-sla.md; fixtures only docs/evidence/task-16/, labeled subagent-generated.

## Fixed profile and finite TDD

scripts/firecracker_code.py: add ONLY literal vuln-unit in mode allowlist and task-label tuple, plus exact command `umask 0077; exec [existing absolute cached Go1.26.10] test -p 1 -count=1 -v ./vuln`. No generic arguments. Keep image pin, UID1000:1000, cap-dropALL/NNP/readonly source+root/networknone/privateIPC-CG, memory=swap2GB/CPU2/PIDs256/tmpfs256MiB/GOMAX2/GOMEM1500 and offline deps/cache paths. No hostGo/gofmt/oldgo/test-postgres, PG/material/new3GB, source loader/controller/charge schema. Existing derived unit cache only.

Exactly3 prospective executions: (1) genuine RED: complete behavior tests plus type/API skeletons/stubs, actual assertion failures, not manufactured compilation error; (2) focused GREEN implementation; (3) same command on frozen identical source, affected ./vuln only. Preserve failures; fourth run needs root ruling. Required TestKEVRanksFirst, TestEPSSBreaksTies, TestSLABreachDetected(fake clock). Bounded table subtests: complete comparator/ties/no-mutation/unknown0/invalid values; SLA thresholds/equality/DST/invalid times/median; feed caps/truncation/duplicates/dates/freshness/status/redirects/cancellation. HTTP fixtures in-memory RoundTripper; any server loopback only inside networknone container. No live feeds/fuzz campaign.

Each actual run needs fresh existing scoped lock/guard: R+ALLQ+own-image accounting+512MB<=12GB; Q5GB stays releasedfalse, native1GB/service3GB guard<=16GB. Preserve ownedIDs/labels/container-terminal/absence/sixsysctls. Unknown external operation stops without replay/broad cleanup. Preserve all brief exclusions.

Before tests root approves exact native recorder body: inline stdlib supervisor around single existing profile command; outer240s overall including original held180s; CPU20/AS256MiB/FSIZE4MiB/combinedlog<=2MiB and finite<=48polls of<=5s. Retain raw commands/results/owned cleanup. Unknown/pending operation stops. No startup guarantee/new recorder/execution.

After PHASE2: current five-path diff/source hashes, complete actual new results; append-only .superpowers/sdd/2-warden-security-plan/task-16-report.md and public docs/evidence/task-16/substage-report.md record TDD/allfailures/resource-cleanup facts+limits/selfreview/pending integrations. Separate source/evidence local commits after handoff, requested source message unchanged. Root reads/reviews; no reviewer child. Daily job/live feed/dashboard/real remediation metrics, original Task16 and Goal remain OPEN. No Task6/3/4 acceptance/cloud/GPU/paid/push/publication.
