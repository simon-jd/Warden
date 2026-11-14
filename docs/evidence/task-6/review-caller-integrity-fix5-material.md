Root verbatim archive of independent subagent scoped review; not human review. Original Task6 final round5/5. Body bytes=18230; SHA256=1b386f927cec405633c7b0e6fa2c36ae419742453e349acc36b76276de81ce76. SOURCE8bf623b / EVIDENCE2c2b869 / REVIEW_HEADaaad04b. Only scoped SOURCE/mock/exact-caller acceptance; actual gates remain root-owned.

# Original Task6 final round 5/5 — material I1 scoped re-review

## Verdicts

**Spec Compliance: PASS, within the dispatched material I1 and fix-caused-breakage scope.**

**Task Quality: Approved, within that same scope.**

**Material I1: ADDRESSED.** New findings: **0 Critical, 0 Important, 0 Minor**. These counts exclude the four previously deferred Minors; they remain open and are not silently resolved by this review. There is no approval-writer verdict in this report. That caller and its native fixture belong to the separate reviewer seat.

This is original Task6's final round **5/5**, not a new review budget or renamed phase. SOURCE/mock/exact-call-plan acceptance is not authorization to execute the caller. All actual gates, Q5, scene obligations, Task6, and the overall Goal remain OPEN. No actual admission or completion is asserted.

## Scope and method

I followed `.superpowers/sdd/2-warden-security-plan/task-6-caller-integrity-fix5-material-re-review-dispatch.md`, the existing re-review method, and the public F1–F6 rulings in `docs/evidence/task-6/controller-caller-integrity-fix5-rulings.md`. I read the complete fix5 report before relying on its claims, then independently inspected the new material caller, material fixture, the complete explicit plan replacement, the material run records, and the scoped immutable provenance. The original material I1 is the defect described in `docs/evidence/task-6/review-four-get-material-source.md`.

The review is limited to the I1 repair and concrete breakage introduced by that repair. It does not reopen production Python, native203, the previously accepted API/parser/controller implementation, old historical proof packages, the four deferred Minors, or the approval-writer issues. It does not create a new runtime capability or require a new meta-controller. The absence of newly discovered issues in this bounded review is not a claim that all possible JavaScript objects or execution environments have been proved safe.

I did not execute a candidate, fixture, caller, verifier, test, project import, or generated source snippet. Public-file reads, byte/hash comparisons and immutable Git object reads were used as review operations. No child was spawned. No source, index, Git state, private data, host resource, socket, service, or external system was changed. This ignored report is the only intended review output.

## Provenance and presentation

The proper previous-review base is `20fdff98c16d51d02cc2d9021bb373b6fb4a2dcf`; the review head is `aaad04b685a9b4e8fbece34a416e468f3d8a4728`. The implementation dispatch base is `50a8f7ca76b65348210752d7a7a93108d4237f8a`; the frozen source commit is `8bf623b6b5fc04a1d2c0a979a274cfeb3f643f51`; the evidence commit is `2c2b869cce28bdfe602e80c5f0415e41492e073c`.

The supplied package is the complete raw diff, without a collapsed presentation:

`.superpowers/sdd/2-warden-security-plan/review-fix5-material-20fdff9..aaad04b.diff`

I independently checked its 2,362,029 bytes and SHA-256 `a021357d8ab9f3a7b6661222292e8e9a5ea04135e1d61404c97c4d12fc124de8`. It contains 325 diff blocks. I checked the material new-file blocks against their file bytes and read the material source hunks and unique material evidence; repeated quoted candidate/fixture text was compared byte-for-byte with the already inspected source. I did not claim semantic review of every unrelated block or generate a replacement diff. The previous 145-block mapping is neither needed nor reopened for this raw package.

Immutable commit headers corroborate the ancestry, in reverse order from review head toward the previous-review base: `aaad04b`, `2c2b869`, `8bf623b`, `50a8f7c`, `297acc2`, `b7c694c`, `285be94`, `50b41dc`, `6bbf995`, `cc725a2`, `44757e5`, then the specified base. That history includes intervening evidence/metadata; it is not represented as a single fresh material source commit.

The full public report is `docs/evidence/task-6/controller-caller-integrity-fix5-substage-report.md`: 15,885 bytes, SHA-256 `3d567146defcc7f58a1a457484987344badd98f195ef1e6903e18561c5b19087`. The ignored report mirror is byte-identical. The artifact index is `controller-caller-integrity-fix5-artifact-sizes.json`: 96,742 bytes, SHA-256 `7c802eb45741936728fcf73713ddcecaac83578037efd1ad3d794d3bacd26532`. I independently checked 48 selected material/shared indexed rows for size, SHA, and allocated bytes. I do not elevate that bounded check into an independent audit of all 310 rows.

The root's supplied `controller-fix5-scope-check-20261025.json` records its broader 310-row, old-prefix/history, and missing-artifact checks. It was read as metadata and was not executed. The aggregate 1,988,043 logical / 2,867,200 allocated bytes and the reported net growth remain the index/root's complete-package accounting; the scope of my direct row verification is stated above. Root's three code-fence/compiled-literal format-assumption failures are disclosed metadata-checker history, not worker test runs or source changes. They must remain in the root history. During my own read-only plan extraction, an initial assumption that the fence was `js` instead of `javascript` produced an IndexError; corrected extraction then established equality. That review-reader error executed no candidate and mutated no artifact.

The material candidate is 11,526 bytes, SHA-256 `dd9553eec47723a1159bc421478cad1b9ad21a97d639f8783a2abdf700f66e13`; the material fixture is 12,699 bytes, SHA-256 `6783d92bae44aaedf1b21540aa368bd2d5ea2724715c4c9b309dfd85079baebb`. Their current bytes match the frozen SOURCE and REVIEW_HEAD blobs. I independently compared the 150 canonical Python files plus the two existing Python controllers against the baseline maps and immutable dispatch-base/SOURCE/HEAD versions; they are unchanged. This is source identity evidence, not a rerun of their tests or actual operation.

## I1 — original failure and repair

The original Important finding concerned failure-record integrity. The old `exactJSON` array branch checked dense keys but returned before the ordinary-prototype check. A dense array with a custom prototype could therefore carry an inherited `toJSON` hook. Normal response validation rejected the array, but the failure serializer could subsequently invoke the inherited hook and write a substituted object such as `{exit_code:0}` instead of preserving the actual response. The old fixture's unconditional ordinary-array cloning also erased the problematic prototype. The finding did not establish a private-authority bypass; it established a concrete loss of evidence integrity on the refusal path.

The new code closes both sides of that defect:

* In `controller-caller-integrity-fix5-material-candidate.js:109`, `exactJSON` checks whether each object is an array and then requires exactly `Array.prototype` or `Object.prototype`, respectively. Custom array prototypes are refused before serialization. At line 120 the prototype-chain traversal inspects property descriptors for `toJSON`; it does not read or call the property. Thus even a hook installed on an otherwise accepted ordinary prototype is refused by this profile.
* Array elements are inspected through own descriptors at line 128. The exact key-count and per-index descriptor rules reject holes, extra fields, symbols, accessors, and non-enumerable indexed properties. Ordinary objects similarly require string keys and enumerable data descriptors at line 134. Recursive checks reject unsupported primitives, cycles, nonfinite numbers and negative zero before `JSON.stringify` runs. The check does not replace unsupported values with null, coerce them, or normalize negative zero.
* `response` now calls `exactJSON(r)` at line 53 before reading normal response fields. In `nativeCall`, line 75 still assigns the original actual return to `e.response` and persists it before subsequent refusal. This order matters: the new refusal does not prevent retention of the actual value in the outer state. The same serializer refuses an unrepresentable failure body, leaving the established outer-retention-only state rather than producing a misleading disk diagnostic.
* In `controller-caller-integrity-fix5-material-fixture.js:13`, the replacement clone preserves prototypes, complete property descriptors and graph identity through a memo map. Data values are recursively copied through descriptors; accessor functions remain descriptor values and are not invoked. The fake store also retains the caller's original state reference. The fixture consequently no longer converts the offending array to an ordinary array before the behavior can be observed.

The relevant new tests explicitly retain the original response identity (`material-fixture.js:150`), compare its snapshot prototype, preserve negative zero with `Object.is` at line 153, and preserve the accessor function in its descriptor. The green assertion at line 157 requires zero hooks, zero patches, and `stopped-unknown-outer-retention-only` for the new unsupported cases. Those requirements match the I1 retention/refusal contract rather than accepting a sanitized substitute.

**I1 assessment: ADDRESSED.** The source correction covers the original inherited-hook array path, the fixture can now represent that path faithfully, and the recorded RED/GREEN/cover sequence distinguishes old failure from the repaired behavior. No actual tool result was supplied or invoked by this review; runtime outer-store retention remains an actual gate.

## Fix-caused breakage and exact caller

I compared the new material candidate with the prior candidate. With the replacement `exactJSON` function and the single added early `exactJSON(r)` call removed for comparison, the remainder is byte-identical. This provides a concrete boundary for the new behavior: response representability is checked earlier and more strictly, while the existing material flow is retained.

Within that boundary, ordinary JSON response envelopes pass without cloning or mutation. The recursion's `seen` set is cleared after each completed branch, so repeated acyclic references do not become false cycle failures. Descriptor reads avoid invoking the getters targeted by this fix. Custom or cross-profile objects are deliberately refused under the fixed local JSON profile. This is a conservative refusal contract, not a newly generalized serializer. No unrelated extension for arbitrary exotic objects or a hostile replacement JavaScript runtime is required by I1 or claimed here.

The unchanged sections preserve request-before-await logging, original return retention, polling and pending-last behavior, native invocation literals, lossless proof text/raw splice, marker rules and BigInt handling, budget/interlock checks, strict patch-result profile, destination consumption, the normal three-patch chain, and the single failure-save attempt. The material command literals and collector remain unchanged: GET literal 126 bytes / SHA-256 `10e0136f53f644e722f6774d5055c84501636b71ae8497bd5cea42910bf4e096`; reconcile literal 127 bytes / `ca45a39b99cd390d3e9ecef75f779e1b0fc1daf812a41bd57bff274b3b07cd28`; collector 1,855 bytes / `a9399f32eae83ada51191bfc36d8d70de914041c93f6b4ef4011a652e522bee3`. No conclusion about approval-writer flag changes is made here.

The complete material execution plan is 90,095 bytes, SHA-256 `e3996d2be4ffb4b3bd684ca46316766b306d54a7b7a514ab9bfc170990019892`. Its original 77,887-byte prefix is unchanged, SHA-256 `0af34159f1ae1c9ff2d522f37ae63cd91d35961102c991341951aa5e2806ccf8`. The append beginning at `continuation-controller-operations-execution-plan.md:529` explicitly identifies the sole replacement material caller and supersedes the archival earlier material caller. Its complete `javascript` fence is byte-identical to the frozen new candidate. The corresponding early response check is at plan line 585; the serializer starts at line 642. The surrounding prose states the outer-retention/refusal behavior and does not silently grant actual admission. I found no disagreement between the candidate and the executable text proposed in the plan.

**New-breakage assessment: no new Critical, Important, or Minor finding in the inspected fix diff.** This statement retains, rather than re-adjudicates, the earlier accepted parts and existing deferred findings.

## Recorded material fixture evidence

The following results are observations of retained artifacts, not tests run by this reviewer. The three directories are `controller-caller-integrity-fix5-material-js-red-01`, `...-green-01`, and `...-cover-01` under `docs/evidence/task-6/`.

| Retained run | Candidate | Cases / failures / errors / skipped | Relevant recorded outcome |
| --- | --- | --- | --- |
| RED | previous material caller | 1 / 1 / 0 / 0 | Original inherited-hook failure reproduced: one hook call, one patch, transformed diagnostic; `expected_regression_observed:true`, `passed:false` |
| GREEN | frozen repaired caller | 22 / 0 / 0 / 0 | All four new unsupported-response cases have zero hooks and zero patches; outer-retention-only |
| Frozen cover | same repaired caller and fixture | 22 / 0 / 0 / 0 | Same result profile; no later source edit evidenced |

The RED harness completing is not relabeled as a passing product test. Its one failing case is the expected original regression. GREEN and cover each retain the four new cases—an inherited-hook array, negative-zero response, indexed accessor, and own object hook—plus the original 18 scenarios. Existing normal immediate/session cases retain their three successful patches, with three/four fake native calls respectively. The retained suites also cover missing interlocks, rejected initial/poll/reader/reconcile calls, patch refusals and bad patch shapes, undefined/nonzero/oversize responses, canonical marker refusal, and array extra fields. Each complete green run records 39 fake native calls, 30 fake patches, a maximum recorded payload of 65,537 bytes, and at most four fake native calls per case. These counts describe a local JavaScript fixture; they do not establish native resource limits or actual command success.

I compared the three `execute.js` bodies: apart from the stage-specific retained-store names, they use the same local fixture invocation with candidate and mode supplied from the retained pre record. The fixture receives fake tools/store/load/notify/text; I did not execute its dynamic function construction. The copied candidate is the old candidate for RED and the repaired candidate for GREEN/cover; all three use the final descriptor-preserving fixture. Their candidate/fixture hashes agree with their maps and retained pre payloads.

For all three runs, the retained pre and post native metadata envelopes have the expected request/initial/polls/final structure, immediate completion, exit code zero, empty polls, and equal initial/final values. The pre/post receipts agree with the parsed final stdout, and source150/controller2/code maps agree before and after. Recorded chunks are RED pre `aea3c9` / post `a26bdf`, GREEN pre `b73365` / post `4b4487`, and cover pre `7fdb0e` / post `6d3b00`. These are metadata receipts around the isolate; the native metadata launch limits do not bound the separate JavaScript isolate. No broader timing/resource conclusion is inferred.

I read the full report's disclosed approval-side history to avoid laundering it into an aggregate clean-run claim: approval JS RED failures and green/cover results, native RED, the first native GREEN's partial observations and telemetry/JSON parsing failure, the 16 missing files, and subsequent native GREEN/cover are distinct records. The three root checker format-assumption failures are likewise distinct. Their behavior and resolution belong to the other reviewer/root scope; this report neither discards their failed history nor supplies a second approval-native verdict.

## Cannot verify and retained gates

1. **Cannot verify actual authorization or admission.** Root-owned interlocks, private actual inputs, approvals, and any decision to admit a call have not been supplied or exercised. A source/fixture PASS does not open them.
2. **Cannot verify actual tool/store behavior.** The runtime's real response objects, outer retention durability and identity, patch result profile, transport failure behavior, and actual malformed-value behavior were not invoked. The mock demonstrates the fixed local profile and preserves the offending values; it does not replace real runtime evidence.
3. **Cannot verify actual material collection or reconciliation.** No four-GET collection, private-body read, native command, controller operation, terminal sampler/writer, post-terminal observation, or reconciliation was executed here. Actual causality, quiescence, freshness, complete terminal ownership, and independent sampling remain subject to the accepted existing gates.
4. **Cannot verify actual timing or resource limits.** No UID/binary/namespace/clock/runtime control, physical provider FD timing, physical pre-Python stop, process elapsed bound, disk/RSS cap, native budget, or host-state claim is proved by the JS isolate. The previously ruled conservative whole-command process-elapsed interpretation remains; it is not strengthened into an unavailable physical guarantee.
5. **Cannot verify actual scenario completion.** Q5000000000/released false, scene22 and ordinary R/Q obligations remain open, along with Task3–4 caps, Azure6 `<=5.40` Retail/own-RG/tags/TTL/protected-RG requirements, 12GB/16GB limits, GPU flock, and the no-host-k3s/iptables/no-push-publication constraints. No cloud, GPU, VM, service, credentials, or private API was touched.
6. **Cannot verify the separate approval-writer repair through this verdict.** Its own reviewer must judge AW-I1/AW-I2 and native fixture behavior. Root's wider index/history check is evidence from root, not an expansion of my direct 48-row material check.

The four old deferred Minors remain open. Original Task6 is at round 5/5, without a sixth round, reset, or renamed phase. This review accepts the scoped material source correction and exact plan; all actual gates remain closed pending their existing admission process. Task6 and Goal are not complete.
