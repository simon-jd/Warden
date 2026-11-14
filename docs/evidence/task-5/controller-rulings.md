# Task5 design rulings and remaining admission gates

This records proposal preparation only, not implementation, fixtures or runtime
acceptance. The [proposal draft](controller-proposal-draft.md) is retained as
submitted; the decisions below supersede its open choices. No runtime/Gate source,
attack body, Go test or resource operation was performed for Task5.

Ruling: keep `evaluation` separate from the three requested verdicts. Setup,
transport, unknown exit/cleanup, truncated logs and absent trustworthy entry
remain unevaluated/error with no verdict. A failed launch or absent success marker
is never a blocked attack. This preserves required verdicts without manufacturing
completed cells. Cost if wrong: conservative unevaluated cells need more actual
instrumentation, not weaker evidence.

Ruling: before Task12, missed means the defined isolation objective actually
succeeded, with detector_state=unavailable; it does not claim a running detector
missed an event. Detected is unavailable until real independently correlated
Task12 evidence exists. Preserve containment separately when detection is added.
Cost if wrong: labels could be misunderstood, so every report must carry these
semantics and actual detector availability.

Ruling: do not adopt a homegrown restricted interpreter as proof of a complete
shell scenario. Future material design should use an independently authenticated
real guest shell with bounded invocation and complete provenance, potentially
from existing authenticated materials, without downloading/installing/executing
anything now. Keep the corpus image distinct from accepted conformance assets,
within the existing32MiB FC payload boundary; any size/compatibility failure stops.
Cost if wrong: shell packaging needs more reviewed work; it cannot be replaced
by a connect-only fixture or a larger disk without authorization.

Ruling: every behavior needs an explicit protection objective and evidence
predicate. A proven early policy denial can support its precisely stated objective;
invalid input, missing scenario or a same-guest success cannot be relabelled host
escape/ARP effect/ENOSPC/module load/full reverse shell. Unrepresentable scenarios
stay unevaluated. Cost if wrong: stricter semantic gaps delay full Task5 acceptance.

Ruling: current42 cells remain unevaluated, with ordinaryguard/runtime/scenario
reasons. No fixture replaces real runc/gVisor/FC results. Next implementation
still requires legitimate bounded Go-code admission; current opaque scene/Q5GB
is no exception. Until it exists, retain the proposal and concrete prerequisites
rather than writing untested behavior or changing the resource guard. Task5 is
not complete; original Task3/4 caps and unknown retirement remain unchanged.
