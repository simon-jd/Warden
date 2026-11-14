**I1 — Successful no-op clearing updates are incorrectly rejected: ADDRESSED.** `controlplane/internal/jit/bindings.go:186` now adds a fresh persisted revocation fence, explicitly different from its current value, making each clearing PUT a substantive change. `bindings.go:202` verifies the returned fence before permitting conditional deletion; UID, advanced-version and empty-subject checks remain intact.

**Regression coverage:** `controlplane/internal/jit/bindings_test.go:68` preserves resourceVersion for identical updates. Tests at `bindings_test.go:189` and `bindings_test.go:203` exercise empty-reservation cleanup and retry after clearing succeeds but DELETE fails. The subcase at `bindings_test.go:153` rejects a missing persisted fence before DELETE. The appended report names the four covering tests and includes their complete passing output, including that subcase.

**New breakage in the fix diff:** None identified.

**Out-of-scope observations:** No new observations. Previously recorded M1 warning noise remains deferred and nonblocking for this round.

**Review checks:** Read the brief, complete appended report, scoped reviewer template and fix diff once. No tests, network access or mutations performed.

**Fix round:** All findings addressed, no new Critical/Important breakage. This verdict covers the component fix; actual Kubernetes, identity and supervised-expiry acceptance remain open.
