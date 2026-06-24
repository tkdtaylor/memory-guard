# Task 009: Identity-scoped read isolation (R1 / roadmap T4)

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog (startable — pending the identity-propagation contract decision; see below)

> ## 🔜 STARTABLE — re-scoped 2026-06-24 (was ⛔ fully blocked)
>
> **The heavy external blocker has cleared.** An audit of the siblings found that **agent-mesh already
> ships the verifiable workload identity** this task asserts against — X.509-SVID issuance (SPIFFE ID as
> a URI SAN, Ed25519-bound), a signed-envelope carrier (`Envelope.From`), and a fail-closed verification
> path (chain → trust-bundle, signature, replay), tracer-validated. Only the *live* SPIRE/Vault issuer is
> deferred; a mock issuer stands in behind agent-mesh's `SvidProvider` seam — which is exactly what this
> task's own tracer would use. **vault is NOT an identity source** — it is a secrets broker whose own
> SPIFFE binding is itself blocked on agent-mesh; it is a co-consumer of the same principal and is
> **removed here as a dependency**.
>
> **What remains is one interface decision, not an upstream build: the identity-propagation contract** —
> the shape of the verified SPIFFE claim memory-guard receives on each `validate_*`, and who verifies it.
> **Recommended (ratify in the REQ-007 ADR): receive a *pre-verified* SPIFFE principal (the normalized
> SPIFFE ID + a `trust_tier`); do NOT re-verify the SVID in-guard.** Verification stays agent-mesh's job;
> enforce isolation only when the principal is `attested`; an unverified/absent principal → the REQ-005
> fallback. Why: the `< 1 ms` hot-path budget rules out per-call X.509 verification, and the seam
> discipline keeps SPIFFE/X.509 specifics out of the guard (the same reason the `Detector` seam exists);
> the `0600` UID-gated socket is already the trust boundary. In-guard SVID verification stays available
> behind a `Principal` seam as a **deferred zero-trust config**.
>
> See roadmap **T4** and **R1** in [`docs/plans/roadmap.md`](../../plans/roadmap.md). 009 is **startable
> now** against agent-mesh's mock SVID; live SPIRE swaps in later with no memory-guard change. The spec +
> acceptance criteria below were authored ahead and need only the propagation-contract decision pinned.

## Goal

Enforce `identity` on `validate_read` so that a writer's stored entries are returned **only** under a
matching identity — tenant isolation on the memory hot path. Today `ValidateRead` (`guard.go`) matches
by substring across the **entire store** and ignores the `identity` argument entirely (it is carried on
both `validate_read` and `validate_write` per [`docs/CONTRACT.md`](../../CONTRACT.md), but never
compared). The target behavior:

- **Bind identity at write** — `validate_write` records the writer's verifiable identity with the
  entry (it already stores `identity`, but as an unverified free-form map).
- **Match identity at read** — `validate_read` returns an entry only when the reader's identity
  **matches** the entry's bound identity; non-matching entries are invisible (not redacted-and-returned,
  not even acknowledged).
- **No cross-identity leakage** — writer A's entry is never returned to reader B, regardless of query
  substring overlap. This is the load-bearing assertion.
- **Replace the un-scoped substrate read** — the whole-store substring scan in `ValidateRead` is
  replaced by an identity-scoped lookup (ideally a per-identity index once task 006's real
  `MemoryStore` lands).

## Context

- **Source:** roadmap **T4** + **R1** ([`docs/plans/roadmap.md`](../../plans/roadmap.md)); the contract
  [`docs/CONTRACT.md`](../../CONTRACT.md) (both `validate_read` and `validate_write` carry `identity`).
- **Code under change:** `MemoryGuard.ValidateRead` and `MemoryGuard.ValidateWrite` (`guard.go`). Today
  `ValidateRead` loops the whole `store` map with `strings.Contains(e.content, query)` and never reads
  `identity`; the `entry` struct already carries `identity map[string]any` set at write time but it is
  inert.
- **External dependency (re-scoped 2026-06-24):** the **verifiable** subject this task asserts against —
  a SPIFFE SVID principal — **already exists in agent-mesh** (X.509-SVID issuance + a fail-closed
  verification path, tracer-validated; mock issuer now, live SPIRE deferred behind agent-mesh's
  `SvidProvider` seam). **vault is not the source** (a secrets broker, itself blocked on agent-mesh;
  removed as a dependency). The remaining gap is the **identity-propagation contract**: the
  verified-SPIFFE-claim shape memory-guard receives on each `validate_*`, and who verifies it.
  **Recommended (ratify in the REQ-007 ADR): receive a pre-verified SPIFFE principal (normalized ID +
  `trust_tier`); do NOT re-verify the SVID in-guard** — verification stays agent-mesh's job, which keeps
  the `< 1 ms` budget and the seam discipline (no X.509 specifics in the guard). Enforce isolation only
  when `attested`; unverified/absent → the REQ-005 fallback.
- **Soft-depends on task 006** (the real `MemoryStore` seam + adapter, roadmap T1): the single in-memory
  map is *why* per-identity indexing can't be real yet. A real store gives a natural per-identity index
  / partition for the scoped lookup. 009 can be implemented as a linear identity filter over the v0 map
  if 006 is not yet done, but the durable form is a per-identity index behind the `MemoryStore` seam.
- **Invariants preserved:** PII redaction on the way out is unchanged (defense in depth); the write-gate
  stays fail-closed; no detector specifics leak (identity matching is guard-side orchestration, not a
  `Detector` concern). The IPC error shape `{error:{code,message,retryable}}` is unchanged.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (read/write behaviors),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (the `entry` / identity shape).

## Requirements

Requirements describe the **target** behavior once unblocked. Per-REQ blocker callouts mark where a
**verifiable external identity** is required.

| Req ID | Description | Priority | Blocker |
|--------|-------------|----------|---------|
| REQ-001 | `validate_write` **binds** the writer's verifiable identity to the stored entry, recording a normalized identity key the read path can match against (not the inert free-form map). | must have | needs the propagation contract (bound subject = the pre-verified SPIFFE ID from agent-mesh) |
| REQ-002 | `validate_read` returns an entry **only** when the reader's identity **matches** the entry's bound identity; non-matching entries are excluded from the result set entirely. | must have | needs the propagation contract (match on the pre-verified SPIFFE ID) |
| REQ-003 | **No cross-identity leakage:** writer A's entry is never returned to reader B even when the query substring matches the content. (The load-bearing isolation assertion.) | must have | — (testable now against a mock SVID principal) |
| REQ-004 | The **un-scoped whole-store substring read** in `ValidateRead` is replaced by an identity-scoped lookup; matching is exact on the normalized identity key, not substring/fuzzy. | must have | — (mechanics local; correctness needs REQ-001/002) |
| REQ-005 | **No-identity / unauthenticated read** falls back to the **documented** behavior (an explicit, spec'd policy — e.g. deny, or return only entries written with no bound identity); it is **not** an implicit return-everything. The chosen policy is recorded in the spec + an ADR. | must have | — (policy decision; document it) |
| REQ-006 | PII redaction on read is **unchanged** (defense in depth still runs on whatever the scoped set returns); the write-gate stays fail-closed; **no detector specifics** leak into the identity-matching path. | must have | — |
| REQ-007 | The identity model is **documented in an ADR** that ratifies the propagation/verification decision (recommended: a pre-verified SPIFFE principal from agent-mesh, not re-verified in-guard) — how the principal is consumed, normalized, bound, and matched; what "match" means for a SPIFFE ID; and the no-identity fallback. | must have | — (decision is recommended above; ADR ratifies it) |

## Readiness gate

- [x] Test spec `009-identity-scoped-read-isolation-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] **Verifiable identity issuer exists** — agent-mesh ships X.509-SVID issuance + a fail-closed
      verification path (tracer-validated; mock issuer now, live SPIRE deferred behind its
      `SvidProvider` seam). *vault dropped — not an identity source.*
- [ ] **Identity-propagation contract pinned** — the verified-SPIFFE-claim shape memory-guard receives
      on each `validate_*`, and who verifies it. **Recommended: pre-verified SPIFFE principal (ID +
      `trust_tier`), verified upstream by agent-mesh, not re-verified in-guard** — ratify in the REQ-007
      ADR. *(This is the one decision that gates the start.)*
- [ ] Task 006 (real `MemoryStore` seam + adapter, roadmap T1) landed, or a decision to ship 009 as a
      linear identity filter over the v0 map first — **recommended dependency; per-identity indexing is
      the durable form**
- [ ] No-identity / unauthenticated read policy decided (deny vs. unbound-only) — REQ-005

## Acceptance criteria

> **Cannot start until the upstream identity model exists.** These criteria are authored ahead; they
> become checkable only after the readiness gate's external-dependency items are satisfied.

- [ ] [REQ-001] `validate_write` binds a normalized verifiable identity to the entry (TC-001).
- [ ] [REQ-002] `validate_read` returns an entry only under a matching identity (TC-002).
- [ ] [REQ-003] Writer A's entry is **not** returned to reader B despite a matching query (TC-003).
- [ ] [REQ-004] The whole-store substring read is replaced by an identity-scoped lookup; same identity
      still returns the entry (TC-004).
- [ ] [REQ-005] No-identity read follows the documented fallback policy, not return-everything (TC-005).
- [ ] [REQ-006] PII redaction on read unchanged; no detector specifics in the identity path (TC-006).
- [ ] [REQ-007] ADR records the identity binding/matching model (TC-007).
- [ ] `go build ./... && go test ./...` green.

## Verification plan

> **Flagged: cannot start until the upstream identity model exists.** Fill this in for real when the
> block clears — the level achievable depends on whether a live verifiable identity is wired (L5/L6) or
> only mocked (L2).

- **Highest level achievable:** **L5** once a real verifiable identity is available — the validation
  harness (`go test`) seeds entries under identity A and identity B and asserts the isolation matrix
  (A reads A, B reads B, A's entry never reaches B). **L6** if exercised over a live `serve`
  `validate_read` with a real SVID/A2A principal. Until the block clears, **no level is reachable.**
- **Level 2 — unit:** `go test ./...` → `ok`, incl. the cross-identity isolation matrix (TC-002/003)
  against a mocked verifiable identity.
- **Level 5/6 — harness/live:** seed under two identities, exercise `validate_read` per identity, quote
  that A's entry is absent from B's result and present in A's. Record the isolation result in
  `behaviors.md` + the ADR.
- **Trace producer→consumer:** confirm the identity bound at the `validate_write` site is the same key
  matched at the `validate_read` site on the **live path** — not merely a hand-set field in a test.
