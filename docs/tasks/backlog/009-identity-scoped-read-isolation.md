# Task 009: Identity-scoped read isolation (R1 / roadmap T4)

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog (blocked)

> ## ⛔ BLOCKED — external dependency not yet available
>
> **This task cannot start.** It is blocked on an **external workload-identity model** — SPIFFE SVID
> issuance / A2A signed identity — from the sibling **agent-mesh / vault** projects. Until that upstream
> lands, `identity` here is a **free-form `map[string]any`** carried through the contract but with no
> verifiable subject to bind to. Enforcing read isolation against a forgeable free-form string would be
> security theatre, not isolation. The block stands until a real, verifiable identity exists to assert.
>
> See roadmap **T4** (⛔ blocked) and **R1 — Identity-scoped read isolation — blocked: external
> identity** in [`docs/plans/roadmap.md`](../../plans/roadmap.md). **Do not begin implementation until
> the readiness gate's external-dependency items below are checked.** The spec + acceptance criteria
> are authored ahead so the work is ready the moment the block clears.

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
- **External blocker (load-bearing):** a **verifiable** workload identity — SPIFFE SVID / A2A signed
  identity — from **agent-mesh / vault** must exist first. The task asserts isolation against a
  *verifiable* subject (an SVID / signed principal), not the current forgeable free-form map. Without
  it, "isolation" is unenforceable. This is the same blocker R1 documents.
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
| REQ-001 | `validate_write` **binds** the writer's verifiable identity to the stored entry, recording a normalized identity key the read path can match against (not the inert free-form map). | must have | ⛔ needs verifiable external identity (SPIFFE/A2A) to be the bound subject |
| REQ-002 | `validate_read` returns an entry **only** when the reader's identity **matches** the entry's bound identity; non-matching entries are excluded from the result set entirely. | must have | ⛔ needs verifiable external identity to match against |
| REQ-003 | **No cross-identity leakage:** writer A's entry is never returned to reader B even when the query substring matches the content. (The load-bearing isolation assertion.) | must have | ⛔ needs verifiable external identity |
| REQ-004 | The **un-scoped whole-store substring read** in `ValidateRead` is replaced by an identity-scoped lookup; matching is exact on the normalized identity key, not substring/fuzzy. | must have | — (mechanics local; correctness needs REQ-001/002) |
| REQ-005 | **No-identity / unauthenticated read** falls back to the **documented** behavior (an explicit, spec'd policy — e.g. deny, or return only entries written with no bound identity); it is **not** an implicit return-everything. The chosen policy is recorded in the spec + an ADR. | must have | — (policy decision; document it) |
| REQ-006 | PII redaction on read is **unchanged** (defense in depth still runs on whatever the scoped set returns); the write-gate stays fail-closed; **no detector specifics** leak into the identity-matching path. | must have | — |
| REQ-007 | The identity model is **documented in an ADR** (how a verifiable identity from agent-mesh/vault is consumed, normalized, bound, and matched; what "match" means for SVID/A2A principals). | must have | ⛔ needs the upstream identity model to exist to document |

## Readiness gate

- [x] Test spec `009-identity-scoped-read-isolation-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **EXTERNAL — agent-mesh / vault workload-identity model is available** (SPIFFE SVID issuance or
      A2A signed identity) and consumable by memory-guard — **the load-bearing blocker; nothing starts
      until this is checked**
- [ ] **EXTERNAL — the verifiable-identity shape is pinned** (what memory-guard receives on each
      `validate_*` call: SVID / signed principal — its representation and verification path)
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
