# Test Spec 009: Identity-scoped read isolation (R1 / roadmap T4)

**Linked task:** [`docs/tasks/backlog/009-identity-scoped-read-isolation.md`](../backlog/009-identity-scoped-read-isolation.md)
**Written:** 2026-06-24

> ## ⛔ BLOCKED — authored ahead of an external dependency
>
> The linked task is **blocked** on the external workload-identity model (SPIFFE SVID / A2A signed
> identity) from **agent-mesh / vault**. This spec is written **now** so the isolation assertions are
> ready the instant the block clears — but TC-001/002/003/007 are **not locally verifiable** until a
> verifiable identity exists to bind and match (the rest can use a mocked/stub identity). See the task's
> **Readiness gate**; nothing runs until its external items are checked.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ⛔ blocked — needs verifiable external identity | ✅ |
| REQ-002 | TC-002 | ⛔ blocked — needs verifiable external identity (stub possible) | ✅ |
| REQ-003 | TC-003 | ⛔ blocked — needs verifiable external identity (stub possible) | ✅ |
| REQ-004 | TC-004 | ✅ (mechanics; correctness rides on REQ-001/002) | ✅ |
| REQ-005 | TC-005 | ✅ (once fallback policy is decided) | ✅ |
| REQ-006 | TC-006 | ✅ | ✅ |
| REQ-007 | TC-007 | ⛔ blocked — needs the upstream identity model to document | ✅ |

## Pre-implementation checklist

- [x] All test cases below are defined
- [x] Expected inputs and outputs are specified for each case
- [x] Edge cases and error paths are covered
- [x] Every REQ-ID from the task has at least one test case
- [x] **EXTERNAL — a verifiable identity (SVID / A2A principal) is available to bind and assert** —
      satisfied via the pre-verified principal contract (ADR-004): agent-mesh owns SVID verification and
      emits `{spiffe_id, trust_tier}`; the guard binds/matches the normalized `spiffe_id` through the
      `Principal` seam (`PreVerifiedPrincipal`). Unit tests use the typed wire shape directly.
- [x] No-identity fallback policy (deny vs. unbound-only) decided before TC-005 is finalized —
      **UNBOUND-ONLY** (ADR-004, ratified): an unattested/absent reader sees only entries written with no
      bound identity, never an identity-bound entry, never the whole store.

## Test fixtures

- **Two identities A and B** — each a *verifiable* principal (SPIFFE SVID / A2A signed identity) once
  the upstream lands; a deterministic **stub** principal stands in for unit runs (TC-002/003/004) before
  then. Each fixture carries the normalized identity key the read path matches on.
- **Overlapping-content entries** — entry written by A and entry written by B whose contents **both**
  match a shared query substring, so isolation cannot be an accident of the query failing to match.
- **No-identity request** — a `validate_read` carrying no/empty identity, to exercise the fallback
  policy.

## Test cases

### TC-001: validate_write binds a verifiable identity to the entry
- **Requirement:** REQ-001
- **Input:** `validate_write("alice's note", identityA)` where `identityA` is a verifiable principal.
- **Expected:** the stored entry carries A's **normalized identity key** (not the inert free-form map);
  the key is what the read path will match against. `allow:true, stored_id:"mem-…"`.
- **Edge cases:** a write with no verifiable identity binds the documented "unbound" marker (feeds the
  REQ-005 fallback), not a wildcard that matches everyone.
- **Blocked:** needs a verifiable external identity to bind.

### TC-002: validate_read returns an entry only under a matching identity
- **Requirement:** REQ-002
- **Input:** seed `("alice's note", identityA)`; then `validate_read("note", identityA)` and
  `validate_read("note", identityB)`.
- **Expected:** under `identityA` → the entry is returned (redacted); under `identityB` → the entry is
  **excluded** (not present in `content_redacted`). `allow` reflects the documented policy; the entry is
  invisible to B, not merely redacted.
- **Edge cases:** identity that matches *no* stored entry → empty result set, no leakage.
- **Blocked:** needs a verifiable external identity (a stub principal suffices for the unit form).

### TC-003: no cross-identity leakage — A's entry never reaches B (load-bearing)
- **Requirement:** REQ-003
- **Input:** seed `("shared keyword balance", identityA)` **and** `("shared keyword balance", identityB)`
  (overlapping content); then `validate_read("shared keyword", identityB)`.
- **Expected:** B receives **only B's** entry; **A's entry is absent** from `content_redacted` even
  though its content matches the query verbatim. The isolation holds *because* of identity, not because
  the query failed to match.
- **Edge cases:** swap the roles (A reads) → symmetric result; an attacker-supplied identity that does
  not verify must match **nothing**, never fall through to the whole store.
- **Blocked:** needs a verifiable external identity; this is the assertion the whole task exists for.

### TC-004: the un-scoped substring read is replaced by an identity-scoped lookup
- **Requirement:** REQ-004
- **Input:** seed several entries under A and several under B; `validate_read(query, identityA)`.
- **Expected:** the result is drawn from A's identity-scoped set only (matching is **exact** on the
  normalized identity key, not substring/fuzzy on identity); the old whole-store
  `strings.Contains(e.content, query)` loop no longer governs which identities are visible. Same
  identity still returns the writer's matching entry (no regression in the read happy path).
- **Edge cases:** an identity key that is a substring of another (`"tenant-1"` vs `"tenant-12"`) must
  **not** match — exact match, no substring bleed.

### TC-005: no-identity / unauthenticated read follows the documented fallback policy
- **Requirement:** REQ-005
- **Input:** `validate_read("note", <no identity>)` against a store holding A's and B's entries.
- **Expected:** the **documented** policy applies — either **deny** (empty/`allow:false`) or
  **unbound-only** (return only entries written with no bound identity). In **no** case does it return
  every entry. The policy chosen is recorded in the spec + ADR and this test asserts exactly that
  policy.
- **Edge cases:** empty-map vs. nil identity treated identically; an identity present but failing
  verification is **not** treated as "no identity" — it matches nothing (see TC-003 edge).

### TC-006: PII redaction on read unchanged; no detector specifics in the identity path
- **Requirement:** REQ-006
- **Input:** seed `("call alice@example.com", identityA)`; `validate_read("call", identityA)`.
- **Expected:** the returned content is still PII-redacted (defense in depth runs on the identity-scoped
  result set); existing PII-redaction read tests still pass. The identity-matching code is guard-side
  orchestration only — **no** `Detector`/backend specifics appear in it (seam preserved).
- **Edge cases:** an entry visible under the reader's identity but containing PII is redacted; identity
  matching never bypasses redaction.

### TC-007: ADR records the identity binding/matching model
- **Requirement:** REQ-007
- **Input:** review the ADR added with this task.
- **Expected:** the ADR states how a verifiable identity from **agent-mesh / vault** (SPIFFE SVID /
  A2A signed identity) is consumed, normalized into the identity key, bound at write, and matched at
  read; what "match" means for a principal; and the no-identity fallback policy. Cross-references R1 /
  roadmap T4 and the upstream blocker.
- **Edge cases:** the ADR notes the soft dependency on task 006's real `MemoryStore` for per-identity
  indexing and the linear-filter fallback.
- **Blocked:** needs the upstream identity model to exist to document it accurately.
