# Test Spec 016: Durable identity isolation (scoped seam lookup + shared scope + restart proof)

**Linked task:** [`docs/tasks/backlog/016-durable-identity-isolation.md`](../backlog/016-durable-identity-isolation.md)
**Written:** 2026-07-11

> Authored ahead of execution. Task 009 already shipped exact-string identity isolation
> (`principal.go`, `guard.go::ValidateRead`); this spec covers the remaining T4 deltas, so every
> case must hold **in addition to** the existing `identity_isolation_test.go` suite, which stays
> green unmodified. The headline negatives: identity A can never read identity B's entry (including
> after a process restart over the persisted store), an unattested writer can never publish into
> the shared scope, and a forged `spiffe_id` equal to the reserved shared marker gains nothing.
> Set-equality assertions throughout, never "result is non-empty" smoke checks.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002, TC-006 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-007 | ✅ | ✅ |
| REQ-007 | TC-008 | ✅ | ✅ |
| REQ-008 | TC-008 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] The full pre-existing isolation suite (`identity_isolation_test.go`) passes unchanged

## Test fixtures

- **Identities** (typed wire shape from ADR-004, built as `map[string]any`):
  - `idA` = `{"spiffe_id": "spiffe://secure-agents/agent/alpha", "trust_tier": "attested"}`
  - `idB` = `{"spiffe_id": "spiffe://secure-agents/agent/beta", "trust_tier": "attested"}`
  - `idAShared` = `idA` plus `"scope": "shared"`
  - `idUnattested` = `{"spiffe_id": "spiffe://secure-agents/agent/alpha", "trust_tier": "unattested"}`
  - `idUnattestedShared` = `idUnattested` plus `"scope": "shared"`
  - `idForgedMarker` = `{"spiffe_id": "<the reserved shared marker literal>", "trust_tier": "attested"}`
  - `nil` identity = the absent-principal case
- **Seed corpus** (contents share the token `memo` so query scoping is isolated from content scoping): `"memo alpha-private"` written under `idA`; `"memo beta-private"` written under `idB`; `"memo broadcast"` written under `idAShared`; `"memo public"` written under `nil` identity.
- **Store adapters:** each guard-level case runs parameterized over `InMemoryStore`, `TwoIndexStore`, and `FileStore` (task 015) unless the case is FileStore-specific.
- **Spy store**: a test-local `MemoryStore` wrapper around `InMemoryStore` that counts calls per verb, to prove which seam verb the read path uses.

## Test cases

### TC-001: the scoped seam verb returns exactly the visible-key matches, per adapter
- **Requirement:** REQ-001
- **Input:** seed each adapter directly with four entries: `("mem-1", entry{content: "memo alpha-private", boundIdentity: "spiffe://secure-agents/agent/alpha"})`, `("mem-2", …beta…)`, `("mem-3", entry{content: "memo broadcast", boundIdentity: sharedScopeKey})`, `("mem-4", entry{content: "memo public", boundIdentity: ""})`. Call `ScanScoped("memo", []string{"spiffe://secure-agents/agent/alpha", sharedScopeKey})`, then `ScanScoped("memo", []string{""})`, then `ScanScoped("alpha", []string{"spiffe://secure-agents/agent/beta"})`.
- **Expected:** call 1 → **set-equal** `{"memo alpha-private", "memo broadcast"}` (order-free, exactly 2); call 2 → exactly `{"memo public"}`; call 3 → **empty** (query matches content of an entry the keys cannot see; the key filter wins). Identical results on all three adapters.
- **Edge cases:** empty `visibleKeys` → empty result (never a fallback to unscoped); `ScanScoped("", keys)` matches every visible entry (empty-substring semantics preserved); membership is **exact string equality**: key `"spiffe://secure-agents/agent/alpha"` never matches boundIdentity `"spiffe://secure-agents/agent/alpha2"`.

### TC-002: ValidateRead goes through ScanScoped, not guard-side filtering
- **Requirement:** REQ-002
- **Input:** wrap the spy store in a guard; call `g.ValidateRead("memo", idA)`.
- **Expected:** the spy records **exactly one `ScanScoped` call** (with visible keys `{A's subject, sharedScopeKey}`) and **zero `Scan` calls**. The verdict shape is unchanged: `{allow: true, content_redacted: <string>, flags: []}`.
- **Edge cases:** an unattested reader triggers `ScanScoped` with visible keys `{unboundKey, sharedScopeKey}`; the dead-wire trap from the retro log is the target here: the new verb existing is not enough, the live `ValidateRead` line must call it (mutation probe: make `ScanScoped` return nothing on the spy and assert the read result becomes empty).

### TC-003: shared scope is writable by attested writers only, readable by everyone
- **Requirement:** REQ-003
- **Input:** parameterized per adapter: write the seed corpus through the guard (`g.ValidateWrite(content, identity)` with `idA`, `idB`, `idAShared`, `nil`). Then read `"memo"` as `idA`, as `idB`, as `idUnattested`, and as `nil`.
- **Expected:** reader `idA` → content_redacted contains `alpha-private` and `broadcast`, **not** `beta-private`, **not** `public`; reader `idB` → `beta-private` + `broadcast` only; readers `idUnattested` and `nil` → `public` + `broadcast` only. (Attested readers still do not see unbound entries, the shipped 009 behavior; shared is the one cross-tenant channel.)
- **Edge cases:** `idUnattestedShared` writing `"memo sneak"` → the entry binds **unbound**, not shared: visible to `nil`/unattested readers, **invisible to `idA`/`idB`** (no privilege escalation: an unverified writer cannot inject into attested tenants' reads); an unknown scope value (`"scope": "team"`) is ignored and binds normally; `scope` on `validate_read` identities is ignored entirely.

### TC-004: the reserved shared marker cannot be forged via spiffe_id
- **Requirement:** REQ-004
- **Input:** `g.ValidateWrite("memo forged-broadcast", idForgedMarker)`; then read `"memo"` as `idA` and as `nil`.
- **Expected:** the entry is bound **unbound** (`boundKeyFor` maps a Subject equal to `sharedScopeKey` to `unboundKey`): `idA` does **not** see `forged-broadcast`; the `nil` reader does (unbound namespace). No write under any forgeable `spiffe_id` value can produce a shared-scoped entry.
- **Edge cases:** a reader presenting `idForgedMarker` sees shared + unbound entries at most, never any tenant-bound entry; `"tenant-1"` vs `"tenant-12"` exactness re-asserted through the scoped path (write as `tenant-1`, read as `tenant-12` → zero hits).

### TC-005: isolation survives restart on the persisted store (FileStore only)
- **Requirement:** REQ-005
- **Input:** `path := t.TempDir()+"/store.jsonl"`; `g1 := NewMemoryGuard(NewNativeDetector(), mustFileStore(path))`; write the full seed corpus through `g1`. Drop `g1`; construct `g2` over a **new** `FileStore` on the same path (simulated restart). Read `"memo"` as `idA`, `idB`, `nil` through `g2`. **Positive control:** first assert `os.ReadFile(path)` contains `"spiffe://secure-agents/agent/alpha"` (the binding really persisted; guards against a store that drops `boundIdentity` and passes vacuously by returning nothing to anyone).
- **Expected:** identical scoping to TC-003 through `g2`: `idA` → `{alpha-private, broadcast}`; `idB` → `{beta-private, broadcast}`; `nil` → `{public, broadcast}`. The explicit negative: `g2.ValidateRead("memo", idB)`'s `content_redacted` does **not** contain the substring `alpha-private` (identity A's entry is unreadable by B **across process lifetimes**).
- **Edge cases:** `verify_delete` of A's entry through `g2` followed by an `idA` read → `alpha-private` gone from the result and from the file bytes (composes with task 015's delete proof).

### TC-006: existing isolation suite green, unchanged
- **Requirement:** REQ-002
- **Input:** `go test -run 'TestWriteBindsVerifiableIdentity|TestReadReturnsOnlyMatchingIdentity|TestNoCrossIdentityLeakage|TestIdentityScopedLookupReplacesWholeStoreScan|TestNoIdentityReadIsUnboundOnly|TestPIIRedactionUnchangedUnderIdentityScoping|TestPrincipalSeamSemantics' ./...` on the finished tree.
- **Expected:** all pass **without edits to their assertions** (mechanical updates only if a constructor signature moved). The switch from guard-side filter to `ScanScoped` is behavior-preserving for every pre-shared-scope case.
- **Edge cases:** none; this is the regression fence.

### TC-007: PII redaction unchanged over every scope class
- **Requirement:** REQ-006
- **Input:** write `"reach me at carol@example.com about the merger"` under `idAShared` (shared) and `"call dana@example.com re: alpha"` under `idA` (bound). Read `"about"`/`"re:"` as `idA`, `idB`, and `nil`.
- **Expected:** no reader ever receives the raw `carol@example.com` / `dana@example.com` bytes in `content_redacted` (redaction on the scoped result set is unchanged, defense in depth); visibility still follows TC-003 scoping (only `idA` sees the dana entry at all).
- **Edge cases:** the shared entry's raw PII is also absent from the FileStore file bytes (write-side redaction landed before persistence, from task 015's TC-008).

### TC-008: ADR + spec propagation, seam hygiene, zero dependencies
- **Requirement:** REQ-007, REQ-008
- **Input:** inspect the tree after the feat commit; run `make fitness` and `make check`; read `go.mod`.
- **Expected:** the new ADR (expected ADR-013) exists in `docs/architecture/decisions/` and records: the `ScanScoped` seam extension, the shared-scope semantics (attested-writer-only publish, readable by all), the reserved-marker guard, and that ADR-004's deferred "durable per-identity index" item is realized at seam level. `docs/spec/interfaces.md` documents the `identity` wire shape with the optional `scope` field; `docs/spec/behaviors.md` and `docs/spec/data-model.md` describe shared-scope visibility and the marker key; all updated in the same commit as the code. `make fitness` exits 0; `go.mod` has no `require` block.
- **Edge cases:** the spec is rewritten in place (no appended "update:" paragraphs); no future-tense statements enter `docs/spec/`.
