# Task 016: Durable identity isolation (scoped seam lookup, shared scope, restart-surviving enforcement)

**Project:** memory-guard
**Created:** 2026-07-11
**Status:** backlog

> Roadmap [T4](../../plans/roadmap.md) ("enforce `identity` on `validate_read` so a writer's entries are readable only under a matching identity") was **partially realized by completed task 009**: `guard.go::ValidateRead` already enforces exact-string isolation through the `Principal` seam, and ADR-004 is already **Accepted** (ratified by 009), so the roadmap row and its R1 note are stale on those points. What T4 still lacks: the isolation only exists **inside one process lifetime** (every adapter was in-memory until task 015), the scoped lookup is a guard-side linear filter that ADR-004 explicitly recorded as "the v0 mechanics, not the intended steady state" (its deferred *durable index* item), and there is **no shared scope**: an attested tenant has no way to publish an entry readable by other identities. This task closes those three gaps.

## Goal

Make identity isolation **durable and complete**: push the identity-scoped lookup into the `MemoryStore` seam (a new `ScanScoped` verb implemented by all three adapters, replacing the guard-side filter over `Scan`), add an **explicit shared scope** (attested writers may mark a write `scope: "shared"`; shared entries are readable under every identity), and prove the whole matrix **survives a process restart** over the task-015 `FileStore` (bound identities persist and are re-enforced by an independently constructed guard). String-exact matching stays the enforcement primitive; cryptographic verification of the principal remains upstream in agent-mesh, per ADR-004.

## Context

- **What 009 shipped (do not rebuild):** `principal.go` (the `Principal` seam: `Subject()` / `Attested()`, `principalFromMap` decoding `{spiffe_id, trust_tier}`, `boundKeyFor` as the producer half, `readerVisibilityKey` as the consumer half, `unboundKey = ""`); `guard.go::ValidateWrite` binds `entry.boundIdentity`; `guard.go::ValidateRead` filters `store.Scan(query)` by exact key equality. The suite is `identity_isolation_test.go` (7 tests); it must stay green unmodified.
- **ADR-004 status correction:** the planning brief for this task assumed ADR-004 was still *Proposed* and that isolation did not exist yet. Repo fact: `docs/architecture/decisions/004-identity-propagation.md` is **Accepted, ratified 2026-06-24 by task 009**. Do not add a "ratify ADR-004" step. What ADR-004 *defers* and this task picks up is its "Confirmed at implementation" item: "**per-identity index/partition is the durable form; 009 ships the linear filter**... exposed through the `MemoryStore` seam so the scoped lookup is scoped store-side, deferred to a future task."
- **The interim identity model stands:** exact string match on the normalized `Subject()` (trimmed SPIFFE ID), enforced only when `trust_tier == "attested"`. Verifying the principal cryptographically (SVID chain, signature, replay) is agent-mesh's job under its identity-propagation contract (agent-mesh task 008); memory-guard receives a pre-verified claim across the `0600` socket. The zero-trust `SvidVerifyingPrincipal` stays deferred behind the `Principal` seam. Nothing in this task parses certificates.
- **Why a shared scope:** under the shipped 009 semantics an attested reader sees *only* entries bound to its exact subject, and unbound (identity-less) entries are visible *only* to unattested/absent readers. There is no way for tenant A to publish a memory readable by tenant B. `scope: "shared"` on `validate_write` is that channel. Security posture: **only attested writers** may bind the shared scope; an unattested writer requesting it falls back to the unbound binding, so an unverified caller can never inject content into attested tenants' reads.
- **Reserved marker, forge-proof:** the shared binding is a reserved `boundIdentity` marker constant (`sharedScopeKey`, suggested literal `"shared://"`, chosen because it is not a valid `spiffe://` URI). `boundKeyFor` must map any principal whose `Subject()` equals the marker to `unboundKey`, so no caller can reach the shared binding by forging `spiffe_id`.
- **Why depends-on-015:** durability claims are only testable against the persistent adapter, and `FileStore` must round-trip `boundIdentity` (task 015 REQ-002). The restart case (write as A, rebuild the guard from the same file, B still cannot read A) is the proof that isolation is a property of the stored data, not of a process's memory.

## Contract shapes

The three IPC verbs keep their tracer-validated response shapes unchanged. The typed `identity` argument (ADR-004) gains one **optional** request field, meaningful on `validate_write` only:

```jsonc
"identity": {
  "spiffe_id":  "spiffe://<trust-domain>/agent/<id>",
  "trust_tier": "attested",        // any other value → unattested (unchanged)
  "scope":      "shared"           // optional; only honored when attested; ignored on validate_read
}
```

New seam verb on `MemoryStore` (`store.go`), implemented by `InMemoryStore`, `TwoIndexStore`, and `FileStore`:

```go
// ScanScoped returns every entry whose content contains query AND whose
// boundIdentity is an exact member of visibleKeys. Exact string membership,
// no substring/fuzzy on keys. Empty visibleKeys returns no entries.
ScanScoped(query string, visibleKeys []string) []entry
```

Guard-side derivation (the only policy site): an attested reader's visible keys are `{Subject(), sharedScopeKey}`; an unattested/absent reader's are `{unboundKey, sharedScopeKey}`.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `MemoryStore` gains `ScanScoped(query string, visibleKeys []string) []entry` with exact-membership semantics (documented on the interface); all three adapters implement it and agree on results; empty `visibleKeys` yields empty. | must have |
| REQ-002 | `guard.go::ValidateRead` computes the reader's visible-key set (via `readerVisibilityKey` + `sharedScopeKey`) and calls `ScanScoped` exactly once; the guard-side filter loop over `Scan` is removed from the read path. Behavior for all pre-shared cases is unchanged and `identity_isolation_test.go` passes unmodified. | must have |
| REQ-003 | Shared scope: `ValidateWrite` binds `sharedScopeKey` iff the writer is attested **and** `identity["scope"] == "shared"`; shared entries are readable under every identity class; an unattested writer requesting shared binds unbound instead; unknown scope values are ignored. | must have |
| REQ-004 | Forge-proofing: `boundKeyFor` (or `principalFromMap`) maps a `Subject()` equal to `sharedScopeKey` to `unboundKey`; no `spiffe_id` value can produce a shared-bound entry; exactness (`tenant-1` vs `tenant-12`) holds through the scoped path. | must have |
| REQ-005 | Restart-surviving enforcement: over a task-015 `FileStore`, an independently constructed guard on the same path enforces the full visibility matrix (A sees A+shared; B sees B+shared; unattested sees unbound+shared), with a positive control that the binding bytes persisted. | must have |
| REQ-006 | PII redaction on the scoped result set is unchanged for every scope class; raw PII never appears in any reader's `content_redacted` nor in the store file. | must have |
| REQ-007 | ADR (next free number, expected ADR-013) records the seam extension, shared-scope semantics, the reserved-marker guard, and marks ADR-004's deferred durable-index item as realized at seam level (per-identity partitioning *inside* an adapter stays an internal optimization, not required here). `docs/spec/interfaces.md` (identity shape + `scope`), `docs/spec/behaviors.md`, `docs/spec/data-model.md` updated in the same commit; `docs/architecture/diagrams.md` checked (no component boundary moves expected; update only if a diagrammed flow names the read path's store verb). | must have |
| REQ-008 | Substrate constraints hold: stdlib-only (`go.mod` require-free), `make fitness` green, no detector/store/identity backend specifics past their seams, IPC error shape untouched. | must have |

## Implementation outline

1. `scripts/start-task.sh 016 durable-identity-isolation`; move this file to `docs/tasks/active/`.
2. Write the ADR; commit `docs: add ADR NNN — scoped seam lookup + shared scope`.
3. `principal.go`: add `const sharedScopeKey = "shared://"`; extend `principalFromMap` to read the optional `scope` string into the principal (e.g. a `PreVerifiedPrincipal.scope` field + a `SharedScope() bool` accessor, keeping the `Principal` interface minimal; alternatively pass scope alongside the principal in `ValidateWrite` only); harden `boundKeyFor` against `Subject() == sharedScopeKey`.
4. `store.go`: add `ScanScoped` to the interface + `InMemoryStore` / `TwoIndexStore` implementations (linear filter over the primary index); `store_file.go`: implement over the parsed on-disk records.
5. `guard.go`: `ValidateWrite` shared-scope binding; `ValidateRead` visible-key set + single `ScanScoped` call, drop the filter loop.
6. Tests per the spec: extend `identity_isolation_test.go` conventions in a new `identity_durable_test.go` (TC-001…TC-005, TC-007), spy-store instrumentation for TC-002, FileStore restart matrix for TC-005.
7. Spec updates (REQ-007) in the feat commit; add the 016 row to `coverage-tracker.md` at 🟡.
8. `make check` green; run the L5/L6 evidence (below); move this file to `docs/tasks/completed/`; commit `feat: complete task 016 — durable-identity-isolation`.

## Readiness gate

- [x] Test spec `016-durable-identity-isolation-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Task 015 merged (FileStore + persisted `boundIdentity` are prerequisites)
- [ ] Decide the scope-carriage mechanics in step 3 (principal accessor vs. write-path argument) before coding; record the choice in the ADR
- [ ] Confirm no external consumer implements `MemoryStore` outside this repo (interface method addition is a breaking change for implementors; in-repo only today)

## Acceptance criteria

- [ ] [REQ-001] `ScanScoped` set-exact results agree across all three adapters (TC-001).
- [ ] [REQ-002] `ValidateRead` provably calls `ScanScoped` (spy store), zero `Scan` calls; existing 009 suite green unmodified (TC-002, TC-006).
- [ ] [REQ-003] Shared-scope visibility matrix holds; unattested shared write demotes to unbound (TC-003).
- [ ] [REQ-004] Forged marker `spiffe_id` gains no shared binding and no tenant data; tenant-1/tenant-12 exactness holds (TC-004).
- [ ] [REQ-005] Restart matrix over FileStore: B never reads A's entry across process lifetimes, with positive control (TC-005).
- [ ] [REQ-006] No raw PII in any reader's output or in the store file (TC-007).
- [ ] [REQ-007] ADR + interfaces/behaviors/data-model spec updates land in the feat commit (TC-008).
- [ ] [REQ-008] `make fitness` green; `go.mod` require-free (TC-008).
- [ ] `go build ./... && go test ./...` green; `make check` green.

## Verification plan

- **Highest level achievable: L6**, operator-observed over the live socket with the persistent store: start `MEMGUARD_STORE=file MEMGUARD_STORE_PATH=/tmp/memguard-016.jsonl go run . serve --socket /tmp/mg-016.sock`; via `nc -U`, `validate_write` one entry as identity alpha and one with `"scope":"shared"`; **restart the serve process**; then `validate_read` as beta and quote the response containing the shared entry and not the alpha entry, and `validate_read` as alpha containing both.
- **Level 2 (unit):** `go test ./...` → `ok`, including the pre-existing 009 suite unmodified and the new durable suite.
- **Level 3 (gate):** `make fitness` and `make check` exit 0 (seam gate confirms no new backend tokens leaked into `guard.go` / `ipc.go` / `main.go`).
- **Level 5 (validation harness):** a tracer-style live-socket test drives the TC-005 restart matrix end-to-end over the Unix socket (two daemon instantiations over one store file), asserting the beta read's `content_redacted` field-by-field; re-run `go test -run TestTracer ./...` to confirm contract shapes unchanged. Record final assertion lines in the verify commit.

## Out of scope

- Cryptographic verification of the principal (SVID chain/signature/replay): stays upstream in agent-mesh per ADR-004; the zero-trust `SvidVerifyingPrincipal` remains deferred behind the `Principal` seam.
- Ratifying ADR-004: already Accepted (see Context); no status change belongs to this task.
- Per-identity physical partitioning *inside* an adapter (O(matches) lookup): an internal optimization behind the new verb, deferred until a store's scale demands it.
- Fine-grained ACLs, groups, or multi-tenant scopes beyond the single shared scope (a future contract decision; would need its own ADR).
- Updating the stale roadmap T4/R1 rows: `docs/plans/` is ask-first; flag it to the operator instead.

## Dependencies

- **Depends on:** task 015 (FileStore adapter persisting `boundIdentity`); completed task 009 (isolation mechanics, `Principal` seam) and ADR-004 (Accepted).
- **Blocks:** nothing in the current backlog; unlocks a later gateway/consumer task binding real agent-mesh principals end-to-end.
- **Independent of** task 017 (audit emission); no shared files beyond tests, safe to sequence either way after 015.
