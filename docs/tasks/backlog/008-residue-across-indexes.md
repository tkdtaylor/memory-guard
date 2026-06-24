# Task 008: Residue proof across every index/copy

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog

> The direct successor to [task 003](../completed/003-post-deletion-residue-verification.md). Task 003
> made `verify_delete` prove "gone, not just deleted" — but only over the survivors in the **single**
> in-memory map. Roadmap **T3** extends that proof to **every backing index/copy** of the real store,
> and takes a real run at the residue class task 003 documented as a known-miss. This is the v1
> meaning the scoping doc names (AGENTS.md `verify_delete` invariant: "v1 extends the proof to every
> index/copy — residue detection, the documented gap").

## Goal

Extend `verify_delete`'s residue scan from "survivors in one in-memory map" to "**no residue of the
deleted content survives in any backing index/copy of the real `MemoryStore`**." A deleted
`user John's balance is $5000` must not survive as `$5k` in a recency cache, a vector/embedding
index, or any secondary id→content copy the store keeps — not just in the primary map. Second goal:
address the documented **semantic-paraphrase residue miss-class** — the `0/2` full-paraphrase cases
task 003 recorded honestly (`user John's balance is $5000` → `the user with a five-thousand-dollar
balance`) — improving the method while keeping precision. The contract shape is unchanged
(`{confirmed, residue_detected, residue_summary?, deletion_hash}`); what changes is the **coverage**
of the scan (every index) and its **recall on paraphrase**.

## Context

- **Depends on task 006 — the `MemoryStore` seam.** Today the residue scan
  (`residue.go::residueScan`) takes `survivors map[string]entry` — the one in-memory map in
  `guard.go::MemoryGuard.store`. There is no way to enumerate "every backing index/copy" until the
  store is behind a `MemoryStore` interface that exposes its indexes. Roadmap T3 is listed as
  **"depends on T1"** (the `MemoryStore` seam, scaffolded here as task 006). This task **cannot
  start** until task 006 lands a seam that lets `VerifyDelete` enumerate every index/copy to scan.
- **Code under change:** `residue.go` (the tiered residue scan — extend its input from a single map
  to the set of indexes the `MemoryStore` seam exposes) and `guard.go::VerifyDelete` (drive the scan
  over every index). At most these two modules plus the seam introduced by task 006.
- **Boundary preserved from task 003:** the residue scan stays **GUARD-SIDE**, not behind the
  `Detector` seam. It is string/semantic matching of deleted content — not PII/injection detection —
  so it lives in `residue.go`, makes no `Detector` call, and imports no detector backend. The
  paraphrase improvement (even if it uses an embedding) stays guard-side too.
- **Paraphrase method is an open decision** (ADR-003 named full-paraphrase the deferred class):
  improve it with the **lightest method that works** — token-stemming / number-word canonicalization
  (`five-thousand-dollar` ⇆ `$5000`) / synonym-lite normalization are stdlib-only candidates and
  **preferred**. An embedding model is an **ask-first ADR + a `dep-scan`/`code-scanner` blocking
  gate** (AGENTS.md "Ask first"); do not add it casually to chase paraphrase recall.
- **Method recorded in an ADR** (successor to / amendment of
  [ADR-003](../architecture/decisions/003-residue-detection-method.md)).
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) B-003,
  [`docs/CONTRACT.md`](../../CONTRACT.md) (`verify_delete`),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (DeleteResult shape),
  [roadmap T3](../../plans/roadmap.md).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `verify_delete` scans **every backing index/copy** the `MemoryStore` seam exposes (primary map + any secondary index/cache/vector copy) for residue of the deleted content — not just the primary map. The `residue_summary` names the index/copy the residue survives in. | must have |
| REQ-002 | The `confirmed` / `residue_detected` truth table holds across indexes: `residue_detected:true` when a fragment survives in **any** index; `false` only when no index holds residue; `confirmed` reflects post-delete absence across the store. A deleted entry never flags itself in any index (no self-residue FP). | must have |
| REQ-003 | The multi-index residue scan **meets or maintains the >80% residue-detection bar** (task 003 measured 85.7% over one map; the bar is now measured **across multiple indexes**), with precision held (no false positive in any index). Rates recorded in the ADR + `behaviors.md` B-003. | must have |
| REQ-004 | `deletion_hash` is unchanged — deterministic over (id + deleted content), independent of index layout, suitable for audit-trail linkage. | should have |
| REQ-005 | **Backward-compatible:** when the `MemoryStore` exposes a single index, the scan reduces exactly to task 003's single-map scan. `TestVerifyDeleteConfirmsAbsence` (v0) and all task-003 residue tests pass **unchanged**. The contract shape is identical. | must have |
| REQ-006 | The residue scan stays **guard-side** (`residue.go`, driven by `VerifyDelete`); it makes **no** `Detector` call and imports no detector backend. The paraphrase improvement also stays guard-side. | must have |
| REQ-007 | The documented **semantic-paraphrase miss-class** is improved over the task-003 `0/2` baseline and **measured separately** from the verbatim/normalized classes (so a paraphrase regression cannot be masked). At least one prior-miss paraphrase case now flags, precision held; method + paraphrase rate recorded in the ADR. | must have |
| REQ-008 | Any new dependency the paraphrase method pulls (e.g. an embedding model) clears `dep-scan` + `code-scanner`, is pinned, and is recorded in an **ask-first ADR**; a stdlib-only paraphrase method adds **no** dependency (preferred). | must have |

## Readiness gate

- [x] Test spec `008-residue-across-indexes-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **Task 006 (`MemoryStore` seam) merged** — `VerifyDelete` can enumerate every backing index/copy
      (hard blocker; this task cannot start without it)
- [ ] Multi-index residue corpus sourced (extends the task-003 single-store corpus; residue lands in
      assorted indexes) for the >80% bar
- [ ] Paraphrase sub-corpus held separately (the task-003 `0/2` cases + added paraphrase variants) for
      the separate paraphrase measurement
- [ ] Paraphrase method chosen — **lightest that works**; an embedding model is an ask-first ADR +
      `dep-scan`/`code-scanner` gate, not a default

## Acceptance criteria

- [ ] [REQ-001] `verify_delete` scans every backing index/copy; summary names the index (TC-001).
- [ ] [REQ-002] The cross-index `confirmed`/`residue_detected` truth table holds; no self-residue FP (TC-002).
- [ ] [REQ-003] Multi-index residue rate ≥80% with precision held; rates recorded (TC-003).
- [ ] [REQ-004] `deletion_hash` present, deterministic, index-layout-independent (TC-004).
- [ ] [REQ-005] Backward-compatible; v0 + task-003 residue tests still green on a single-index store (TC-005).
- [ ] [REQ-006] Scan stays guard-side; no `Detector` call (TC-006).
- [ ] [REQ-007] Paraphrase class improved over `0/2` and measured separately; ADR records the rate (TC-007).
- [ ] [REQ-008] dep-scan/code-scanner clear any new dep; ask-first ADR; stdlib method adds none (TC-008).
- [ ] `go build ./... && go test ./...` green.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) runs the multi-index
  residue corpus and the paraphrase sub-corpus through `verify_delete`, with final assertions
  reporting (a) ≥80% multi-index residue detection, (b) the cross-index truth-table cases passing,
  and (c) the separately-measured paraphrase rate strictly above `0/2`; plus **L3** dep-scan /
  code-scanner **only if** the paraphrase method adds a dependency.
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`, incl. the multi-index residue corpus, the
  cross-index truth table, the paraphrase sub-corpus, and the preserved task-003 residue tests.
- **Level 6 (optional):** `go run .` / a live `serve` `verify_delete` on a seeded multi-index store
  with a known residue in a secondary index → observe `residue_detected:true` + a summary naming that
  index. Record the per-index + paraphrase rates in the ADR + `behaviors.md` B-003.
- **Seam-isolation check:** confirm (grep + the call path) that the residue scan makes no `Detector`
  call and that the guard/contract/IPC remain backend-agnostic.
</content>
