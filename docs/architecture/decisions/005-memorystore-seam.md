# ADR-005 — `MemoryStore` seam: extract the store behind verbs; prove it with a stdlib multi-index adapter

**Status:** Accepted
**Date:** 2026-06-24
**Task:** [006 — MemoryStore seam + one real adapter](../../tasks/completed/006-memorystore-seam.md)
**Relates to:** ADR-001 (foundational stack, the in-memory `map` stand-in), ADR-002 (the `Detector`
seam this mirrors), ADR-003 (post-deletion residue scan — the consumer this unblocks).

## Context

In v0 the entry store was a bare `map[string]entry` inlined in `MemoryGuard` (`guard.go`). That single
map is the load-bearing **stand-in** behind the "v0 substrate" headline, and it is *why* two roadmap
goals could not be real:

- **T3 — delete-proof across every index/copy.** The residue scan (ADR-003) can only prove "no residue
  in *the one map*." "Absent from **every** index/copy" is meaningless when there is exactly one index.
- **T4 — identity-scoped reads.** A flat map cannot cleanly partition reads by tenant/identity.

Both need the store to become a real, swappable thing behind a seam — exactly the way the `Detector`
seam (ADR-002) isolates the detection backend. The task is to extract a `MemoryStore` interface and
prove it carries a **second** backing with a genuinely different representation, not merely that a
second store compiles.

The open sub-decision was **which** "one real adapter beyond the map" to build:

1. A third-party memory store — vector store / LangChain / LlamaIndex / SQLite / bbolt client.
2. A **stdlib-only second store** with a different backing representation (file-backed, or a
   multi-index in-memory store).

## Decision

**Extract a `MemoryStore` interface (`store.go`) with the verb set `Put` / `Get` / `Delete` / `Scan`
/ `All`, and prove the seam with a stdlib-only `TwoIndexStore` — a store that keeps entries in MORE
THAN ONE backing index.** Defer (do not foreclose) any third-party vector/LangChain/SQLite adapter.

- **Seam shape:** the guard holds a `MemoryStore` (interface), not a `map`. Only `string` / `entry`
  / `[]entry` cross the boundary — no store-backend type, no SQL handle, no vector-client object
  leaks into `guard.go`, `ipc.go`, or `docs/CONTRACT.md`. Swapping the backing is a one-line
  construction change: `NewMemoryGuard(det, someStore)`.
- **Default adapter — `InMemoryStore`:** the extracted v0 map (`type InMemoryStore map[string]entry`),
  constructed by `NewMemoryGuard` when no store is supplied (a nil/omitted store falls back to it,
  mirroring the nil-`Detector` → `RegexDetector` default). CLI / `serve` behavior is identical to v0.
- **Second adapter — `TwoIndexStore` (the "one real adapter beyond the map"):** a store with a
  **primary** `id → entry` map PLUS a **secondary** content-keyed index (`content → set of ids`). This
  is the smallest backing that makes task 008's "residue absent from **every** index/copy" a concrete,
  testable claim: `Delete` must purge **both** indexes, and `All()` must reflect the purge — a delete
  that left the secondary index populated would be exactly the multi-index residue memory-guard exists
  to catch.
- **Dependencies:** **none.** `TwoIndexStore` is pure Go standard library; `go.mod` stays
  **require-free**. There is no module tree for `dep-scan` (`gods`) / `code-scanner` to scan, so
  REQ-006's gate is trivially satisfied (asserted by `TestNoNewDependency`).

## Rationale

| Criterion | Third-party (vector/LangChain/SQLite) | **Stdlib `TwoIndexStore` (chosen)** |
|---|---|---|
| Proves the seam (different backing) | ✓ | ✓ — primary map + secondary content index |
| Makes "every index/copy" concrete (T3/008) | ✓ | ✓ — `Delete` purges two indexes |
| New dependency / supply-chain gate | ✗ ask-first ADR + `dep-scan`/`code-scanner` blocking gate, offline-infeasible here | ✓ none — `go.mod` stays require-free |
| Single static binary (ADR-001) | ~ pulls a client tree | ✓ one binary |
| Cheap to revisit | ✓ behind the seam | ✓ behind the seam |

A third-party store buys nothing the seam needs *right now* that the multi-index stdlib store does not
already provide: a second, genuinely different backing whose `Delete` must keep multiple indexes
consistent. It would, however, trigger the first external dependency and a blocking supply-chain gate —
the same posture the `Detector` backend took (ADR-002), which chose Go-native for identical reasons.
Because the choice lives entirely behind the `MemoryStore` seam, a vector/LangChain/SQLite adapter
still slots in **additively** later if a future requirement (scale, persistence, ANN search) demands
it — this ADR defers that, it does not foreclose it.

## Consequences

- The stdlib-only property (ADR-001 §2, reaffirmed by ADR-002) **holds** — the store extraction adds
  no dependency.
- The residue scan (`residue.go`) now operates over the store's `All()` survivors (`[]entry`) instead
  of the raw map, so it is decoupled from the backing: a single-index and a multi-index store hand it
  the same survivor slice across the seam. The residue **summary** now references the surviving entry
  by a short content snippet rather than a map id (the store no longer exposes ids to the scan) — a
  wire-visible change to the `residue_summary` string only (the field is still present only when
  `residue_detected:true`; `data-model.md` updated).
- T3 (delete-proof across every index/copy, task 008) and T4 (identity-scoped reads) are unblocked:
  there is now more than one index to scan and a real store to partition.
- `verify_delete` proves absence through the seam's `Get` (a fresh post-delete read), not the `Delete`
  return — the post-deletion-verification invariant is preserved verb-for-verb.

## Measured / as-built

- **As built:** `store.go` — the `MemoryStore` interface plus `InMemoryStore` (default) and
  `TwoIndexStore` (the multi-index second adapter). `guard.go` routes `ValidateWrite → Put`,
  `ValidateRead → Scan`, `VerifyDelete → Get` (absence proof) + `Delete` + `All()` (residue
  survivors). `ipc.go` and `docs/CONTRACT.md` are untouched by any store-backend type.
- **Seam proven behaviorally (not by compilation):** `TestGuardBehaviorParityAcrossStores` and
  `TestInvariantsThroughSeam` run the **same** guard-behavior corpus once per store
  (`InMemoryStore`, `TwoIndexStore`) and assert **identical** outcomes — clean write, PII redaction,
  fail-closed poisoned write (no `Put`), redacted read, and delete-with-residue.
- **No-leak guard:** `TestNoStoreBackendLeak` greps `guard.go` / `ipc.go` / `main.go` /
  `docs/CONTRACT.md` for store-backend tokens (`TwoIndexStore`, `byContent`, `primary`) — none appear
  outside `store.go`.
- **`dep-scan` / `code-scanner`:** **no new dependency added → trivially clear.** `go.mod` stays
  require-free (`TestNoNewDependency`); there is no new module tree to scan.
