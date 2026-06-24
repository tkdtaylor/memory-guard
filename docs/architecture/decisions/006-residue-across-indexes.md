# ADR-006 — Residue proof across every index/copy + stdlib number-word paraphrase

**Status:** Accepted
**Date:** 2026-06-24
**Refines:** [ADR-003](003-residue-detection-method.md) (the single-map residue scan) and builds on
[ADR-005](005-memorystore-seam.md) (the `MemoryStore` seam).
**Task:** [008 — Residue proof across every index/copy](../../tasks/completed/008-residue-across-indexes.md)

## Context

ADR-003 made `verify_delete` prove "no residue survives" — but only over the survivors in the
**single** in-memory map. The AGENTS.md `verify_delete` invariant names the v1 meaning explicitly:
"v1 extends the proof to **every index/copy** — residue detection, the documented gap." A real memory
store keeps entries in MORE THAN ONE backing index/copy (a recency cache, a vector/embedding index, a
secondary id↔content map); a deleted `user John's balance is $5000` must not survive as `$5k` in ANY
of them, not just the primary map. ADR-005 landed the `MemoryStore` seam and a `TwoIndexStore` proving
the seam carries a genuinely multi-index backing — which is the prerequisite this ADR consumes.

ADR-003 also recorded the **full-paraphrase residue class** as the honest `0/2` known-miss of a
substring/token method (`user John's balance is $5000` → `the user with a five-thousand-dollar
balance`). Two open decisions remained: (1) how the scan enumerates "every index/copy", and (2)
whether — and how — to improve the paraphrase miss-class without taking on an embedding-model
dependency on a security-critical, hot-adjacent path.

## Decision

### 1. Enumerate every backing index/copy through a seam method

Add **one** small method to the `MemoryStore` seam: `AllByIndex() map[string][]entry` — a map from an
**index name** (a plain `string` label the store chooses) to that index's surviving entries. Only
`string` / `entry` / `[]entry` cross the boundary, so **no store-backend type leaks** into `guard.go`,
`ipc.go`, or `docs/CONTRACT.md` (the fitness-seam gate and `TestNoStoreBackendLeak` still pass).

- `verify_delete` now scans **every** index returned by `AllByIndex()` (via
  `residue.go::residueScanIndexes`), in deterministic order (`"primary"` first, then the rest
  alphabetically), and the `residue_summary` **NAMES the index** the residue survives in.
- **Backward-compatible (REQ-005):** a single-index store returns exactly one entry keyed
  `"primary"`, so `residueScanIndexes` reduces **exactly** to ADR-003's single-map scan
  (`residueScan` is preserved as a thin wrapper over it). All task-003 residue tests and the v0
  `TestVerifyDeleteConfirmsAbsence` pass **unchanged**; the contract shape is identical
  (`{confirmed, residue_detected, residue_summary?, deletion_hash}`).
- `deletion_hash` is **unchanged** — a SHA-256 over (`id` + deleted content), independent of index
  layout (verified identical across `InMemoryStore`, `TwoIndexStore`, and a multi-index cache store).

### 2. Improve the paraphrase miss-class with stdlib number-word canonicalization (no dependency)

Adopt **spelled-out number-word canonicalization** as the lightest method that moves the paraphrase
class: `canonicalizeNumberWords` rewrites contiguous runs of cardinal number-words (`five thousand`,
`twenty five thousand`, `one million two hundred thousand`) to their integer digits (`5000`, `25000`,
`1200000`) inside `normalizeForResidue`, **before** the existing currency/magnitude passes. A deleted
`$5000` and a paraphrased `five thousand dollars` then share the strong token `5000` and flag through
the existing normalized tier. It is conservative (only recognized number-word runs fold; everything
else passes through verbatim), so it adds **no false positives** on the clean controls.

**Embedding-based semantic matching is explicitly NOT taken** (it would be an ask-first ADR + a
`dep-scan`/`code-scanner` blocking gate per AGENTS.md "Ask first"). Free-form synonym paraphrase with
no shared distinctive token ("potted plant" → "planter near the rack closet") remains the recorded
**residual** known-miss — improvement plus separate measurement was the requirement, not 100% recall.

## Rationale

| Criterion | Embedding (semantic) | **AllByIndex seam + number-word (chosen)** |
|---|---|---|
| Scans every backing index/copy | n/a | ✓ — `AllByIndex()` names each index; summary names where residue survives |
| Single-index reduces to ADR-003 scan | n/a | ✓ — one `"primary"` index ⇒ identical detection + summary |
| Catches number-word paraphrase (`five thousand` → `5000`) | ✓ | ✓ — stdlib canonicalization |
| Catches free-form synonym paraphrase | ✓ | ✗ — recorded residual known-miss |
| New dependency / supply-chain gate | ✗ ML model + ask-first ADR | ✓ none — `go.mod` stays require-free |
| Detector seam untouched (guard-side) | depends | ✓ — scan makes no `Detector` call, imports no backend |

## Consequences

- `MemoryStore` gains `AllByIndex()`; both `InMemoryStore` (one index) and `TwoIndexStore`
  (primary + secondary content index) implement it. `residue.go` gains `residueScanIndexes`,
  `matchSurvivor`, and `canonicalizeNumberWords`; `guard.go::VerifyDelete` scans through
  `AllByIndex()`. No detector backend is touched (REQ-006).
- `residue_summary` now reads `… survives in index "<name>", entry "<snippet>": "<fragment>"` — a
  wire-visible change to the **summary string only**. The contract field set is unchanged
  (`data-model.md`, `behaviors.md` B-003 updated in the same commit).
- A third-party / embedding backend still slots in **additively** behind the same `verify_delete`
  surface if free-form paraphrase must be closed later — this ADR defers it, it does not foreclose it.

## Measured / as-built

Reproduce: `go test -v -run 'TestMultiIndexResidueRate|TestParaphraseSubCorpusImprovedSeparately' ./...`.

- **Multi-index residue-detection rate (`TestMultiIndexResidueRate`, 13 cases: 10 residue across
  indexes + 3 clean controls):**

  | Backing index | Rate |
  |---|---|
  | primary | 4/4 = 100% |
  | secondary (a copy the primary-keyed `All()` would miss) | 6/6 = 100% |

  | Residue class | Rate |
  |---|---|
  | verbatim | 5/5 = 100% |
  | normalized-numeric | 5/5 = 100% |
  | **OVERALL** | **10/10 = 100%** (bar: ≥80% ✓; ADR-003 was 85.7% over one map) |
  | **Precision** | **0 FP / 3 clean controls = 100%** (no FP in any index) |

- **Paraphrase sub-corpus, measured SEPARATELY (`TestParaphraseSubCorpusImprovedSeparately`, 4
  cases):** **3/4 caught** vs the ADR-003 **0/2 baseline**.

  | Paraphrase case | Result |
  |---|---|
  | `$5000` → "five thousand dollars" (number-word) | CAUGHT |
  | `25000` → "twenty five thousand" (number-word) | CAUGHT |
  | `1200000` → "one million two hundred thousand" (number-word) | CAUGHT |
  | "potted plant" → "planter near the rack closet" (free-form synonym) | **residual known-miss** (recorded, not padded) |

- **`dep-scan` / `code-scanner`:** **no new dependency** — `go.mod` stays require-free
  (`TestNoNewDependency`); only stdlib was used (number-word canonicalization is plain Go). Trivially
  clear (TC-008).
