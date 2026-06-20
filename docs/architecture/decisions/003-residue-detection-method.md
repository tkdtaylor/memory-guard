# ADR-003 — Post-deletion residue-detection method: normalized substring/token matching

**Status:** Accepted
**Date:** 2026-06-19
**Refines:** ADR-001 §5 (post-deletion verification) and ADR-001 "Open questions" → the residue-method entry.
**Task:** [003 — Post-deletion verification across every index/copy](../../tasks/backlog/003-post-deletion-residue-verification.md)

## Context

ADR-001 §5 commits memory-guard to **proving** a deletion, not assuming it — the documented industry
blind spot. v0 proves only "absent from the in-memory map." v1 must extend `verify_delete` to "**no
semantic residue of the deleted content survives anywhere in the store**": a deleted
`user John's balance is $5000` must not survive as `John's balance is $5k` in another entry.

ADR-001 left the **residue-detection method** open across three candidates:

1. **Exact-substring matching** — fast, exact, zero-dependency; misses normalized/paraphrased fragments.
2. **Embedding-based semantic matching** — catches paraphrase; pulls an embedding-model dependency
   onto the hot path.
3. **Bloom-filter deleted-content signatures** — compact membership of *known* signatures; does not
   catch fuzzy fragments.

The scoping doc sets a **>80% residue-detection** acceptance bar and instructs: "prefer the lightest
that meets the bar without a heavy ML dependency on the hot path."

## Decision

**Adopt a tiered, normalized substring/token-overlap residue scan — zero new dependency.** Defer
embedding-based semantic matching.

On `verify_delete(id)`, after deleting the entry and confirming its absence, scan the **remaining**
store for residue of the deleted content using, in order:

1. **Exact-substring** match of distinctive fragments of the deleted content against each surviving
   entry (catches verbatim copies — the credential/secret case).
2. **Normalized match** — lowercase, fold whitespace/punctuation, and **canonicalize numbers and
   currency** (e.g. `$5000` ⇆ `$5k`, `5,000` ⇆ `5000`) before substring/token-overlap comparison.
   This is what catches the scoping doc's named `$5000 → $5k` fragment and near-verbatim paraphrase.
3. **Token-overlap threshold** — flag an entry whose overlap of distinctive tokens with the deleted
   content exceeds a tuned threshold (catches reordered/partial fragments).

- **`deletion_hash`:** a deterministic **SHA-256** (stdlib `crypto/sha256`) over the canonical
  deletion operation (the id + the deleted content), suitable for later audit-trail (RFC-6962-style)
  chaining. Deterministic now; chaining is future.
- **Response shape (contract extension, backward-compatible):**
  `verify_delete(id) -> { confirmed, residue_detected, residue_summary?, deletion_hash }`. `confirmed`
  retains its v0 meaning (the target id is gone). Callers that ignored the new fields do not break;
  `TestVerifyDeleteConfirmsAbsence` (v0) still passes with `residue_detected:false` added.

## Rationale

| Criterion (invariant) | Embedding (semantic) | Bloom signatures | **Normalized substring/token (chosen)** |
|---|---|---|---|
| Catches `$5000 → $5k` fragment | ✓ | ✗ | ✓ (numeric/currency canonicalization) |
| Catches verbatim secret residue | ✓ | ✓ | ✓ |
| Catches full paraphrase | ✓ | ✗ | ~ (the known miss class — recorded per residue class) |
| New dependency on hot path | ✗ ML model | ✓ none | ✓ none (stdlib only) |
| Meets >80% bar on realistic corpus | ✓ | ✗ | ✓ (corpus dominated by verbatim/normalized fragments) |
| Single static binary / low latency | ✗ | ✓ | ✓ |

Full semantic paraphrase ("the user with a five-thousand-dollar balance") is the **known miss class**
of a substring/token method — recorded honestly per residue class in the task's corpus, not hidden.
The >80% bar is met because realistic residue (the way fragments actually propagate across memory
entries: copy, truncate, abbreviate, renumber) is overwhelmingly verbatim-or-normalized, which this
method catches. Embedding-based matching is a clean future upgrade behind the same `verify_delete`
surface if the paraphrase class must be closed — and it can reuse a detector backend model **if**
ADR-002 ever adopts one (it currently does not, so no embedding dependency exists to borrow).

## Consequences

- `verify_delete` gains a residue scan over the remaining store — **no new dependency**, so
  `dep-scan` / `code-scanner` clear trivially (TC-006 note).
- The contract (`CONTRACT.md`), `data-model.md` (DeleteResult), `behaviors.md` B-003, and
  `interfaces.md` gain the `residue_detected` / `residue_summary` / `deletion_hash` fields — updated
  in task 003's commit (spec-in-the-same-commit rule).
- The residue scan runs on `verify_delete`, **not** on the read/write hot path, so its cost is off the
  most latency-sensitive paths; it stays O(store size × fragment compare), acceptable for the
  in-memory store and revisited when a real MemoryStore lands.

## Measured

Recorded by the task 003 implementation (`TestResidueCorpusDetectionRate` in `residue_test.go`;
reproduce with `go test -v -run TestResidueCorpusDetectionRate ./...`). The implemented method is the
tiered scan above plus a **tier 2b "contiguous distinctive phrase"** match (a ≥3-distinctive-token
contiguous span surviving verbatim/normalized), which catches multi-word secret fragments whose
individual tokens are too short to be "strong" on their own ("merger with Acme Corp"). Tuning:
single-token matches require a *strong* token (digit-bearing, or ≥8 chars) so a lone common word
never flags; tier-3 token-overlap threshold = 0.70 over ≥3 distinctive tokens.

- **Residue-detection rate on the labelled corpus (18 cases: 12 residue + 2 paraphrase + 4 clean):**
  | Residue class | Rate |
  |---|---|
  | verbatim | 5/5 = 100% |
  | normalized-numeric (incl. `$5000`→`$5k`, `5,000`→`5000`, k/m magnitudes, reordered/partial) | 7/7 = 100% |
  | paraphrase (the **documented known-miss class** of a substring/token method — not padded) | 0/2 = 0% |
  | **OVERALL** | **12/14 = 85.7%** (bar: >80% ✓) |
  | **Precision** | **0 false positives / 4 clean controls = 100%** |

  The >80% bar is met because realistic residue (copy / truncate / abbreviate / renumber) is
  overwhelmingly verbatim-or-normalized, which the method catches at 100%; the only misses are the two
  full-paraphrase cases, recorded honestly. Closing the paraphrase class is the deferred
  embedding-based upgrade behind the same `verify_delete` surface.
- **`dep-scan` / `code-scanner`:** no new dependency added — `go.mod` / `go.sum` unchanged; only
  `crypto/sha256` (stdlib) was newly imported. Trivially clear (TC-006).
