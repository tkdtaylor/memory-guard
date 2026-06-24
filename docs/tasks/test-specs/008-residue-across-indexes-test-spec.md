# Test Spec 008: Residue proof across every index/copy

**Linked task:** [`../backlog/008-residue-across-indexes.md`](../backlog/008-residue-across-indexes.md)
**Written:** 2026-06-24

> Authored ahead of execution, and the direct successor to test-spec 003. Task 003 proved residue over
> the survivors in **one** in-memory map (85.7% residue / 100% precision, with full-paraphrase the
> documented 0/2 known-miss). This task extends the proof to **every backing index/copy** of the real
> `MemoryStore` (so it **depends on task 006** — the `MemoryStore` seam) and takes a real run at the
> paraphrase miss-class. The multi-index scan + truth table are **unit-verifiable locally**; the
> >80% bar (TC-003) needs the multi-index residue corpus; the paraphrase class (TC-007) is measured
> **separately** so a regression there can never be masked by the verbatim/normalized cases. The
> dep-scan gate (TC-008) applies **only if** the paraphrase improvement pulls an embedding-model
> dependency — and a lighter, stdlib-only method is preferred precisely so it stays trivial.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ (needs multi-index corpus) | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-006 | ✅ | ✅ |
| REQ-007 | TC-007 | ✅ (paraphrase sub-corpus) | ✅ |
| REQ-008 | TC-008 | ⚠️ only if an embedding dep is added | ✅ |

## Pre-implementation checklist

- [ ] Task 006 (`MemoryStore` seam) is merged — the multi-index scan has a seam to enumerate
- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] `TestVerifyDeleteConfirmsAbsence` (v0) and the task-003 residue tests are preserved and pass
      unchanged when the store is single-index

## Test fixtures

- **Multi-index residue corpus** — labelled cases where the deleted content's residue survives in a
  **different backing index/copy** than the primary store map (e.g. a vector/embedding index, a
  recency cache, a secondary id→content map exposed through the `MemoryStore` seam). Each case names
  which index the residue lands in, and is labelled `residue` / `clean`. Reuses and extends the
  task-003 single-store corpus so the single-index cases stay green.
- **Paraphrase sub-corpus** — the full-paraphrase residue cases (the task-003 0/2 known-miss class,
  e.g. `user John's balance is $5000` → `the user with a five-thousand-dollar balance`), held and
  scored **separately** from the verbatim/normalized cases so the paraphrase rate is reported on its
  own and cannot be diluted by the easy classes.
- **Clean controls** — unrelated entries across the same set of indexes, to track precision (no
  false positive in any index).

## Test cases

### TC-001: residue scan covers every backing index/copy, not just the primary map
- **Requirement:** REQ-001
- **Input:** through the `MemoryStore` seam, seed an entry plus a residue fragment that lives in a
  **secondary** index/copy (not the primary map); `verify_delete(id of the primary)`.
- **Expected:** `{confirmed:true, residue_detected:true, residue_summary:"…", deletion_hash:"…"}` —
  the summary names the index/copy the residue survives in. The scan enumerates **every** backing
  index the `MemoryStore` exposes, so residue in a non-primary copy is caught (the single-map scan
  would have missed it).
- **Edge cases:** residue present in two indexes → still one `residue_detected:true` with a summary
  identifying at least the first (deterministic, highest-confidence) match; no index left unscanned.

### TC-002: confirmed / residue_detected truth table holds across indexes
- **Requirement:** REQ-002
- **Input:** (a) delete with no residue in any index; (b) delete with residue in a secondary index;
  (c) delete of an absent id; (d) delete where residue is in the primary map (the task-003 case).
- **Expected:** (a) `confirmed:true, residue_detected:false`; (b) `confirmed:true,
  residue_detected:true` + summary naming the secondary index; (c) `confirmed:true,
  residue_detected:false`; (d) `confirmed:true, residue_detected:true` (unchanged from task 003).
  `confirmed` reflects the post-delete absence check across the store; `residue_detected` reflects
  the multi-index scan.
- **Edge cases:** the deleted entry's own copies (its primary entry and any index entry for the same
  id) are removed before the scan → no self-residue false positive in any index.

### TC-003: multi-index residue rate meets/maintains the >80% bar (now across indexes)
- **Requirement:** REQ-003
- **Input:** run every `residue` case in the multi-index corpus (verbatim + normalized classes,
  residue landing in assorted indexes) through `verify_delete`.
- **Expected:** ≥80% of multi-index residue cases flagged `residue_detected:true` — at least matching
  task 003's 85.7% now measured **across multiple indexes** rather than one map. `clean` controls in
  every index stay false (precision tracked, target: maintain 100% / no regression). The per-index
  and overall rates are recorded in the ADR/`behaviors.md` B-003.
- **Edge cases:** a residue fragment split across two indexes (half in each) is reported per the
  documented method; record its class.

### TC-004: deletion_hash present and deterministic (unchanged contract field)
- **Requirement:** REQ-004
- **Input:** delete the same logical operation twice (fresh multi-index store, same content/id).
- **Expected:** `deletion_hash` present and a deterministic function of the deletion op — identical
  across runs, suitable for audit-trail chaining. Multi-index does not change the hash (it is over
  id + deleted content, not over the index layout).
- **Edge cases:** different deleted content → different hash; same content reachable through two
  indexes → still one stable hash.

### TC-005: backward-compatible — single-store behavior and task-003 residue tests stay green
- **Requirement:** REQ-005
- **Input:** run the exact `TestVerifyDeleteConfirmsAbsence` (v0) scenario and the task-003 residue
  tests (`TestVerifyDeleteReturnsResidueFields`, `TestVerifyDeleteTruthTable`,
  `TestResidueCorpusDetectionRate`, `TestDeletionHashDeterministic`) against a single-index store.
- **Expected:** all pass **unchanged** — when the `MemoryStore` exposes a single index, the
  multi-index scan reduces exactly to the task-003 single-map scan. No caller that ignored the new
  behavior breaks; the contract shape is identical (`{confirmed, residue_detected, residue_summary?,
  deletion_hash}`).
- **Edge cases:** a store with one index and zero survivors → `residue_detected:false`, no summary.

### TC-006: residue scan stays GUARD-SIDE, not behind the Detector seam
- **Requirement:** REQ-006
- **Input:** inspect the multi-index residue scan's call path (and run `go test ./...`).
- **Expected:** the scan is invoked from `VerifyDelete` (guard-side, `residue.go`) over the
  `MemoryStore` seam's indexes; it makes **no** call into the `Detector` interface and imports no
  detector backend. String/semantic matching of deleted content is not PII/injection detection, so it
  must not cross the `Detector` seam (the boundary task 003 established is preserved).
- **Edge cases:** the paraphrase improvement (REQ-007), even if it uses embeddings, lives guard-side
  in `residue.go` (or a residue-specific helper) — it does **not** reach through `Detector`.

### TC-007: paraphrase miss-class measured separately and improved over the task-003 0/2 baseline
- **Requirement:** REQ-007
- **Input:** run the **paraphrase sub-corpus** (the task-003 0/2 full-paraphrase cases plus added
  paraphrase variants) through `verify_delete`, scored on its own.
- **Expected:** the paraphrase residue rate is reported as a standalone number and is **strictly
  better than the 0/2 baseline** (at least one paraphrase case now flagged), with precision on the
  clean controls held (no new false positives from the paraphrase method). The method used and its
  paraphrase rate are recorded in an ADR; if a lighter (stdlib-only) method reaches the improvement,
  that is preferred and no dependency is added.
- **Edge cases:** if the chosen method is conservative and still misses a hard paraphrase, that case
  is recorded honestly as a residual known-miss (not padded) — the requirement is *improvement +
  separate measurement*, not 100% paraphrase recall.

### TC-008: dep-scan/code-scanner clear any new dependency the paraphrase method pulls
- **Requirement:** REQ-008
- **Input:** if the paraphrase improvement (REQ-007) adds an embedding-model or any third-party
  dependency, run `gods` (dep-scan) + `code-scanner` over the resulting module tree.
- **Expected:** pass, exit 0, version pinned, recorded in the ADR. A stdlib-only paraphrase method
  adds **no** dependency — note that in the ADR and this case is trivially satisfied (as in task 003).
- **Edge cases:** a flagged transitive module blocks that method → fall back to the lighter,
  no-dependency paraphrase method; do not adopt the dependency to chase paraphrase recall.
</content>
</invoke>
