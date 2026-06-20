# Test Spec 003: Post-deletion verification across every index/copy

**Linked task:** [`docs/tasks/backlog/003-post-deletion-residue-verification.md`](../backlog/003-post-deletion-residue-verification.md)
**Written:** 2026-06-19

> Authored ahead of execution. The residue scan + truth table are **unit-verifiable locally**. The
> >80% detection bar (TC-003) needs the labelled residue corpus; the dep-scan gate (TC-006) only
> applies if an embedding method pulls a model dependency (a substring/Bloom method makes it trivial).

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ (needs corpus) | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-006 | ⚠️ only if an embedding dep is added | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] `TestVerifyDeleteConfirmsAbsence` (v0) is preserved

## Test fixtures

- **Residue corpus** — labelled triples: a primary entry, a deletion target, and one or more
  *residue* entries (semantic fragments of the deleted content, e.g. `$5000` → `$5k`) plus *no-residue*
  controls (unrelated entries). Each case labelled `residue` / `clean`.

## Test cases

### TC-001: verify_delete scans for residue and returns the residue fields
- **Requirement:** REQ-001
- **Input:** seed an entry + a residue entry; `verify_delete(id of the primary)`.
- **Expected:** `{confirmed:true, residue_detected:true, residue_summary:"…", deletion_hash:"…"}` —
  the response carries the new fields after a post-delete scan of the remaining store.
- **Edge cases:** delete of an id with no surviving residue → `residue_detected:false`, no summary.

### TC-002: the confirmed / residue_detected truth table holds
- **Requirement:** REQ-002
- **Input:** (a) delete with no residue; (b) delete with surviving residue; (c) delete of an absent id.
- **Expected:** (a) `confirmed:true, residue_detected:false`; (b) `confirmed:true, residue_detected:true`
  + summary; (c) `confirmed:true, residue_detected:false` (absent is gone). `confirmed` always reflects
  the post-delete presence check; `residue_detected` reflects the scan.
- **Edge cases:** an entry whose own content is the residue source is itself deleted → no self-residue
  false positive.

### TC-003: residue method meets >80% detection on the corpus
- **Requirement:** REQ-003
- **Input:** run every `residue` case through the chosen method (substring / embedding / Bloom).
- **Expected:** ≥80% of residue cases flagged `residue_detected:true`; `clean` controls stay false
  (precision tracked). The method + rate are recorded in the ADR.
- **Edge cases:** paraphrase-level residue (semantic, not substring) is the hard case the method choice
  must address; record the rate per residue class.

### TC-004: deletion_hash present and deterministic
- **Requirement:** REQ-004
- **Input:** delete the same logical operation twice (fresh store, same content/id scheme).
- **Expected:** `deletion_hash` is present and a deterministic function of the deletion operation —
  suitable for later audit-trail chaining.
- **Edge cases:** different deleted content → different hash.

### TC-005: backward-compatible — v0 delete behavior preserved
- **Requirement:** REQ-005
- **Input:** the exact `TestVerifyDeleteConfirmsAbsence` scenario (benign note, delete, re-delete).
- **Expected:** still returns `confirmed:true` (now with `residue_detected:false`); the v0 test passes
  unchanged. No caller that ignored the new fields breaks.
- **Edge cases:** re-deleting an absent id still confirms gone with no residue.

### TC-006: dep-scan/code-scanner clear any new dependency
- **Requirement:** REQ-006
- **Input:** if an embedding method adds a model dependency, run `gods` + `code-scanner` on the tree.
- **Expected:** pass, exit 0, pinned. A substring/Bloom method adds **no** dependency — note that in
  the ADR and this case is trivially satisfied.
- **Edge cases:** a flagged transitive module blocks that method; fall back to a lighter residue method.
</content>
