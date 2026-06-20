# Task 003: Post-deletion verification across every index/copy

**Project:** memory-guard
**Created:** 2026-06-19
**Status:** backlog (not started)

> Post-deletion verification is the **documented industry blind spot** the block exists to close
> (scoping §6, arXiv 2604.16548). v0 proves only "absent from the in-memory map." This task makes
> `verify_delete` prove **gone, not just deleted** — across every index/copy.

## Goal

Extend `verify_delete` from "the entry is absent from the in-memory store" to "**no semantic residue of
the deleted content survives anywhere in the store**" — the v1 contract the scoping doc names. A deleted
"user John's balance is $5000" must not survive as "John's balance is $5k" in another entry. The
response gains the residue fields the contract already specifies: `residue_detected` and
`residue_summary` (and a `deletion_hash` for audit linkage), surfacing partial copies the bare delete
misses.

## Context

- Source: the project's internal design notes
  §4 ("Detailed v0 contract: `verify_delete` → {confirmed, residue_detected, residue_summary,
  deletion_hash}"), §6 ("Post-Deletion Verification" — semantic residue detection, method TBD), §8.
- Code under change: `MemoryGuard.VerifyDelete` (`guard.go`) — today it deletes + re-checks the map.
  This task adds the residue scan over the remaining entries.
- **Method is an open decision** (scoping §6 / ADR-001 "Open questions"): exact-substring matching
  (credentials), embedding-based semantic matching (sensitive concepts), or Bloom-filter deleted-content
  signatures. Pick one (or a tiered combination) and record it in an ADR; prefer the lightest that
  meets the >80% residue-detection acceptance bar (scoping §8) without a heavy ML dependency on the hot
  path.
- **Soft-depends on task 001** if an embedding method is chosen (it may reuse the detector backend's
  model); a substring/Bloom method has no such dependency.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) B-003, [`docs/CONTRACT.md`](../../CONTRACT.md)
  (`verify_delete`), [`docs/spec/data-model.md`](../../spec/data-model.md) (DeleteResult shape).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `verify_delete` deletes the entry, then **scans the remaining store** for semantic residue of the deleted content, returning `{confirmed, residue_detected, residue_summary?, deletion_hash}`. | must have |
| REQ-002 | `confirmed=true, residue_detected=false` only when the entry is gone **and** no residue is found; `confirmed=true, residue_detected=true` when the entry is gone but a fragment survives elsewhere (with a `residue_summary`). | must have |
| REQ-003 | The residue-detection **method** (substring / embedding / Bloom) is chosen, implemented, and recorded in an ADR; it meets a residue-detection rate of **>80%** on a labelled residue corpus (scoping §8). | must have |
| REQ-004 | `deletion_hash` is a stable hash of the deletion operation, suitable for audit-trail linkage (RFC-6962-style chaining is future; the field is present and deterministic now). | should have |
| REQ-005 | The change is **backward-compatible**: a delete with no residue still returns `{confirmed:true}` (plus the new `residue_detected:false`), and `TestVerifyDeleteConfirmsAbsence` still passes. | must have |
| REQ-006 | Any new dependency (e.g. an embedding model) clears `dep-scan` + `code-scanner` and is pinned; a substring/Bloom method adds no dependency. | must have |

## Readiness gate

- [x] Test spec `003-post-deletion-residue-verification-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Residue-detection method chosen (substring / embedding / Bloom) — ADR
- [ ] Labelled residue corpus sourced for the >80% bar

## Acceptance criteria

- [ ] [REQ-001] `verify_delete` returns the residue fields after a post-delete scan (TC-001).
- [ ] [REQ-002] The `confirmed`/`residue_detected` truth table holds (TC-002).
- [ ] [REQ-003] Residue method implemented; >80% detection on the corpus; ADR written (TC-003).
- [ ] [REQ-004] `deletion_hash` present + deterministic (TC-004).
- [ ] [REQ-005] Backward-compatible; v0 delete test still green (TC-005).
- [ ] [REQ-006] dep-scan/code-scanner clear any new dep; pinned (TC-006).
- [ ] `go build ./... && go test ./...` green.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) runs the residue corpus
  through `verify_delete` and the final assertion reports >80% residue detection + the truth-table
  cases passing; plus **L3** dep-scan/code-scanner on any embedding dependency.
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`, incl. the residue corpus and truth table.
- **Level 6 (optional):** `go run .` / a live `serve` `verify_delete` on a seeded store with a known
  residue → observe `residue_detected:true` + summary. Record the residue-detection rate in the ADR +
  `behaviors.md` B-003.
</content>
