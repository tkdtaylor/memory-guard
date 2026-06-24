# Task 006: MemoryStore seam + one real adapter

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** completed (🟡 code merged — pending spec-verifier + L5/L6 promotion to ✅)

> The single in-memory `map` in `guard.go` is the load-bearing **stand-in** that keeps the headline at
> "v0 substrate." It is *why* delete-proof (T3) and identity isolation (T4) can't be real — you cannot
> prove "absent from **every** index/copy" with one index, and you cannot scope reads across tenants
> with one flat map. This task extracts the store behind a seam (mirroring the `Detector` seam) and
> proves the seam with a second, real adapter. Roadmap **T1** — foundational, unblocks T3 + T4.

## Goal

Extract a `MemoryStore` interface from the in-memory `map[string]entry` currently inlined in
`MemoryGuard` (`guard.go`), modelled on the existing `Detector` seam: the guard talks to the store
only through stable verbs (`Put` / `Get` / `Delete` / `Scan` / a residue-supporting `All`), and **no
backend specific detail leaks past that seam** into the guard, the contract, or the IPC. Ship **two
concrete implementations** behind the seam: the existing in-memory map as the **default** adapter
(`InMemoryStore`, backward-compatible), and **one real adapter beyond the map** (a vector- /
LangChain- / LlamaIndex-style memory, or — at minimum — a second concrete store, e.g. a SQLite- or
bbolt-backed store) that exercises the seam under a genuinely different backing representation. The
write-gate, PII redaction, `verify_delete` proof, and the `Detector` seam are **untouched in
behavior** — they now route their storage through `MemoryStore` instead of a bare map.

## Context

- **Code under change:** `MemoryGuard` (`guard.go`) — the `store map[string]entry` field and every
  site that touches it (`ValidateWrite` puts, `ValidateRead` scans, `VerifyDelete` deletes + iterates
  survivors for the residue scan). The map moves behind a new `MemoryStore` interface (its own file,
  e.g. `store.go`, mirroring `detector.go`). `MemoryGuard.mu` and the residue scan (`residue.go`) move
  to operate over the seam's accessors, not the raw map.
- **Why now (roadmap T1):** the residue scan (task 003 / ADR-003) proves "no residue in *the one
  map*." A real store has multiple backing indexes/copies (a vector index + a doc store, say); T3's
  "residue across every index/copy" is meaningless until there is more than one index to scan, which
  only exists once the store is a real adapter behind a seam. Likewise T4 (identity-scoped reads) needs
  a store that can partition by identity — impossible to assert cleanly against an inlined flat map.
- **Seam discipline (the load-bearing constraint):** this mirrors the `Detector` seam exactly. Only
  `string` / `entry` / `[]entry`-shaped values cross the boundary — **no** vector-client type, no SQL
  handle, no LlamaIndex object leaks into `guard.go`, the contract, or `ipc.go`. Swapping the default
  in-memory store for the real adapter must be a one-line construction change (`NewMemoryGuard(det,
  store)`), with **zero** contract / guard / IPC impact — the same property that made the `Detector`
  backend choice cheap to make and cheap to revisit (ADR-002).
- **Dependency posture:** a real vector-store / LangChain / LlamaIndex client is a **new third-party
  dependency** — v0 is stdlib-only (`go.mod` has no `require` block). That is an **ask-first ADR +
  `dep-scan` / `code-scanner` blocking gate**, exactly as for the Presidio backend (T2). If the gate
  is undesirable for this task, the "one real adapter" requirement is satisfiable with a **stdlib-only
  second store** (e.g. a file-backed or two-index in-memory store) that still proves the seam — the
  ADR records which path was taken and why.
- Reference: [`docs/plans/roadmap.md`](../../plans/roadmap.md) (T1), [`AGENTS.md`](../../../AGENTS.md)
  (invariants + the `Detector` seam this mirrors), [`docs/CONTRACT.md`](../../CONTRACT.md),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (`MemoryGuard.store`, the `entry` type).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A `MemoryStore` interface is extracted (its own file, mirroring `detector.go`) exposing stable verbs — `Put(id, entry)`, `Get(id) (entry, bool)`, `Delete(id)`, `Scan(query) []entry` (substring match for `validate_read`), and `All() []entry` (the survivors the residue scan iterates). `MemoryGuard` holds a `MemoryStore`, not a `map`. | must have |
| REQ-002 | The existing in-memory map becomes the **default** implementation `InMemoryStore`; `NewMemoryGuard` constructs it when no store is supplied, so the CLI / `serve` defaults are unchanged. **All existing tests stay green unmodified** (`guard_test`, `residue_test`, `poisoning_suite_test`, corpus + detector tests). | must have |
| REQ-003 | **One real adapter beyond the map** is implemented behind the seam (a vector- / LangChain- / LlamaIndex-style store, or at minimum a second concrete store with a genuinely different backing representation — e.g. SQLite/bbolt/file-backed/two-index). The **same guard-behavior suite passes against both stores** (write-gate, PII redaction, read, delete+residue) — proving the seam, not just compiling it. | must have |
| REQ-004 | **No backend specifics leak past the seam.** `guard.go`, `docs/CONTRACT.md`, and `ipc.go` carry no store-backend type or import; only `string` / `entry` / `[]entry` cross the boundary. A swap from `InMemoryStore` to the real adapter is a one-line construction change with no contract/guard/IPC diff. | must have |
| REQ-005 | **All load-bearing invariants are preserved through the seam:** the write-gate stays **fail-closed** (an `injection_suspected` write calls **no** `Put` and persists nothing); **PII is never stored or returned raw** (only redacted `content` is `Put`, redacted again on `Scan`/read); `verify_delete` still **proves absence** via a fresh post-delete `Get` (not the `Delete` return) and runs the residue scan over `All()` survivors; the **error shape `{error:{code,message,retryable}}` is unchanged**; the **`Detector` seam is untouched**. | must have |
| REQ-006 | Any **new third-party dependency** for the real adapter (vector-store / LangChain / LlamaIndex client) is treated as **ask-first**: recorded in an ADR, pinned, and cleared by `dep-scan` (`gods`) + `code-scanner` as a **blocking gate** before merge. A stdlib-only second store adds **no** dependency — note that in the ADR and the gate is trivially satisfied. | must have |

## Readiness gate

- [x] Test spec `006-memorystore-seam-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Real-adapter backend chosen (vector / LangChain / LlamaIndex / stdlib second store) — ADR
- [ ] If a third-party client is chosen: `dep-scan` + `code-scanner` run and clear, version pinned
- [ ] Confirmed the `MemoryStore` verb set covers every current map access in `guard.go` (Put/Get/Delete/Scan/All)

## Acceptance criteria

- [ ] [REQ-001] `MemoryStore` interface extracted; `MemoryGuard` holds it, not a `map` (TC-001).
- [ ] [REQ-002] `InMemoryStore` is the default; all existing tests pass unmodified (TC-002).
- [ ] [REQ-003] A second real adapter exists; the shared guard-behavior suite passes against **both** (TC-003).
- [ ] [REQ-004] No store-backend type/import in `guard.go` / `ipc.go` / `CONTRACT.md`; swap is one line (TC-004).
- [ ] [REQ-005] Write-gate fail-closed (no `Put`), PII never stored/returned raw, `verify_delete` proves absence via post-delete `Get` + residue over `All()`, error shape + `Detector` seam unchanged (TC-005).
- [ ] [REQ-006] dep-scan/code-scanner clear any new dep, pinned + ADR; a stdlib store satisfies it trivially (TC-006).
- [ ] `go build ./... && go test ./...` green; `docs/spec/data-model.md` updated to describe the seam.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) runs the **same**
  guard-behavior suite parameterized over **both** `MemoryStore` implementations (table-driven /
  shared subtest), asserting identical write-gate, redaction, read, and delete+residue outcomes — the
  seam is proven by behavioral parity across two backings, not by compilation. Plus **L3**
  `dep-scan` / `code-scanner` on any third-party adapter dependency.
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`, including the parameterized two-store suite,
  the fail-closed write-gate assertion (no `Put` on an injection-flagged write), and the
  no-leak/seam-isolation check.
- **Level 6 (optional):** `go run . serve` (or `write`/`read`) against the real adapter wired as the
  store → observe a clean write, a redacted read, and a `verify_delete` proving absence on the real
  backing. Record the chosen backend + the gate result in the ADR and `docs/spec/data-model.md`.
