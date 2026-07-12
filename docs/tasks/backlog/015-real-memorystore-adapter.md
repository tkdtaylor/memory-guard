# Task 015: Real MemoryStore adapter (file-backed, persistent)

**Project:** memory-guard
**Created:** 2026-07-11
**Status:** backlog

> Roadmap [T1](../../plans/roadmap.md) is the foundational v1 item: "back the `MemoryStore` interface with a real store instead of the in-memory map. The single map is *why* delete-proof and identity can't be real yet." Task 006 extracted the seam and task 008 proved it against a second in-memory adapter (`TwoIndexStore`), but **every adapter is still process-memory**: kill the process and the "store" never existed. `verify_delete`'s proof is therefore still a proof about a map. This task adds the first **persistent** adapter, stdlib-only, so "the entry is gone" becomes "the bytes are gone from disk-backed state".

## Goal

Add a **file-backed `MemoryStore` adapter** (`FileStore`) behind the existing, unchanged seam (`store.go::MemoryStore`: `Put` / `Get` / `Delete` / `Scan` / `All` / `AllByIndex`), selected by configuration the same way the detector backend is (`MEMGUARD_STORE` mirroring `MEMGUARD_DETECTOR`, a `NewStoreFromConfig` factory mirroring `detector_config.go::NewDetectorFromConfig`). Writes are crash-safe (temp file + fsync + rename); every verb reads through to disk; and the residue scan + absence re-check inside `guard.go::VerifyDelete` therefore run against **actual persistence**. The in-memory map stays the default and the test workhorse behind the same seam.

## Context

- **Where the seam lives:** `store.go` defines `MemoryStore` and two adapters, `InMemoryStore` (a named map type; the v0 default) and `TwoIndexStore` (primary map + secondary content index; the task-008 multi-index proof). `primaryIndexName = "primary"` is the canonical single-index label.
- **How the guard consumes it:** `guard.go::NewMemoryGuard(det, store ...MemoryStore)` defaults to `NewInMemoryStore()`; `ValidateWrite` → `Put`, `ValidateRead` → `Scan`, `VerifyDelete` → `Get` + `Delete` + post-delete `Get` (the absence proof) + `residueScanIndexes(deleted.content, g.store.AllByIndex())` (`residue.go`). The guard serializes store access under `g.mu`; adapters do not need internal locking (same model as the existing two).
- **What an `entry` is:** `guard.go` struct `entry{content string; boundIdentity string; flags []string}`. All three fields must round-trip through persistence: `boundIdentity` is the load-bearing isolation key from task 009 / ADR-004, and task 016 (durable identity isolation) depends on this task persisting it faithfully.
- **How selection works today:** it doesn't. `main.go` always builds the default store; only the detector is configurable (`MEMGUARD_DETECTOR` → `detectorBackend()` → `buildDetector()` → `NewDetectorFromConfig`, which keeps backend Go types out of `main.go` so the seam-isolation fitness gate stays clean). This task replicates that exact pattern for the store.
- **Why JSONL-snapshot-rewrite, not append-only:** an append-only log keeps a deleted entry's bytes on disk (tombstones), which would make the byte-level delete proof false by construction. The chosen design (full-snapshot rewrite via temp+rename on every mutation) is the simplest stdlib-only layout where a delete physically removes the bytes at the canonical path. Record this trade-off (and the rejected append-only and per-entry-file layouts) in the new ADR.
- **Roadmap reconciliation (deviation, deliberate):** T1's parenthetical suggests "vector/LangChain/LlamaIndex memory". Those require third-party dependencies; AGENTS.md pins the substrate stdlib-only and makes any new dependency an ask-first ADR + dep-scan gate. A file-backed adapter is the real, persistent store achievable inside those constraints; a vector-store adapter remains a future additive adapter behind the same unchanged seam. State this explicitly in the ADR so nobody reads this task as foreclosing T1's vector option.
- **Default stays `memory` (deviation, deliberate):** the one-shot CLI demos (`go run . write`) and the existing tracer/tests assume an ephemeral store; flipping the global default to `file` is a behavior change deferred to an explicit follow-on decision. Persistence is opt-in via `MEMGUARD_STORE=file`.

## Contract shapes

Unchanged. `validate_write` / `validate_read` / `verify_delete` keep their tracer-validated shapes (docs/CONTRACT.md); the `MemoryStore` interface keeps its six verbs with unchanged signatures. New surface is configuration only:

```
MEMGUARD_STORE       = "memory" (default) | "file"
MEMGUARD_STORE_PATH  = absolute path to the JSONL store file (required when MEMGUARD_STORE=file)
```

Persisted wire record (one JSON object per line, internal to `store_file.go`, never crossing the seam):

```jsonc
{"id": "mem-a1b2c3", "content": "<redacted content>", "bound_identity": "spiffe://…|''", "flags": ["pii:EMAIL"]}
```

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A `FileStore` adapter in a new `store_file.go` implements all six `MemoryStore` verbs with the semantics documented on the interface (idempotent `Delete`, non-nil `All`/`AllByIndex` slices, `AllByIndex` exposing exactly the `"primary"` index). No seam signature changes; `guard.go` / `ipc.go` / `docs/CONTRACT.md` logic untouched. | must have |
| REQ-002 | Entries persist across independent constructions: a new `FileStore` on the same path returns previously-written entries with `content`, `boundIdentity`, and `flags` field-for-field intact. | must have |
| REQ-003 | Every mutation (`Put`, `Delete`) rewrites the snapshot **crash-safely**: write full JSONL to `<path>.tmp` in the same directory, fsync, then `os.Rename` over `path` (mode `0o600`). The canonical path never holds a partially-written snapshot. | must have |
| REQ-004 | Verbs **read through to disk**: no in-memory entry cache; `Get`/`Scan`/`All`/`AllByIndex` parse the current file, so a second handle (or restarted process) on the same path always sees persisted truth. | must have |
| REQ-005 | Byte-level delete proof: after `VerifyDelete` on a FileStore-backed guard, the deleted content's bytes are absent from the store file and from any `<path>.tmp` remnant, and the verb's response keeps the exact contract keys. | must have |
| REQ-006 | The residue scan and post-delete absence re-check operate on persisted state: a guard freshly constructed over an existing file detects residue among on-disk survivors and names the `"primary"` index in `residue_summary`. | must have |
| REQ-007 | A `NewStoreFromConfig(backend, path string) (MemoryStore, error)` factory in a new `store_config.go` (string keys `"memory"` / `"file"`, mirroring `detector_config.go`) is the single construction point; unknown backend or `file` without a path is a fail-closed error, never a silent fallback. `main.go` gains `storeBackend()` / `buildStore()` reading `MEMGUARD_STORE` / `MEMGUARD_STORE_PATH`, exits `2` on config errors, and names only strings, never a store Go type. | must have |
| REQ-008 | The map store stays behind the seam as the default and the test workhorse: `NewMemoryGuard` defaults unchanged; the parameterized parity suite (`store_test.go::TestGuardBehaviorParityAcrossStores`, `TestMemoryStoreSeamVerbs`) is extended to include `FileStore`, plus byte-level assertions that a rejected poisoned write never reaches disk and raw PII never lands in the file. | must have |
| REQ-009 | Corruption fails closed: an unparseable store file (or a record missing required fields) is a construction **error**, not an empty store; the corrupt file is left untouched. Runtime I/O failure after successful construction panics with a descriptive message (fail fast, crash loudly); record this posture and its alternatives in the ADR. | must have |
| REQ-010 | Seam isolation preserved: add `"FileStore"` and the wire-record type name to `fitness_test.go::seamBannedStoreTokens` and `store_test.go::TestNoStoreBackendLeak`; `make fitness` green; `go.mod` stays `require`-free (stdlib only). | must have |
| REQ-011 | Runtime-visible selection is exercised live: a tracer-style live-socket test drives write → read → delete against a FileStore-backed daemon and asserts the on-disk bytes before/after; `MEMGUARD_STORE=bogus` and `MEMGUARD_STORE=file` without a path exit `2` with clear stderr. | must have |
| REQ-012 | ADR (next free number, expected ADR-012) records the design: snapshot-JSONL with atomic rewrite, read-through-disk, byte-level delete proof, default-stays-memory, the rejected append-only/per-entry-file/vector-dep options, and the T1 reconciliation. `docs/spec/configuration.md` (new env-var rows), `docs/spec/data-model.md` (persisted record), `docs/spec/architecture.md` + `docs/architecture/diagrams.md` (new adapter behind the seam) updated in the same commit. | must have |

## Implementation outline

1. `scripts/start-task.sh 015 real-memorystore-adapter`; move this file to `docs/tasks/active/`.
2. Write the ADR (design + rejected options above); commit `docs: add ADR NNN — file-backed MemoryStore adapter`.
3. `store_file.go`: `FileStore{path string}` + `NewFileStore(path string) (*FileStore, error)` (constructor validates any existing file; missing/empty file is a valid empty store). Internal helpers: `load() []fileRecord` (parse the file; panic with context on post-construction I/O errors), `save([]fileRecord)` (marshal one record per line, write `<path>.tmp`, `f.Sync()`, `os.Rename`). Implement the six verbs over load/save; reuse `substringContains` for `Scan`; `AllByIndex` returns `map[string][]entry{primaryIndexName: all}`.
4. `store_config.go`: `StoreMemory = "memory"`, `StoreFile = "file"`, `NewStoreFromConfig`.
5. `main.go`: `storeBackend()` / `storePath()` env readers + `buildStore()` (exit `2` on error, message pattern matching `buildDetector`); pass the store to `NewMemoryGuard` in the `serve`, `write`, and `read` arms. Strings and the generic factory only.
6. Tests per the spec: new `store_file_test.go` (TC-001…TC-006, TC-009), factory cases (TC-007), parity-suite extension in `store_test.go` (TC-008), banned-token updates (TC-010), and the live-socket FileStore tracer case (TC-011a), following `contract_tracer_test.go::startLiveDaemon`.
7. Spec + diagram updates (REQ-012), same commit as the code. Add the 015 row to `docs/tasks/test-specs/coverage-tracker.md` at 🟡.
8. `make check` green; run the L6 observation (below); move this file to `docs/tasks/completed/`; commit `feat: complete task 015 — real-memorystore-adapter`.

## Readiness gate

- [x] Test spec `015-real-memorystore-adapter-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Confirm the constructor-with-error shape (`NewFileStore(path) (*FileStore, error)`) against how `NewStoreFromConfig` reports errors, before writing code
- [ ] Confirm no existing test constructs stores positionally in a way the new wiring would break (`grep -rn "NewMemoryGuard(" *_test.go`)

## Acceptance criteria

- [ ] [REQ-001] All six seam verbs behave per the interface docs on `FileStore` (TC-001).
- [ ] [REQ-002] Full `entry` (content, boundIdentity, flags) survives re-construction (TC-002).
- [ ] [REQ-003] Mutations are atomic temp+rename snapshots; stale tmp never promoted (TC-003).
- [ ] [REQ-004] A second handle on the same path sees persisted truth immediately (TC-004).
- [ ] [REQ-005] Deleted content bytes absent from disk after `verify_delete`, with the positive control asserting they were present before (TC-005).
- [ ] [REQ-006] Residue detected and named from on-disk survivors by a freshly-constructed guard (TC-006).
- [ ] [REQ-007] Factory fail-closed on unknown backend / missing path; `main.go` string-only (TC-007).
- [ ] [REQ-008] Parity suite green across all three adapters; poisoned writes and raw PII never reach the file (TC-008).
- [ ] [REQ-009] Corrupt file → construction error, file untouched (TC-009).
- [ ] [REQ-010] Banned-token lists extended; `make fitness` green; `go.mod` require-free (TC-010).
- [ ] [REQ-011] Live-socket FileStore slice green; bad-config exits observed with exit code 2 (TC-011).
- [ ] [REQ-012] ADR written; configuration/data-model/architecture spec files + diagrams updated in the feat commit.
- [ ] `go build ./... && go test ./...` green; `make check` green.

## Verification plan

- **Highest level achievable: L6**, an operator-observed live run: `MEMGUARD_STORE=file MEMGUARD_STORE_PATH=/tmp/memguard-015.jsonl go run . serve --socket /tmp/mg-015.sock`, drive `{"op":"validate_write","entry":"the launch memo veloheliotrope must vanish"}` then `{"op":"verify_delete","id":"<stored_id>"}` via `nc -U /tmp/mg-015.sock`, and quote `grep -c veloheliotrope /tmp/memguard-015.jsonl` → non-zero between the calls, `0` after.
- **Level 2 (unit):** `go test ./...` → `ok` (store_file, factory, parity, corruption cases).
- **Level 3 (gate):** `make fitness` and `make check` exit 0; `MEMGUARD_FITNESS_SEAM_BREACH=FileStore make fitness-seam` exits non-zero (red-path probe).
- **Level 5 (validation harness):** the FileStore live-socket tracer case (TC-011a) drives write → read → delete over a real Unix socket against the persisted file and asserts on-disk bytes before/after; also re-run the existing contract tracer, `go test -run TestTracer ./...`, to confirm the shapes are untouched. Record the final assertion lines in the verify commit.

## Out of scope

- Flipping the default store to `file` (explicit follow-on decision; noted in the ADR).
- Any vector / embedding / third-party store adapter (future additive adapter behind the same seam; would trigger the ask-first dependency ADR + dep-scan/code-scanner gate).
- Identity-scoped lookup through the seam and shared scopes (task 016).
- Compaction, file locking across processes, or multi-file segmenting (single-writer model is the documented v1 posture; note in the ADR).
- Any change to `Detector`, IPC verbs, or the contract shapes.

## Dependencies

- **Builds on (all completed):** task 006 (MemoryStore seam / ADR-005), task 008 (residue across indexes / ADR-006), task 003 (residue verification / ADR-003).
- **Blocks:** task 016 (durable identity isolation) and, at the roadmap level, the T3 "residue proof across every index/copy of a real store" claim maturing beyond in-memory adapters.
- **No dependency on tasks 016/017**; note both 015 and 017 touch `main.go`, so execute them sequentially, not in parallel worktrees.
