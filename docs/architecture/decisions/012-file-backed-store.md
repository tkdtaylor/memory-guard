# ADR-012: File-backed `MemoryStore` adapter (snapshot-JSONL with atomic rewrite, read-through-disk)

**Status:** Accepted
**Date:** 2026-07-12
**Task:** [015 (Real MemoryStore adapter, file-backed, persistent)](../../tasks/completed/015-real-memorystore-adapter.md)
**Relates to:** ADR-005 (the `MemoryStore` seam this adapter plugs into), ADR-003 / ADR-006 (post-deletion residue verification, the consumer whose proof this makes byte-level), ADR-002 (the `Detector` seam whose config-driven selection pattern this mirrors for the store).

## Context

Every `MemoryStore` adapter shipped so far (`InMemoryStore`, `TwoIndexStore`) is **process memory**: kill the process and the "store" never existed. `verify_delete`'s absence proof (ADR-003) is therefore a proof about a map, and "the entry is gone" means "the key is gone from a `map` that dies with the process." Roadmap T1 asks for a **real store behind the seam**. The load-bearing security claim the whole block rests on, *deletion is verified, not assumed*, is only as strong as the persistence it is proven against.

This task adds the first **persistent** adapter, stdlib-only, so "the entry is gone" becomes "the bytes are gone from disk-backed state." Two sub-decisions had to be settled:

1. **On-disk layout:** how entries are physically laid out so a delete *removes the bytes*.
2. **Corruption / runtime-failure posture:** what happens when the file is unparseable at construction, or an I/O call fails after construction.

## Decision

**Add `FileStore` (`store_file.go`): a single JSONL snapshot file, rewritten atomically (temp file + `fsync` + `os.Rename`) on every mutation, read through to disk on every verb, selected by configuration (`MEMGUARD_STORE` / `MEMGUARD_STORE_PATH`) via a `NewStoreFromConfig` factory (`store_config.go`) that mirrors `detector_config.go`.** The in-memory map stays the default.

- **Layout is full-snapshot JSONL rewrite, not append-only.** The canonical file holds one JSON object per line: `{"id","content","bound_identity","flags"}`. Every `Put` / `Delete` marshals the *entire* current entry set and rewrites the file. A delete physically removes the deleted entry's bytes from the canonical path.
- **Crash-safe writes.** A mutation writes the full snapshot to `<path>.tmp` in the *same directory*, `f.Sync()`s it, then `os.Rename`s it over `path` (mode `0o600`). `os.Rename` within a directory is atomic on POSIX, so the canonical path never holds a partially-written snapshot; a crash mid-write leaves either the old complete snapshot or the new complete snapshot, never a torn one.
- **Read-through-disk, no cache.** `Get` / `Scan` / `All` / `AllByIndex` each parse the current file. A second handle (or a restarted process) on the same path always sees persisted truth. There is no per-handle in-memory copy that could diverge from disk. This is what makes the residue scan and the post-delete absence re-check (inside `guard.go::VerifyDelete`) run against *actual persistence*.
- **Config-driven selection, string-only at the call site.** `NewStoreFromConfig(backend, path)` (keys `"memory"` / `"file"`) is the single construction point; `main.go` gains `storeBackend()` / `buildStore()` reading `MEMGUARD_STORE` / `MEMGUARD_STORE_PATH`, naming only backend *strings* and the generic factory, never a store Go type, so the seam-isolation fitness gate (F-004) stays clean.
- **Fail-closed factory.** An unknown backend name, or `file` without a path, is a construction **error** (`os.Exit(2)` from `main.go`), never a silent fallback to memory or a default file location.
- **Corruption fails closed at construction.** An unparseable line, or a record missing a required field, makes `NewFileStore` return an error and leaves the file **untouched** (never truncated, never treated as empty, since that would orphan real data). A runtime I/O failure *after* successful construction panics with a descriptive message (fail fast, crash loudly).

## Rationale: why snapshot-rewrite, not append-only or per-entry-file

| Criterion | Append-only log (tombstones) | Per-entry file | **Snapshot-JSONL rewrite (chosen)** |
|---|---|---|---|
| Delete removes the bytes | ✗ deleted bytes linger as history before a tombstone; the byte-level delete proof is **false by construction** | ✓ unlink the file | ✓ rewrite without the entry |
| Crash-safety | ✓ append is atomic | ~ per-file rename, many files | ✓ single temp+rename |
| Stdlib-only, one binary | ✓ | ✓ | ✓ |
| Simplicity of "every index/copy" scan | ~ must replay the log | ✗ directory walk | ✓ one parse |
| Write cost | O(1) append | O(1) per entry | O(n) rewrite per mutation |

The byte-level delete proof is the whole point: memory-guard exists to prove deletion, and an append-only log keeps a deleted entry's bytes on disk (as pre-tombstone history), which would make the headline claim false the moment it is written to disk. Snapshot-rewrite is the simplest stdlib-only layout where a delete *physically removes the bytes* at the canonical path. The cost is an O(n) rewrite per mutation; for the single-writer, moderate-volume memory-gate workload this is acceptable, and compaction / segmenting / cross-process file locking are explicitly out of scope (single-writer model is the documented v1 posture).

## Deviations recorded (deliberate)

- **Default stays `memory`, not `file`.** Flipping the global default is a behavior change (the one-shot CLI demos and the tracer/tests assume an ephemeral store). Persistence is opt-in via `MEMGUARD_STORE=file`; flipping the default is an explicit follow-on decision.
- **T1's "vector/LangChain/LlamaIndex" parenthetical is *not* foreclosed.** Those require third-party dependencies, which AGENTS.md pins behind an ask-first ADR + `dep-scan` gate. A file-backed adapter is the real, persistent store achievable inside the stdlib-only constraint; a vector-store adapter remains a future *additive* adapter behind the same unchanged seam.

## Consequences

- `verify_delete`'s absence proof and the residue scan now run against disk-backed state when `MEMGUARD_STORE=file`; "the entry is gone" is a byte-level claim, asserted by scanning the store file (and any `<path>.tmp` remnant) for the deleted content.
- `entry`'s three fields (`content`, `boundIdentity`, `flags`) all round-trip through persistence. `boundIdentity` persisting faithfully is the prerequisite task 016 (durable identity isolation) builds on: isolation becomes a property of the stored bytes, re-enforced by an independently constructed guard.
- The stdlib-only property holds. `FileStore` uses only `encoding/json`, `os`, `bufio`, `path/filepath`; `go.mod` stays `require`-free.
- The seam is unbroken: `FileStore` and its wire-record type (`fileRecord`) are added to the banned-token lists (`fitness_test.go::seamBannedStoreTokens`, `store_test.go::TestNoStoreBackendLeak`), so no store-backend specific leaks into `guard.go` / `ipc.go` / `main.go` / `CONTRACT.md`.
