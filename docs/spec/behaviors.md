# Behaviors

**Project:** memory-guard
**Last updated:** 2026-06-19

What the system does, observably — triggering condition, response, externally-visible side effects,
failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry points*
([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Validate a memory write (`validate_write`) — the write-gate, fail-closed on poisoning

- **Trigger:** `{"op":"validate_write","entry":…,"identity":{…}}` over IPC, or
  `MemoryGuard.ValidateWrite(text, identity)` in-process (the `write` CLI subcommand).
- **Response:** the guard runs **injection detection first** (`Detector.DetectInjection`). If the
  content is flagged `injection_suspected`, the write is **rejected fail-closed** —
  `{ "allow": false, "stored_id": null, "flags": [ …, "injection_suspected" ] }` — and **nothing is
  stored**. Otherwise the content is **PII-redacted** (`Detector.RedactPII`, PII → `<LABEL>`
  placeholders), an opaque `stored_id` of the form `mem-<hex>` is minted from `crypto/rand`, the
  **redacted** content is inserted into the in-memory store under that id, and the guard returns
  `{ "allow": true, "stored_id": "mem-…", "flags": […] }`. `flags` carries the PII categories found
  (e.g. `pii:EMAIL`) as informational metadata.
- **Side effects:** on a clean write, mutates the in-memory store (with the **redacted** content +
  identity + flags). On a rejected write, no store mutation.
- **Failure modes:** a write flagged for poisoning never persists (the write-gate). The raw PII is
  **never** stored — only the redacted form. The agent receives the opaque `stored_id`, **never** the
  raw value. *(Tests: `TestWriteGateRejectsSuspectedInjection`, `TestWriteRedactsPIIAndStores`, `TestPoisoningRecallPrecision`, `TestPoisoningFailClosedPerCase` — adversarial recall=0.69, precision=0.85 on the v0 4-pattern regex; measured 2026-06-19 against 32-case corpus; see fitness-functions.md F-006.)*

### B-002: Validate a memory read (`validate_read`) — redact PII on the way out

- **Trigger:** `{"op":"validate_read","query":…,"identity":{…}}` over IPC, or
  `MemoryGuard.ValidateRead(query, identity)` in-process (the `read` CLI subcommand).
- **Response:** the guard scans the in-memory store for entries whose content **contains the query
  substring**, joins the matching contents with newlines, runs `Detector.RedactPII` over the joined
  result (defense in depth — PII redacted again on read), and returns
  `{ "allow": true, "content_redacted": "…", "flags": […] }`. v0 always returns `allow:true`; `flags`
  carries any PII categories the read-time redaction found.
- **Side effects:** none (read-only).
- **Failure modes:** a query matching no entries yields an empty `content_redacted` and an empty
  `flags`. PII that somehow reached the store is still redacted on the way out. *(Test:
  `TestWriteRedactsPIIAndStores` — the read half asserts `<EMAIL>` present and `alice@example.com`
  absent.)*

### B-003: Verify a deletion (`verify_delete`) — prove absence **and** scan for surviving residue

- **Trigger:** `{"op":"verify_delete","id":…}` over IPC, or `MemoryGuard.VerifyDelete(id)` in-process.
- **Response:** the guard (1) removes the entry keyed by `id` from the in-memory store, (2)
  **re-checks** the store for that id (`confirmed:true` iff no longer present — the v0 proof), then
  (3) **scans the remaining store for residue** of the just-deleted content and returns
  `{ "confirmed", "residue_detected", "residue_summary"?, "deletion_hash" }`. `residue_detected:true`
  means a verbatim or near-verbatim fragment of the deleted content survives in another entry (the
  documented industry gap a bare `delete()` misses); when true, `residue_summary` names the match
  class (`verbatim` / `normalized` / `phrase` / `token-overlap N%`) and the surviving entry. The
  residue scan is a tiered, normalized substring / contiguous-phrase / token-overlap match (ADR-003) —
  deterministic, **stdlib-only guard-side orchestration**, with **no** detector backend involvement.
  `deletion_hash` is a deterministic SHA-256 over the deletion op (`id` + deleted content) for
  audit-trail linkage.
- **Side effects:** removes the entry from the in-memory store (idempotent — deleting an absent id is a
  no-op that still confirms gone). The scan is read-only over the survivors.
- **Failure modes:** deleting an unknown or already-deleted id still returns `confirmed:true,
  residue_detected:false` (no scan — there is no deleted content to scan for). Because the scan runs
  over the store *after* the target is removed, a deleted entry never flags itself (no self-residue
  false positive). Full semantic paraphrase is the known miss class of the substring/token method
  (ADR-003), recorded honestly per residue class. *(Tests: `TestVerifyDeleteConfirmsAbsence` (v0 compat),
  `TestVerifyDeleteReturnsResidueFields`, `TestVerifyDeleteTruthTable`, `TestResidueCorpusDetectionRate`,
  `TestDeletionHashDeterministic`.)*

### B-004: Serve over a `0600` Unix-socket IPC server (`serve`)

- **Trigger:** `memory-guard serve --socket <path>`.
- **Response:** removes any stale socket at `<path>`, binds a Unix socket, sets permissions to `0600`
  (owner-only), logs `memory-guard serving on <path>` to stderr, and accepts connections — spawning a
  goroutine per connection over a shared `*MemoryGuard`. Each accepted connection sends one
  newline-delimited JSON object `{op, …}`; ops are `validate_write` (B-001), `validate_read` (B-002),
  `verify_delete` (B-003), and `ping` (→ `{"ok":true}`).
- **Side effects:** creates the socket file; spawns one goroutine per connection. The shared
  `MemoryGuard`'s `sync.Mutex` guards the store across concurrent connections.
- **Failure modes:** a missing `--socket` exits with a usage error (`2`). A bind failure returns a
  non-zero exit (`1`) with `error: …` on stderr. An empty / unreadable first line closes the connection
  with no response. *(No automated test — runtime-observable via a live `serve`.)*

### B-005: Reject a malformed or unknown request (fail-closed)

- **Trigger:** unparseable request JSON, or an `op` that is not `validate_write` / `validate_read` /
  `verify_delete` / `ping`.
- **Response:** the structured error shape `{ "error": { "code": …, "message": …, "retryable": false } }`.
  Codes in use: `bad_request` (unparseable JSON — the parse error message is echoed) and `unknown_op`
  (an unsupported op — `"unsupported op"`).
- **Side effects:** none; the connection is closed after the single response.
- **Failure modes:** the caller must treat any `error` response as a non-result (fail-closed); no store
  mutation occurs on a malformed/unknown request. *(No automated test — runtime-observable.)*

### B-006: One-shot in-process write demo (`write`)

- **Trigger:** `memory-guard write "<text>"`.
- **Response:** constructs a fresh `MemoryGuard` (default `RegexDetector`), runs `ValidateWrite(text,
  nil)` in-process, and prints the `WriteResult` as indented JSON to stdout — either a redacted-and-
  stored result (`allow:true`, a `stored_id`, `pii:*` flags) or a write-gate rejection (`allow:false`,
  `stored_id:null`, `injection_suspected`).
- **Side effects:** stdout only; no socket, no persistence across the process.
- **Failure modes:** an absent text argument validates the empty string (a benign clean write). *(No
  automated test for the CLI wrapper; the underlying `ValidateWrite` is unit-tested.)*

### B-007: One-shot in-process read demo (`read`)

- **Trigger:** `memory-guard read "<query>"`.
- **Response:** constructs a fresh `MemoryGuard`, **seeds** the store by running `ValidateWrite(query,
  nil)` (so the one-shot demo has something to read), then runs `ValidateRead(query, nil)` and prints
  the `ReadResult` as indented JSON — the redacted content and any flags.
- **Side effects:** stdout only; the seeded entry lives only for the process.
- **Failure modes:** if the seed text itself trips the write-gate (looks like injection), nothing is
  stored and the read returns empty content. *(No automated test for the CLI wrapper.)*

---

## Behavioral invariants

- **No poisoned write persists.** `validate_write` runs injection detection before storage; an
  `injection_suspected` flag rejects the write (`allow:false`, `stored_id:null`) and nothing enters the
  store. The write-gate is fail-closed.
- **PII is never stored or returned raw.** `validate_write` redacts before storing; `validate_read`
  redacts again on the way out. The raw PII is replaced by `<LABEL>` placeholders and appears in no
  response and in no stored entry.
- **The agent never receives the raw stored value.** `validate_write` returns an opaque `stored_id`
  (`mem-<hex>` from `crypto/rand`); the stored content is reachable only via `validate_read`, and only
  in redacted form.
- **Deletion is verified, and residue is hunted.** `verify_delete` re-checks the store after the
  delete and reports `confirmed` from that fresh check — never an assumed success from the `delete()`
  call — and additionally scans the remaining entries for a surviving fragment of the deleted content
  (`residue_detected`), the documented industry gap. A deleted entry never flags itself.
- **The detection backend is isolated behind the `Detector` seam.** All PII + injection detection goes
  through the `Detector` interface; the guard, the IPC, and the contract carry no backend-specific
  detail.
- **Every malformed / unknown request fails closed.** An unparseable request or an unknown op returns
  the structured error shape; nothing is stored or returned.

> **v0 scope note.** The store is an in-memory map, the detector is regex, reads match by substring
> across the whole store (no identity-scoped isolation), and detections are not yet emitted to
> `audit-trail`. These are stated facts about v0, tracked as limitations in [SPEC.md](SPEC.md) and
> [fitness-functions.md](fitness-functions.md), not behaviors to rely on as final.
</content>
