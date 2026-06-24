# memory-guard — Authoritative Spec

**Project:** memory-guard
**Last updated:** 2026-06-19

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of memory-guard. It answers:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured — output of every task that changes externally-observable behavior, the data
model, an interface, or configuration; and input to onboarding, drift audits, and (in the limit)
regenerating the codebase. The code is one realization of this spec. If they disagree, one is wrong —
fix it in the same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour | Snapshot, human-readable |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

## The seven sub-files

| File | Covers |
|------|--------|
| [behaviors.md](behaviors.md) | What the system does — validate_write (the write-gate, fail-closed on poisoning), PII redaction on write and read, validate_read, verify_delete (post-deletion verification), the IPC server, the write/read demos, fail-closed errors |
| [architecture.md](architecture.md) | C4 element catalog — persons, systems, the binary, its components |
| [data-model.md](data-model.md) | The in-memory store + entry, the `Detector` seam, the wire shapes (WriteResult/ReadResult/DeleteResult), error shape |
| [interfaces.md](interfaces.md) | CLI (`serve`/`write`/`read`), the IPC protocol (`validate_write`/`validate_read`/`verify_delete`/`ping`), the `MemoryGuard` + `Detector` public surface |
| [configuration.md](configuration.md) | `--socket`, socket permissions, hook profile env vars, no secrets in repo |
| [fitness-functions.md](fitness-functions.md) | Proposed executable invariants (write-gate fail-closed, PII never stored/returned raw, delete-verified, detector seam isolation, fail-closed errors) |

## Project summary

memory-guard is the **agent memory-I/O gate** for the secure-agent ecosystem (OWASP **ASI06** —
Memory & Context Poisoning). It sits in front of any agent memory store and gates every read and write:
poisoned writes are flagged and **rejected at ingestion** (the write-gate, fail-closed); PII is
**redacted before it lands in the store** and again on read; and deletions are **verified** — proven
gone, not merely `delete()`d. The write-gate and post-deletion verification are the **built delta** the
block owns; PII detection is the commodity layer beside them. The PII + injection detection lives behind
the **`Detector` seam** (`detector.go`) — the v0 ships a pure-Go `RegexDetector` (a Presidio stand-in),
and a Presidio-backed detector (sidecar / ONNX) or a Go-native NER model can slot in behind the same
interface without changing the guard, the contract, or the IPC. The contract is
`validate_read` / `validate_write` / `verify_delete`, exposed over a CLI and a newline-delimited-JSON
Unix-socket IPC server. memory-guard is written in **Go** (single static binary, low per-call overhead
on the memory hot path). **Apache-2.0.**

> The contract is **tracer-validated**: memory-guard's own tracer-bullet (roadmap T6,
> [ADR-008](../architecture/decisions/008-contract-tracer-validation.md)) drives
> `validate_write → validate_read → verify_delete` over the live `serve` socket against the real
> `MemoryStore` seam, asserting each verb's response field-by-field on the JSON decoded off the
> socket. The shapes validated **unchanged**. The detector dimension was validated against the v0
> `NativeDetector` (Presidio, task 007, is not yet merged); the shapes are detector-agnostic behind
> the `Detector` seam, and a real-backend re-validation is a noted follow-up.

## Top-level invariants

- **The write-gate is fail-closed on suspected poisoning.** `validate_write` runs injection detection
  **before** storage; a write flagged `injection_suspected` is **rejected** (`allow:false`,
  `stored_id:null`) and never persists. *(Enforced in `guard.go::ValidateWrite`; test
  `TestWriteGateRejectsSuspectedInjection`. Proposed fitness rule F-001.)*
- **PII is never stored or returned raw.** `validate_write` redacts via the `Detector` before storing;
  `validate_read` redacts again on the way out. The raw PII never enters the store and never appears in
  a response — it is replaced by `<LABEL>` placeholders. *(Enforced in `guard.go::ValidateWrite` /
  `ValidateRead`; test `TestWriteRedactsPIIAndStores`. Proposed fitness rule F-002.)*
- **Deletion is verified, not assumed.** `verify_delete` deletes the entry, **re-checks the store** to
  prove absence, and **scans surviving entries for residue** of the deleted content, returning
  `{confirmed, residue_detected, residue_summary?, deletion_hash}` — never a bare `delete()` whose
  success is assumed. v0 proves absence in the in-memory store and ships residue detection (normalized
  substring/token match, ADR-003); v1 extends the proof to every index/copy. *(Enforced in
  `guard.go::VerifyDelete` and `residue.go`; test `TestVerifyDeleteConfirmsAbsence`. Proposed fitness
  rule F-003.)*
- **The detection backend lives only behind the `Detector` seam.** No Presidio (or any backend)
  specific detail leaks past the `Detector` interface (`detector.go`) into the guard, the contract, or
  the IPC. Swapping `RegexDetector` for a Presidio-backed detector is a one-implementation change.
  *(Enforced by the `Detector` interface in `detector.go`. Proposed fitness rule F-004.)*
- **Fail-closed errors.** A malformed request or an unknown op returns the structured error shape
  `{error:{code,message,retryable}}`; nothing is stored or returned. *(Enforced in `ipc.go`. Proposed
  fitness rule F-005.)*
- **The agent receives an opaque `stored_id`, never the raw stored value.** A successful
  `validate_write` returns `mem-<hex>` (from `crypto/rand`), not the value — supporting the
  zero-knowledge-of-stored-form principle. *(Enforced in `guard.go::ValidateWrite`.)*

## Non-goals (current scope)

These are stated as facts about what memory-guard **is not yet**, not as a roadmap (planned work lives
in `docs/plans/` / `docs/tasks/`):

- **The `Detector` is a pure-Go `RegexDetector`, not Presidio.** A few high-signal recognizers, not the
  production PII engine. The Presidio-backed detector (sidecar / ONNX) is behind the seam but not built;
  the detector deployment shape and the hot-path latency budget are **unresolved** — settled in the
  memory-guard tracer.
- **The store is a plain in-memory `map`, not a real MemoryStore.** No LangChain / LlamaIndex / SQLite /
  vector-store backend; the map is the MemoryStore stand-in behind the `validate_*` verbs. Nothing
  persists across a restart.
- **`verify_delete` proves absence only in the in-memory store.** v1 extends the proof to **every
  index/copy** (semantic residue detection — the documented gap).
- **Identity-scoped reads are enforced; the index and in-guard verification are not yet final.**
  `validate_read` returns a writer's entry only under a **matching attested** identity (`{spiffe_id,
  trust_tier}`), with an **unbound-only** fallback for unattested/absent readers (ADR-004 / task 009).
  Enforcement is a **linear identity filter** over the store — the durable form is a per-identity
  index/partition behind the `MemoryStore` seam (deferred). Identity is **pre-verified upstream**
  (agent-mesh); in-guard SVID verification (`SvidVerifyingPrincipal`) is deferred behind the `Principal`
  seam.
- **No adversarial poisoning test-suite.** The v0 injection detector is regex-based; the
  MINJA-/GRAGPoison-class adversarial suite the write-gate is measured against is v1.
- **Audit emission is wired but default-disabled.** The `AuditSink` seam (`audit.go`) is wired and
  the OCSF event shape is modelled on the public OCSF 1.1 standard (ADR-007). Emission is **default-
  disabled** pending confirmation of the sibling audit-trail's emit endpoint; once confirmed, wiring a
  real `AuditSink` is a one-implementation change with zero guard/IPC/contract impact.
- **Not the tool-call / web-ingestion guard.** That boundary is `armor`'s (ASI01); memory-guard gates
  what gets **stored** (ASI06).
</content>
