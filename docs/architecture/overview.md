# Architecture Overview

**Project:** memory-guard

**Last updated:** 2026-06-19

## System purpose

memory-guard is the **agent memory-I/O gate** for the secure-agent ecosystem (OWASP **ASI06** —
Memory & Context Poisoning). It sits in front of any agent memory store and gates every read and
write the agent performs, answering one question on the hot path:

> Is this safe to store, or safe to return?

The answer is enforced three ways: poisoned writes are **flagged and rejected at ingestion** (the
write-gate, fail-closed); PII is **redacted before it lands in the store** (and again on the way
out); and deletions are **verified** — proven gone, not merely `delete()`d. The first two are the
detection layer; the **write-gate and post-deletion verification are the built delta** the block
owns — the documented blind spots no framework-native memory store covers.

The PII + injection detection lives behind the **`Detector` seam**. That seam is deliberate: the v0
ships a pure-Go `RegexDetector` (a Presidio stand-in), but a Presidio-backed detector — run as a
sidecar/subprocess or via an ONNX runtime — or a Go-native NER model can slot in behind the same
interface without touching the guard, the contract, or the IPC. *Adopt the detection tool behind a
seam; don't let it dictate the substrate.*

memory-guard coordinates with the other ecosystem blocks: it emits detections to `audit-trail` (v1;
not wired in v0), and sits beside `armor` (which guards the tool-call / web-ingestion path) — armor
guards what enters the agent, memory-guard guards what gets *stored*.

## Component map

A single Go `package main` (a flat set of `*.go` files at the repo root):

| File | Responsibility |
|------|----------------|
| `detector.go` | The **`Detector` seam** — the `Detector` interface (`RedactPII` / `DetectInjection`) and the v0 `RegexDetector` (a few high-signal recognizers: EMAIL / US_SSN / CREDIT_CARD / API_KEY for PII; ignore/disregard-instructions, system-prompt, `<system>`/`<instructions>` tags for injection). The boundary that isolates the detection backend (Presidio) from the rest of the block. |
| `guard.go` | The `MemoryGuard` core and its `ValidateWrite` / `ValidateRead` / `VerifyDelete` methods — the value-add the block owns: the write-gate (fail-closed on suspected poisoning) and post-deletion verification (prove an entry is gone). Holds the in-memory store (a `map[string]entry`, the MemoryStore stand-in) behind a `sync.Mutex`. |
| `ipc.go` | The JSON-over-Unix-socket IPC server (`serve`): binds a `0600` socket, frames newline-delimited JSON, dispatches `validate_write` / `validate_read` / `verify_delete` / `ping`, and the structured error shape `{error:{code,message,retryable}}`. |
| `main.go` | CLI entrypoint. Dispatches `serve` (the IPC daemon), `write` (one-shot validate-write demo), and `read` (seed-then-read demo). |
| `go.mod` | Module `github.com/tkdtaylor/memory-guard` (`go 1.26`) — **no third-party dependencies** in v0. |

## Data flow

```
agent ──validate_write(entry)──▶ MemoryGuard                agent ──validate_read(query)──▶ MemoryGuard
                                   │  DetectInjection                                          │  scan store for hits
                                   ▼  (fail-closed if suspected)                               ▼  RedactPII(hits)
                            RedactPII → store(redacted)                              { allow, content_redacted, flags }
                            { allow, stored_id, flags }       agent ──verify_delete(id)──▶ MemoryGuard
                                                                                              │  delete(id), re-check absence
                                                                                              ▼
                                                                                       { confirmed }
```

On **write**, the guard runs `DetectInjection` first; if the content is flagged
`injection_suspected` it **fails closed** — `allow:false`, `stored_id:null`, nothing persists. Only a
clean write is PII-redacted via the detector and stored, returning an opaque `stored_id` (not the raw
value). On **read**, the guard scans the store for entries containing the query and redacts the
joined hits via the detector before returning them (defense in depth). On **delete**, the guard
removes the entry and **re-checks the store** to confirm absence, returning `{confirmed}`. The `write`
and `read` CLI subcommands run this flow in-process for operator verification, without binding a
socket.

## Key dependencies

**None in v0.** memory-guard runs on the Go standard library only — `net` (Unix socket),
`encoding/json` (the wire format), `crypto/rand` (`stored_id` minting), `regexp` (the v0 detector),
`bufio` / `sync`. memory-guard is written in **Go** specifically because it gates *every* memory op:
a single static binary with low per-call overhead, and because its value-add (write-gate +
delete-verification) is plain orchestration, not NLP. The one Python-leaning dependency the design
anticipates — **Microsoft Presidio** for PII — is isolated behind the `Detector` seam and is **not**
present in v0; adopting it (sidecar/ONNX) is a future ADR and the first `dep-scan` / `code-scanner`
blocking gate.

## Entry points

- `memory-guard serve --socket <path>` — long-running IPC daemon; binds a `0600` Unix socket and
  serves `validate_write` / `validate_read` / `verify_delete` / `ping` as newline-delimited JSON.
- `memory-guard write "<text>"` — one-shot in-process `ValidateWrite`; prints the `WriteResult` JSON
  (redacted-and-stored, or write-gate rejection).
- `memory-guard read "<query>"` — one-shot in-process demo: seeds the store with the query text, then
  `ValidateRead`s it; prints the redacted `ReadResult` JSON. Exit code `2` on a missing/unknown
  subcommand.

## Key decisions

- **The write-gate is fail-closed** — `ValidateWrite` rejects suspected poisoning before storage; the
  poisoned entry never persists. This is the central commitment, not the PII redaction.
- **PII is redacted before storage and again on read** — the raw PII is never stored and never
  returned (defense in depth).
- **Deletion is verified** — `VerifyDelete` proves absence (v0: re-checks the in-memory store), the
  documented gap most memory stores skip.
- **The `Detector` seam isolates the detection backend** — the v0 `RegexDetector` can be swapped for a
  Presidio-backed detector (sidecar / ONNX) or a Go-native NER model without changing the guard, the
  contract, or the IPC. The backend choice is deferred to the memory-guard tracer.
- **Single-binary Go layout** — a flat `package main`, not a multi-package tree; the gate deploys as
  one static binary alongside the agent.
- **Fail-closed error posture** — a malformed request or unknown op returns the structured error
  shape; the write-gate denies by default.

The full as-built record of these decisions is
[ADR-001 — Foundational stack](decisions/001-foundational-stack.md). Future decisions get their own
sequential ADRs.

## Current limitations (v0)

memory-guard is a **v0 skeleton against the v0 contract**. The following are *not yet* present —
stated as facts, not a roadmap (planned work lives in `docs/plans/` / `docs/tasks/`):

- **The `Detector` is a pure-Go `RegexDetector`** — a few high-signal recognizers, **not** Presidio.
  The Presidio-backed detector (sidecar / ONNX) is behind the seam but not built, and the detector
  deployment shape + hot-path latency budget are **unresolved** (settled in the memory-guard tracer).
- **The store is a plain in-memory `map`** — no real MemoryStore backend (LangChain / LlamaIndex /
  SQLite / vector store). It is the MemoryStore stand-in behind the `validate_*` verbs.
- **`verify_delete` proves absence only in the in-memory store** — v1 extends the proof to **every
  index/copy** (semantic residue detection — the documented gap).
- **No identity-scoped access** — `validate_read` / `validate_write` carry an `identity` but do not
  yet enforce tenant isolation; reads match by substring across the whole store.
- **No adversarial poisoning test-suite** — the v0 injection detector is regex-based; the
  MINJA-/GRAGPoison-class adversarial suite the write-gate is measured against is v1.
- **No audit-trail emission** — detections are returned as `flags` but not yet emitted as OCSF events
  to `audit-trail`.

## Design principles

memory-guard follows **Unix philosophy** — composability over monolithic design. The full statement
lives in `AGENTS.md`; the load-bearing instance here is the `Detector` seam: a small, well-defined
interface that lets an independently-evolving detection backend plug in without entanglement, so the
substrate (Go) stays independent of the detection tool (Presidio). The write-gate orchestration inside
`MemoryGuard` is deliberately cohesive (a monolithic choice for hot-path correctness) — composability
lives at the `Detector` boundary, not inside the gate.
</content>
