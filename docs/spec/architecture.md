# Architecture — C4 Element Catalog

**Project:** memory-guard
**Last updated:** 2026-06-19

The structured catalog of architectural elements that
[`../architecture/diagrams.md`](../architecture/diagrams.md) renders. Tables here are the
machine-readable spec for the structure — a drift audit checks the code against them.

---

## 1. Persons (actors)

| Name | Description | Goals |
|------|-------------|-------|
| Autonomous agent core | The agent runtime that reads from and writes to memory | Store only safe, PII-redacted content; retrieve redacted content; verify deletions |
| Operator | Human running the daemon or the demos | Start `serve`; run `write` / `read` to verify the write-gate + redaction |

---

## 2. Systems

| Name | Type | Description | Owner |
|------|------|-------------|-------|
| memory-guard | In-scope | Agent memory-I/O gate (ASI06): write-gate, PII redaction, post-deletion verification; `validate_read`/`validate_write`/`verify_delete` | This team |
| Memory store | External (stand-in in v0) | The backing MemoryStore (LangChain / LlamaIndex / SQLite / vector store); v0 is an in-memory `map` behind the `validate_*` verbs | secure-agent ecosystem |
| audit-trail | External | Receives detection events (flags → OCSF) — **v1; not wired in v0** | secure-agent ecosystem |
| armor | External | Guards the tool-call / web-ingestion path (ASI01); memory-guard guards what gets **stored** (ASI06) | secure-agent ecosystem |

Note: memory-guard guards what gets **stored**; `armor` guards what **enters** the agent. The
`audit-trail` emission is a v1 integration — v0 returns detections as `flags` but does not emit them.

---

## 3. Containers

| Name | Technology | Responsibility | Source path | Depends on |
|------|------------|----------------|-------------|------------|
| memory-guard binary | Go (`go 1.26`) single static binary | Gate every memory write (write-gate, fail-closed on poisoning), redact PII on write and read, and verify deletions (`validate_write`/`validate_read`/`verify_delete`); serve over a `0600` Unix socket or run the one-shot `write`/`read` demos | `detector.go`, `guard.go`, `ipc.go`, `main.go` | **stdlib only** (`net`, `encoding/json`, `crypto/rand`, `regexp`, `bufio`, `sync`) |

**Invariants for this table**
- The single container corresponds to the one Go `package main` (the single-binary layout, ADR-001 §2).
- Runtime dependencies are **the Go standard library only** — no third-party modules in v0. The first
  external dependency will be the Presidio-backed `Detector` (sidecar SDK / ONNX runtime / NER model),
  a future ADR; on adoption it makes `dep-scan` / `code-scanner` blocking gates.

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| memory-guard binary | CLI | `main.go` | Parse `serve`/`write`/`read` subcommands and `--socket`; run the in-process `write`/`read` demos (print `WriteResult`/`ReadResult` JSON); start `serve`; exit `2` on a missing/unknown subcommand | IPC server, MemoryGuard core |
| memory-guard binary | IPC server | `ipc.go` | `serve`: remove a stale socket, bind the `0600` Unix socket, frame newline-delimited JSON, dispatch `validate_write`/`validate_read`/`verify_delete`/`ping` over a shared `*MemoryGuard` (goroutine per connection); structured error shape `{error:{code,message,retryable}}` (`bad_request`/`unknown_op`) | MemoryGuard core |
| memory-guard binary | MemoryGuard core | `guard.go` | The in-memory store (`map[string]entry` behind a `sync.Mutex`) + `ValidateWrite` (write-gate: `DetectInjection` → fail-closed on `injection_suspected` → `RedactPII` → store), `ValidateRead` (substring scan → `RedactPII`), `VerifyDelete` (delete → re-check absence); mints the opaque `stored_id` (`mem-<hex>`) from `crypto/rand`. The value-add the block owns | Detector seam |
| memory-guard binary | Detector seam | `detector.go` | The `Detector` interface (`RedactPII` / `DetectInjection`) + the v0 `RegexDetector`: PII recognizers (EMAIL, US_SSN, CREDIT_CARD, API_KEY → `<LABEL>` + `pii:<LABEL>` flags) and injection patterns (ignore/disregard-instructions, `system prompt`, `<system>`/`<instructions>` tags → `["injection_suspected"]`). The Presidio stand-in; the boundary that isolates the detection backend | — (stdlib `regexp` only) |

---

## 5. Cross-cutting decisions

- **Write-gate fail-closed** — `ValidateWrite` rejects suspected poisoning before storage; the poisoned
  entry never persists. ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **PII redacted before storage and again on read** — the raw PII never enters the store and never
  appears in a response. (ADR-001 §1)
- **`Detector` seam isolates the detection backend** — the v0 `RegexDetector` can be swapped for a
  Presidio-backed detector (sidecar / ONNX) or a Go-native NER model without changing the guard, the
  contract, or the IPC. (ADR-001 §3)
- **Post-deletion verification** — `VerifyDelete` proves absence (v0: re-checks the in-memory store;
  v1: every index/copy), never a bare `delete()`. (ADR-001 §5)
- **Fail-closed errors** — every malformed/unknown request resolves to a structured error; nothing is
  stored. (ADR-001 §7)
- **Single-binary Go layout** — one `package main`, deployed as a static binary alongside the agent.
  (ADR-001 §2)
- **Opaque `stored_id`** — a successful write returns `mem-<hex>` from `crypto/rand`, never the raw
  value. (ADR-001 §1/§4)

---

## Maintenance

- Update in the same commit as `../architecture/diagrams.md` when structure changes.
- Supersede in place; never append. The ADR carries the *why*.
- The drift-audit mode of the `architect` agent uses this catalog against the module graph and the
  deployable-artifact list. The dependency set (**stdlib only** in v0) is recorded in Container §3
  `Depends on`; the first third-party module (the Presidio-backed detector) updates that cell in the
  same commit and makes dep-scan / code-scanner blocking gates.
</content>
