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
| Memory store | External (in-tree backings ship in v0) | The backing `MemoryStore` behind the seam (ADR-005); ships as a stdlib in-memory map (`InMemoryStore`) or a multi-index store (`TwoIndexStore`); a LangChain / LlamaIndex / SQLite / vector backend slots in behind the same `Put`/`Get`/`Delete`/`Scan`/`All` verbs | secure-agent ecosystem |
| audit-trail | External | Receives detection events (flags → OCSF) — **v1; not wired in v0** | secure-agent ecosystem |
| armor | External | Guards the tool-call / web-ingestion path (ASI01); memory-guard guards what gets **stored** (ASI06) | secure-agent ecosystem |

Note: memory-guard guards what gets **stored**; `armor` guards what **enters** the agent. The
`audit-trail` emission is a v1 integration — v0 returns detections as `flags` but does not emit them.

---

## 3. Containers

| Name | Technology | Responsibility | Source path | Depends on |
|------|------------|----------------|-------------|------------|
| memory-guard binary | Go (`go 1.26`) single static binary | Gate every memory write (write-gate, fail-closed on poisoning), redact PII on write and read, and verify deletions (`validate_write`/`validate_read`/`verify_delete`); serve over a `0600` Unix socket or run the one-shot `write`/`read` demos | `detector.go`, `store.go`, `guard.go`, `residue.go`, `ipc.go`, `main.go` | **stdlib only** (`go.mod` has no `require` block) |

**Invariants for this table**
- The single container corresponds to the one Go `package main` (the single-binary layout, ADR-001 §2).
- **Go** runtime dependencies are **the Go standard library only** — `go.mod` stays `require`-free. The
  first third-party dependency (the Presidio backend, ADR-009) is realized as an **out-of-process Python
  sidecar**, so it adds **no Go module** — the single-static-Go-binary property holds. The sidecar's
  pinned Python deps cleared `dep-scan` (all security checks pass; informational provenance WARN
  accepted) and are opt-in (`MEMGUARD_DETECTOR=presidio`).

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| memory-guard binary | CLI | `main.go` | Parse `serve`/`write`/`read` subcommands and `--socket`; run the in-process `write`/`read` demos (print `WriteResult`/`ReadResult` JSON); start `serve`; exit `2` on a missing/unknown subcommand | IPC server, MemoryGuard core |
| memory-guard binary | IPC server | `ipc.go` | `serve`: remove a stale socket, bind the `0600` Unix socket, frame newline-delimited JSON, dispatch `validate_write`/`validate_read`/`verify_delete`/`ping` over a shared `*MemoryGuard` (goroutine per connection); structured error shape `{error:{code,message,retryable}}` (`bad_request`/`unknown_op`) | MemoryGuard core |
| memory-guard binary | MemoryGuard core | `guard.go` | Holds a `MemoryStore` (the seam, behind a `sync.Mutex`) + `ValidateWrite` (write-gate: `DetectInjection` → fail-closed on `injection_suspected` → `RedactPII` → `store.Put`), `ValidateRead` (`store.Scan` → `RedactPII`), `VerifyDelete` (`store.Delete` → re-check absence via `store.Get` → residue scan over `store.All()` survivors → `deletion_hash`, returning `{confirmed, residue_detected, residue_summary?, deletion_hash}`); mints the opaque `stored_id` (`mem-<hex>`) from `crypto/rand`. The value-add the block owns | Detector seam, MemoryStore seam, residue scan |
| memory-guard binary | MemoryStore seam | `store.go` | The `MemoryStore` interface (`Put` / `Get` / `Delete` / `Scan` / `All`) + two stdlib backings — `InMemoryStore` (the default single `map[string]entry`) and `TwoIndexStore` (a primary `id→entry` map PLUS a secondary `content→ids` index; `Delete` purges both). The boundary that isolates the storage backend; only `string`/`entry`/`[]entry` cross it, so a swap is one-line with no guard/IPC/contract change (ADR-005) | — (stdlib only) |
| memory-guard binary | Detector seam | `detector.go`, `detector_config.go`, `detector_presidio.go` | The `Detector` interface (`RedactPII` / `DetectInjection`) + three backends selected by `NewDetectorFromConfig` (`MEMGUARD_DETECTOR`): `RegexDetector` and the Go-native `NativeDetector` (ADR-002 default, stdlib `regexp`), plus the opt-in `PresidioDetector` (ADR-009) — a composite of native structured PII + Presidio NER, talking to the Python sidecar over stdlib JSON IPC; injection delegated to native UNCHANGED. The boundary that isolates the detection backend (no backend type leaks past the seam) | Presidio sidecar (opt-in); else — (stdlib only) |
| **Presidio sidecar** (external, opt-in) | Presidio analyzer subprocess | `presidio/sidecar.py` | Out-of-process Python: loads spaCy NER + Presidio recognizers ONCE (warm process), serves `{"op":"analyze","text":…}` → entity spans over newline-delimited JSON on stdin/stdout. NO outbound network at runtime. Pinned base-only deps (presidio-analyzer/anonymizer 2.2.362, spacy 3.8.14, en_core_web_lg 3.8.0). Reached ONLY behind the `Detector` seam | presidio-analyzer, spaCy (pinned, scanned) |
| memory-guard binary | Residue scan | `residue.go` | Post-deletion residue detection (normalized substring/token match for surviving fragments of deleted content per ADR-003) + the deterministic `deletion_hash` (SHA-256 over `id`+content for audit-trail linkage). Invoked by `VerifyDelete`; not a Detector concern | — (stdlib `crypto/sha256`, `regexp` only) |

---

## 5. Cross-cutting decisions

- **Write-gate fail-closed** — `ValidateWrite` rejects suspected poisoning before storage; the poisoned
  entry never persists. ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **PII redacted before storage and again on read** — the raw PII never enters the store and never
  appears in a response. (ADR-001 §1)
- **`Detector` seam isolates the detection backend** — `RegexDetector` / the Go-native `NativeDetector`
  (default) / the opt-in Presidio sidecar (ADR-009) are all selectable behind the seam (config-driven
  via `MEMGUARD_DETECTOR`) without changing the guard, the contract, or the IPC; no backend type leaks
  past the seam. (ADR-001 §3, ADR-002, ADR-009)
- **Post-deletion verification** — `VerifyDelete` proves absence (re-checks the in-memory store) and
  scans surviving entries for residue of the deleted content, returning a `deletion_hash` for
  audit-trail linkage; never a bare `delete()`. v0 ships residue detection (normalized
  substring/token match, ADR-003); v1 extends the proof to every index/copy. (ADR-001 §5, ADR-003)
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
