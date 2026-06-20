# ADR-001 — Foundational stack (as-built)

**Status:** Accepted
**Date:** 2026-06-19

## Context

memory-guard predates this ADR process: the v0 skeleton (`detector.go`, `guard.go`, `ipc.go`,
`main.go`, `guard_test.go`, `go.mod`) was committed before the project adopted the create-project
workflow. This bootstrap ADR consolidates the decisions the codebase **already commits to** as of
2026-06-19, so that subsequent ADRs have a coherent baseline to amend rather than free-floating in a
vacuum.

It does **not** back-number every prior micro-decision into fiction. It records the foundational
stack as observed in the source. Future ADRs (ADR-002, …) supersede or refine individual points.

The authoritative design rationale lives in `memory-guard.md` and
`interface-contracts.md §2`. Unlike vault, memory-guard was **out of the first tracer-bullet's
scope** (the slice is stateless — tracer-bullet.md §6), so the contract shapes here are **v0 and not
yet tracer-validated**; the block gets its own tracer once memory is in play, which may refine them.
This ADR records what is *built*, not the full prior-art survey. Prior-art verdict: **DERIVE** — adopt
Microsoft Presidio (PII) behind the `Detector` seam and OWASP Agent Memory Guard's architecture as the
reference design; **build** the write-gate, post-deletion verification, and the adversarial suite (the
delta no production tool covers).

## Decisions

### 1. The write-gate, fail-closed (the central commitment)

The agent must **never** persist content that looks like context poisoning. `ValidateWrite` runs
injection detection **before** storage; an entry flagged `injection_suspected` is **rejected** —
`allow:false`, `stored_id:null` — and never enters the store (`guard.go::ValidateWrite`). The
write-gate is the value-add; the PII redaction is the commodity layer beside it. This is the central
security commitment — *all writes are suspect until proven safe*, inverting the framework-native
assumption that the agent is trusted.

### 2. Language & packaging — Go single binary, `package main`

- A single Go `package main` — a flat set of `*.go` files at the repo root (`detector.go`,
  `guard.go`, `ipc.go`, `main.go`, `guard_test.go`), **not** a multi-package tree. Module
  `github.com/tkdtaylor/memory-guard`, `go 1.26`.
- **Go specifically** because memory-guard gates *every* memory op: per-call latency on the hot path
  matters, a single static binary deploys cleanly alongside the agent, and the value-add (write-gate +
  delete-verification) is plain orchestration, not NLP — Go is the right substrate, and the one
  Python-leaning dependency (Presidio) is isolated behind the `Detector` seam (§4).
- **No third-party dependencies in v0** — the standard library only (`net`, `encoding/json`,
  `crypto/rand`, `regexp`, `bufio`, `sync`). The smallest possible attack surface for a block on the
  memory hot path. The Presidio-backed detector is the first external dependency and a future ADR.
- Build/test tooling: `go build ./...`, `go test ./...` (tests beside source in `guard_test.go`), a
  `Makefile` (`build`/`test`/`fmt`/`clean`). No `make check` / `make fitness` target yet.

### 3. The `Detector` seam — the detection-backend boundary

PII + injection detection lives **only** behind the `Detector` interface (`detector.go`):

```go
type Detector interface {
    RedactPII(text string) (redacted string, flags []string)   // PII → <LABEL> placeholders + "pii:<LABEL>" flags
    DetectInjection(text string) []string                       // ["injection_suspected"] or nil
}
```

The v0 `RegexDetector` is a pure-Go stand-in for Presidio — a few high-signal recognizers (EMAIL,
US_SSN, CREDIT_CARD, API_KEY; ignore/disregard-instructions, system-prompt, `<system>`/`<instructions>`
tags). A Presidio-backed detector (sidecar/subprocess or ONNX runtime) or a Go-native NER model can
replace it **without touching the guard, the contract, or the IPC**. "Adopt the tool behind a seam;
don't let it dictate the substrate." The detector deployment shape and the hot-path latency budget are
**not decided here** — they are settled in the memory-guard tracer (§ Open questions).

### 4. Interface contract — `validate_read` / `validate_write` / `verify_delete` (the v0 contract)

```
validate_read(query, identity)  -> { allow, content_redacted, flags }
validate_write(entry, identity) -> { allow, stored_id, flags }    # write-gate: fail-closed on poisoning
verify_delete(id)               -> { confirmed }                  # post-deletion verification (the industry gap)
```

Mirrors `the ecosystem's interface contract §2`. The agent receives an opaque `stored_id` from a
successful write — not the raw value (zero-knowledge of the stored form). The `Detector` interface +
the `validate_*` verbs are the **adapter seam**: the v0 store is an in-memory map and the v0 detector
is regex, but any LangChain / LlamaIndex MemoryStore (behind the verbs) and any detection backend
(behind `Detector`) can slot in without changing callers.

> Note: these shapes are **v0 and not yet tracer-validated** — memory-guard was out of the first
> tracer-bullet's scope (stateless slice). Its own tracer, run when memory is in play, may refine them.

### 5. Post-deletion verification, not bare `delete()`

`VerifyDelete` deletes the entry and **re-checks the store** to confirm absence, returning
`{confirmed}` (`guard.go::VerifyDelete`). v0 proves absence from the in-memory store; v1 extends the
proof to **every index/copy** (semantic residue detection — a deleted "user John's balance is $5000"
must not survive as "John's balance is $5k" elsewhere). This is the documented industry blind spot —
no other memory-poisoning defense tool implements post-deletion verification.

### 6. IPC transport — newline-delimited JSON over a `0600` Unix socket

`serve --socket <path>` removes any stale socket, binds a Unix socket, and `chmod 0600`
(`ipc.go::serve`). Each connection sends one newline-delimited JSON object `{op, …}`; ops are
`validate_write`, `validate_read`, `verify_delete`, and `ping`. Responses are newline-delimited JSON:
the verb's result, or a structured error `{error:{code,message,retryable}}` for bad/unknown requests.
The server spawns a goroutine per connection over a shared `*MemoryGuard` (its own `sync.Mutex` guards
the store).

### 7. Fail-closed posture

Denial is the default. A write flagged for poisoning (§1) does not persist; a malformed request
(`bad_request`) or an unknown op (`unknown_op`) resolves to the structured error shape — nothing is
stored, nothing is returned. The PII redaction also runs on read, so even content that reached the
store is redacted on the way out.

### 8. License — Apache-2.0

memory-guard is licensed **Apache-2.0** (`LICENSE`, `NOTICE`, and a
`// SPDX-License-Identifier: Apache-2.0` header on every first-party `.go` file). Open-source and free
to use, modify, and distribute, including in commercial and proprietary products; contributions are
inbound=outbound under the DCO (no CLA, `git commit -s` sign-off required).

## Consequences

- The write-gate guarantee (poisoned content never persists) holds as long as `ValidateWrite` runs
  detection before storage and fails closed on a suspicion flag. Any future convenience path that
  stores-then-checks is a regression to flag, not ship.
- The `Detector` seam means adopting Presidio (or any detection backend) is an *additive* change
  behind the interface — no guard, no IPC, no contract change. The seam is what keeps the
  backend-choice cheap to defer to the tracer.
- The stdlib-only property ends when the Presidio-backed detector is added (sidecar SDK, ONNX runtime,
  or NER model); that is the moment `dep-scan` and `code-scanner` become blocking gates (recorded in
  CLAUDE.md → Recommended tooling).
- The v0 store being a plain in-memory map, `verify_delete` proving absence only in that map, the
  regex detector, the absent identity enforcement, and the missing audit-trail emission are accepted
  v0 scoping — each is recorded as a limitation in the spec and (for the security-relevant ones) a
  fitness row, so they are tracked rather than forgotten.

## Open questions

- **`Detector` backend** — Presidio-as-sidecar vs. Presidio-via-ONNX in-process vs. a Go-native NER
  model, **and** the hot-path latency budget the choice must fit. **Not decided here** — settled in
  the memory-guard tracer (the same way the first tracer settled the vault↔exec-sandbox handoff).
- **Post-deletion residue detection method** — exact-substring (credentials) vs. embedding-based
  semantic matching vs. Bloom-filter deleted-content signatures, for the v1 "gone from every
  index/copy" proof. TBD in the tracer.
- **Identity model** — `identity` is a free-form map today; tenant isolation / SPIFFE binding on
  `validate_read` / `validate_write` is a future ADR (coordinate with agent-mesh / vault).
- **MemoryStore backend** — the in-memory map is the stand-in; which real MemoryStore (LangChain /
  LlamaIndex / SQLite / vector store) ships first is a v1 task behind the `validate_*` seam.
</content>
