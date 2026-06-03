# memory-guard — project instructions

Gates all agent memory I/O (ASI06). **Go.** PolyForm Noncommercial 1.0.0.

## Language rationale (why Go, not Python)

The block is Go for ecosystem uniformity (single static binary; it gates *every* memory op,
so per-call overhead matters) and because its value-add — the write-gate + delete-verification
— is plain orchestration, not NLP. The one Python-leaning dependency, **Presidio**, is
isolated behind the `Detector` interface ([detector.go](detector.go)). Swapping the v0
`RegexDetector` for a Presidio-backed detector (sidecar/subprocess or ONNX) must be a
one-implementation change with **no contract, guard, or IPC impact**. Don't leak Presidio (or
any detector) specifics past the `Detector` seam.

## The built delta (don't let it regress into a thin detector wrapper)

- **Write-gate:** flag/reject context-poisoning at ingestion (fail-closed on suspected
  injection). This is the value-add, not the PII redaction.
- **Post-deletion verification:** `VerifyDelete` must PROVE the entry is gone (and, in v1,
  gone from every index/copy), not just `delete()`.

## Contract

`validate_read` / `validate_write` / `verify_delete`. Authoritative spec:
`memory-guard.md` + `interface-contracts.md §2`. NOT yet
tracer-validated (out of the first tracer's scope) — gets its own tracer when memory is in play.

## Open decision — settle it in the memory-guard tracer

The **`Detector` backend** (v0 `RegexDetector` → Presidio-as-sidecar vs. Presidio-via-ONNX
in-process vs. a Go-native NER model) is deliberately *unresolved* at v0. Resolve it in the
memory-guard tracer-bullet — the same way the first tracer settled the vault↔exec-sandbox
credential handoff (see `tracer-bullet.md` and the tracer's
`decisions.md`). What that tracer must decide: detector deployment shape (sidecar vs.
in-process), the latency budget on the read/write hot path, and the adversarial-poisoning
test-suite the write-gate is measured against. Until then, keep everything Presidio-specific
behind the `Detector` seam so this choice stays cheap to make.

## Conventions

`go build ./...` / `go test ./...` stay green. Error shape `{error:{code,message,retryable}}`.
