# memory-guard — context-poisoning & memory-I/O defense (ASI06)

Gates every memory read and write an agent performs. PII never lands in stored context
unredacted; poisoned writes are flagged and rejected at ingestion; and deletions are
**verified** — the industry gap most memory stores skip.

- **Write-gate (built delta)** — flag/reject context-poisoning at ingestion (fail-closed on suspected injection)
- **PII redaction** — recognizers redact emails/SSNs/cards/API-keys before storage
- **Post-deletion verification (built delta)** — `verify_delete` proves an entry is actually gone

> Prior-art verdict: **DERIVE** — ADOPT Microsoft Presidio (PII) and sit in front of any MemoryStore; BUILD the write-gate + post-deletion verification + adversarial suite.
>
> **Language: Go.** The block itself (contract, write-gate orchestration, delete-verification, IPC, hot-path gate) is Go — uniform with the rest of the ecosystem, single static binary, low per-call overhead on a path that gates *every* memory op. The one Python-leaning dependency (Presidio) is isolated **behind the `Detector` seam** ([detector.go](detector.go)): v0 ships a pure-Go `RegexDetector`; v1 swaps in a Presidio-backed detector (sidecar/subprocess or ONNX runtime) without touching the guard or contract. *Adopt the tool behind a seam; don't let it dictate the substrate.* **License: PolyForm Noncommercial 1.0.0.**

## Contract (interface-contracts.md §2)

```
validate_read(query, identity)  -> { allow, content_redacted, flags }
validate_write(entry, identity) -> { allow, stored_id, flags }
verify_delete(id)               -> { confirmed }
```

> Note: memory-guard was **out of the tracer-bullet scope** (the slice is stateless,
> tracer-bullet.md §6) — its contract gets its own tracer once memory is in play. This v0 is
> a skeleton against the v0 contract shape, not yet tracer-validated.

## Build & run

```sh
go build ./... && go test ./...
memory-guard write "contact alice@example.com"     # redacts PII, stores
memory-guard serve --socket /run/memguard.sock     # IPC daemon
```

IPC: `{"op":"validate_write","entry":"…"}` · `{"op":"validate_read","query":"…"}` ·
`{"op":"verify_delete","id":"…"}` · `{"op":"ping"}`.

## Status

🚧 **v0 skeleton.** Working write-gate (injection flag + fail-closed), regex `Detector`
(Presidio stand-in behind the seam), in-memory store (MemoryStore stand-in), post-deletion
verify. **Deferred (v1):** Presidio-backed `Detector` (sidecar/ONNX), real MemoryStore
backends, identity-scoped access, adversarial poisoning test-suite, audit-trail emission.
See [docs/CONTRACT.md](docs/CONTRACT.md) and the scoping doc.

## Adapter seam & standards

`Detector` interface (PII + injection detection) — pluggable: RegexDetector (v0), Presidio
(v1). Sits in front of any LangChain/LlamaIndex MemoryStore behind the validate_* verbs.
