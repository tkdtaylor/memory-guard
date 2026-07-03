# memory-guard — context-poisoning & memory-I/O defense (ASI06)

Gates every memory read and write an agent performs. PII never lands in stored context unredacted; poisoned writes are flagged and rejected at ingestion; and deletions are **verified** — the industry gap most memory stores skip.

- **Write-gate (built delta)** — flag/reject context-poisoning at ingestion (fail-closed on suspected injection)
- **PII redaction** — recognizers redact emails/SSNs/cards/API-keys before storage
- **Post-deletion verification (built delta)** — `verify_delete` proves an entry is actually gone

> Prior-art verdict: **DERIVE** — ADOPT Microsoft Presidio (PII) and sit in front of any MemoryStore; BUILD the write-gate + post-deletion verification + adversarial suite.
>
> **Language: Go.** The block itself (contract, write-gate orchestration, delete-verification, IPC, hot-path gate) is Go — uniform with the rest of the ecosystem, single static binary, low per-call overhead on a path that gates *every* memory op. The one Python-leaning dependency (Presidio) is isolated **behind the `Detector` seam** ([detector.go](detector.go)): v0 ships pure-Go detectors (`RegexDetector` and the Go-native `NativeDetector`, the resolved backend per [ADR-002](docs/architecture/decisions/002-detector-backend.md)); a Presidio-backed detector (sidecar/subprocess or ONNX runtime) is deferred-not-foreclosed and slots in behind the same seam without touching the guard or contract. *Adopt the tool behind a seam; don't let it dictate the substrate.* **License: Apache-2.0.**

## Scope

**What memory-guard does:** defense for what gets written into agent memory/context — PII detection plus poisoning/injection screening at the memory-write boundary (ASI06).

**What it does *not* do (and which sibling owns it instead):**
- Guard the inbound prompt / tool-call boundary → **[armor](https://github.com/tkdtaylor/armor)** (armor guards what comes in; memory-guard guards what gets stored)
- Store or broker secrets → **[vault](https://github.com/tkdtaylor/vault)**
- Authorize actions → **[policy-engine](https://github.com/tkdtaylor/policy-engine)**

`memory-guard` is one block in a composable secure-agent ecosystem — each block is standalone and independently usable, and composes with its siblings over published contracts rather than absorbing their responsibilities (no central "god object").

## Contract ([docs/CONTRACT.md](docs/CONTRACT.md))

```
validate_read(query, identity)  -> { allow, content_redacted, flags }
validate_write(entry, identity) -> { allow, stored_id, flags }
verify_delete(id)               -> { confirmed, residue_detected, residue_summary?, deletion_hash }
```

> Note: these contract shapes are **tracer-validated** — memory-guard's own tracer-bullet
> (roadmap T6, [ADR-008](docs/architecture/decisions/008-contract-tracer-validation.md)) drives
> `validate_write → validate_read → verify_delete` over the live `serve` socket against the real
> `MemoryStore` seam, asserting each verb's response field-by-field on the JSON decoded off the
> socket. The shapes validated **unchanged**. (The detector dimension was validated against the v0
> `NativeDetector`; a real-Presidio-backend re-validation is a noted follow-up — shapes are
> detector-agnostic behind the `Detector` seam.)

## Build & run

```sh
go build ./... && go test ./...
go run . write "contact alice@example.com"          # redacts PII, stores
go run . serve --socket /run/memguard.sock          # IPC daemon
```

IPC: `{"op":"validate_write","entry":"…"}` · `{"op":"validate_read","query":"…"}` ·
`{"op":"verify_delete","id":"…"}` · `{"op":"ping"}`.

## Documentation

- [docs/architecture/overview.md](docs/architecture/overview.md) — system design and design principles
- [docs/architecture/diagrams.md](docs/architecture/diagrams.md) — C4 diagrams and runtime flows
- [docs/spec/SPEC.md](docs/spec/SPEC.md) — authoritative spec
- [docs/plans/roadmap.md](docs/plans/roadmap.md) — roadmap and current status
- [docs/CONTRACT.md](docs/CONTRACT.md) — contract reference

## Status

🟢 **Contract tracer-validated; detector backends real.** Working write-gate (injection flag + fail-closed) with an adversarial poisoning test-suite (enforced floor: recall 0.8125 / precision 0.867, task 014 Phase A; PII corpus recall/precision 1.00), pure-Go `Detector`s behind the seam (`RegexDetector` + Go-native `NativeDetector`, the default) plus an opt-in **Presidio-backed NER sidecar** (task 007, ADR-009), a real `MemoryStore` seam (`InMemoryStore` default + multi-index `TwoIndexStore`), identity bound-and-matched, and post-deletion verification with multi-index residue detection + deletion-hash. The `validate_*`/`verify_delete` contract is tracer-validated over the live `serve` socket (T6 / ADR-008).

The five historically "v1"-labelled tasks (001–005) hardened the v0 substrate; tasks 006–011 then made the load-bearing stand-ins real: a real `MemoryStore` seam (006/008), identity bound-and-matched (009), audit emission (010, default-off), and — the gating item — a **tracer-validated contract** (011, [ADR-008](docs/architecture/decisions/008-contract-tracer-validation.md)): the `validate_*`/`verify_delete` shapes are now proven against the live `serve` socket with a real store and a real consumer, validated **unchanged**. The **real detection backend** then landed as well: an opt-in Presidio-backed sidecar behind the unchanged `Detector` seam (task 007, ADR-009), with the injection-recall lift phased in on top (tasks 013–014 — Phase A enforced by F-006 at recall 0.8125 / precision 0.867; the remaining framing classes are deferred to Phase B, ADR-011). The contract tracer's caveat stands: it validated the detector dimension against the v0 backend, and the real-backend re-validation remains a noted follow-up. See [Toward a true v1](docs/plans/roadmap.md#toward-a-true-v1-substrate-not-just-tasks) in the roadmap.

## Adapter seam & standards

`Detector` interface (PII + injection detection) — pluggable: `RegexDetector` and Go-native
`NativeDetector` (default), and an opt-in Presidio-backed sidecar (task 007). Sits in front of any
LangChain/LlamaIndex MemoryStore behind the validate_* verbs.

## License

memory-guard is licensed under the **Apache License 2.0** — free to use, modify, and distribute, including in commercial and proprietary products. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

> **Security notice:** memory-guard is a security tool provided **as-is, without warranty**. It does not guarantee the security of any system. See the disclaimer in [NOTICE](NOTICE).

## Enterprise Support

Need hardened deployments, integration help, or a support SLA? **Commercial support and consulting are available.**

📧 Contact **[tools@taylorguard.me](mailto:tools@taylorguard.me)**

## Sponsorship

memory-guard is independent, open-source security tooling. If it saves you time or risk, consider sponsoring continued development:

- 💜 [GitHub Sponsors](https://github.com/sponsors/tkdtaylor)

## Contributing

Contributions are welcome and become part of the project under Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). We use the **Developer Certificate of Origin (DCO)** — sign off your commits with `git commit -s`. No CLA required.
