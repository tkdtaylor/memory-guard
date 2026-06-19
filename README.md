# memory-guard — context-poisoning & memory-I/O defense (ASI06)

Gates every memory read and write an agent performs. PII never lands in stored context
unredacted; poisoned writes are flagged and rejected at ingestion; and deletions are
**verified** — the industry gap most memory stores skip.

- **Write-gate (built delta)** — flag/reject context-poisoning at ingestion (fail-closed on suspected injection)
- **PII redaction** — recognizers redact emails/SSNs/cards/API-keys before storage
- **Post-deletion verification (built delta)** — `verify_delete` proves an entry is actually gone

> Prior-art verdict: **DERIVE** — ADOPT Microsoft Presidio (PII) and sit in front of any MemoryStore; BUILD the write-gate + post-deletion verification + adversarial suite.
>
> **Language: Go.** The block itself (contract, write-gate orchestration, delete-verification, IPC, hot-path gate) is Go — uniform with the rest of the ecosystem, single static binary, low per-call overhead on a path that gates *every* memory op. The one Python-leaning dependency (Presidio) is isolated **behind the `Detector` seam** ([detector.go](detector.go)): v0 ships a pure-Go `RegexDetector`; v1 swaps in a Presidio-backed detector (sidecar/subprocess or ONNX runtime) without touching the guard or contract. *Adopt the tool behind a seam; don't let it dictate the substrate.* **License: Apache-2.0.**

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

## License

memory-guard is licensed under the **Apache License 2.0** — free to use, modify, and distribute, including in commercial and proprietary products. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

> **Security notice:** memory-guard is a security tool provided **as-is, without warranty**. It does not guarantee the security of any system. See the disclaimer in [NOTICE](NOTICE).

## Enterprise Support

Need hardened deployments, integration help, or a support SLA? **Commercial support and consulting are available.**

📧 Contact **[tools@taylorguard.me](mailto:tools@taylorguard.me)**

## Sponsorship

memory-guard is independent, open-source security tooling. If it saves you time or risk, consider sponsoring continued development:

- 💜 [GitHub Sponsors](https://github.com/sponsors/tkdtaylor)
<!-- - 🤝 [Open Collective](https://opencollective.com/memory-guard)  (uncomment once the collective exists) -->

## Contributing

Contributions are welcome and become part of the project under Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). We use the **Developer Certificate of Origin (DCO)** — sign off your commits with `git commit -s`. No CLA required.
