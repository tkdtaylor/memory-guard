# memory-guard vs OWASP Agent Memory Guard

Both projects address the same problem: OWASP agentic threat **ASI06** (memory and context poisoning), the risk that an attacker writes malicious content into an agent's persistent memory so it survives context resets and reshapes later behavior. They were built independently and land on the same seam, a gate in front of the memory store, so keeping the relationship straight is useful.

This is a reference for how the two relate. It is not a claim that either replaces the other.

## What they share

- The same threat model: screen every memory write before it persists, and treat tool output as the primary injection vector.
- A detector pipeline plus a policy decision (allow, redact, reject).
- Local operation with no external API call on the hot path.
- PII and secret redaction before storage.

## Where they differ

| | OWASP Agent Memory Guard | memory-guard (this repo) |
|---|---|---|
| Form | Python package (`agent-memory-guard`) | Go single static binary, IPC daemon over a `0600` Unix socket |
| Integration | Framework adapters (LangChain, OpenAI Agents SDK, AutoGen, mem0, CrewAI) plus an MCP server | The `validate_write` / `validate_read` / `verify_delete` wire contract (`docs/CONTRACT.md`) |
| Detection | Regex plus ML detection (v0.3.0) | Pure-Go regex and native detectors behind the `Detector` seam; Presidio deferred behind the same seam |
| Deletion | `retire_if` marks entries retired; a snapshot store allows rollback that restores them | `verify_delete` proves the entry is gone, then scans surviving entries for residue |
| Read path | Not a documented gate | Redaction reapplied on read; an opaque `stored_id` so the agent never learns raw stored content |
| Policy | A YAML policy engine bundled inside the guard | Detection returns flags; the action decision is the ecosystem's separate `policy-engine` block |
| Status | OWASP Incubator, v0.3.0 (June 2026) | v1, tracer-validated write-gate and delete-verify |

## What memory-guard does that theirs does not

- **Delete-verification with a residue scan.** `verify_delete` proves absence and then scans every surviving index for a verbatim or near-verbatim fragment of the deleted content. Their model marks an entry retired and keeps a snapshot that rollback can restore, which is the opposite guarantee.
- **Read-side redaction and opaque IDs.** PII is redacted again on the way out, and the caller receives an opaque `stored_id`, so a poisoned or curious agent never reads back raw stored content.
- **Detection kept separate from policy.** In this ecosystem the action decision lives in `policy-engine`, not inside the memory gate. That keeps the gate a thin, auditable hot-path component and avoids running two policy engines.

## What theirs does that we do not, and our stance

- **Self-reinforcement and size-anomaly detectors, source-class tagging, protected and immutable keys.** These are good ideas. They are planned as adopt tasks behind our `Detector` and behavioral-inspection seams rather than by importing their code.
- **A snapshot store and point-in-time rollback.** A real capability we lack. It partly conflicts with our prove-gone stance, so it is parked as a consideration in the roadmap, not planned.
- **The MCP server and framework adapters.** Useful for their Python audience. Our consumers speak the IPC contract, so this is not a fit.

## Why we do not adopt theirs wholesale

The ecosystem is Go single-binaries composed over socket contracts, with a tight egress allowlist and supply-chain scanning on every dependency. Adopting a Python package puts an interpreter and its dependency tree on the trusted memory-I/O hot path. Their 59 microsecond figure is in-process Python; reaching it from our Go orchestrator would mean an MCP or sidecar round trip, which does not fit our sub-millisecond per-call budget. Their delete model is also weaker for our requirement, since it retires and can restore rather than proving gone. We take the ideas and the threat taxonomy, not the code.

## Naming

Both projects use a generic, descriptive name in the same threat space. That is deliberate here (the name says what the block does), and the two are distinguishable by stack and repository. No rename is planned.
