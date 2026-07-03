# memory-guard

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/tkdtaylor/memory-guard)](go.mod)
[![Last commit](https://img.shields.io/github/last-commit/tkdtaylor/memory-guard)](https://github.com/tkdtaylor/memory-guard/commits)

**A memory-I/O gate that screens agent context for poisoning and verifies deletions.** It sits in front
of any agent memory store and gates every read and write: poisoned writes are detected and rejected at
ingestion (fail-closed); PII is redacted before it lands in the store and again on read; and deletions
are verified — proven gone, not merely deleted. It addresses the OWASP Agentic threat **ASI06** (Memory
& Context Poisoning), the industry gap most memory stores skip. Standalone block in the
[Secure Agent Ecosystem](https://github.com/tkdtaylor/agent-builder#the-building-blocks), Apache-2.0 licensed.

> **Status.** The write-gate, PII redaction, and post-deletion verification are working and
> tracer-validated over the live IPC server. Pure-Go detectors (`RegexDetector` and `NativeDetector`)
> ship with the binary; a Presidio-backed detector (sidecar) is built and behind the pluggable seam
> but integration is deferred. See [docs/plans/roadmap.md](docs/plans/roadmap.md) for the full
> pipeline and current status.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [The gates](#the-gates)
- [Develop locally](#develop-locally)
- [Tech stack](#tech-stack)
- [Sponsorship](#sponsorship)
- [Enterprise support](#enterprise-support)
- [License](#license)

## Quick start

The fastest way to see it work takes one command — no database, no network, no setup:

```bash
git clone https://github.com/tkdtaylor/memory-guard && cd memory-guard

go run . write "my email is alice@example.com"
```

Output shows PII redacted to a placeholder before storage, and an opaque `stored_id` returned so the
agent never learns what was stored. To read back with redaction applied:

```bash
go run . read "email"
```

For the full write→read→verify-delete cycle, run as an IPC daemon (what agent-builder uses):

```bash
go run . serve --socket /run/memguard.sock &
# Then from another tool, send: {"op":"validate_write","entry":"contact alice@example.com"}
# And verify deletion with: {"op":"verify_delete","id":"mem-3785de541ddf"}
```

See [docs/CONTRACT.md](docs/CONTRACT.md) for the full IPC wire format and `verify_delete` semantics.

## How it works

An agent writes context to memory. memory-guard intercepts that write, detects poisoning and PII,
redacts what it finds, stores what's safe, and returns an opaque ID. On read, it redacts again. On
deletion, it verifies the entry is actually gone and scans surviving entries for leaked fragments.

```mermaid
flowchart LR
  W[Write<br/>context] --> DET{Detect<br/>poisoning?}
  DET -->|reject| ER["❌ Rejected<br/>poisoned write"]
  DET -->|redact| S["✓ Store<br/>with PII→labels"]
  S --> ID["Return opaque<br/>stored_id"]
  R[Read<br/>query] --> RED["Redact PII<br/>in response"]
  D[Delete<br/>stored_id] --> VER["Verify absent<br/>+ scan residue"]
  VER --> HASH["Return deletion<br/>hash + residue"]
```

The design sits on three principles:

- **Fail-closed on poisoning.** A write flagged as injection or known-poisoning is rejected outright,
  never stored.
- **PII never lands raw.** Redaction happens before storage and again on read. The agent never sees
  the raw PII; it receives placeholders like `<EMAIL>` or `<CREDIT_CARD>`.
- **Deletion is verified, not assumed.** A delete operation re-checks the store to confirm the entry
  is gone and scans other entries for leaked fragments (normalized substring match). You get back a
  deletion hash and a residue report.

Detection sits behind a pluggable `Detector` seam (`detector.go`). The binary ships with pure-Go
detectors; a Presidio-backed sidecar or ONNX-native model can be swapped in without touching the gate
or contract.

Deeper detail: [architecture overview](docs/architecture/overview.md),
[diagrams](docs/architecture/diagrams.md), and the [spec](docs/spec/SPEC.md).

## The gates

| Operation | What it does | Output |
|-----------|--------------|--------|
| **write-gate** | Detects context-poisoning (injection + known-poison rules) at ingestion; rejects if suspected | `allow: true/false`, `stored_id`, `flags` |
| **PII redaction** | Detects and redacts PII (email, SSN, API key, credit card, etc.) before storage and on read | Placeholders (`<EMAIL>`, `<SSN>`, etc.) replace raw PII |
| **delete verify** | Deletes entry, re-checks absence, scans remaining entries for residue fragments | `confirmed: true/false`, `residue_detected`, `deletion_hash` |
| **IPC daemon** | Unix-socket server accepting newline-delimited JSON ops: `validate_write`, `validate_read`, `verify_delete`, `ping` | JSON responses over socket |

## Develop locally

```bash
go test ./...                 # tests (including injection recall floor + PII corpus)
go build ./...                # compile
make check                    # the verification gate: lint + test + fitness
```

Contributing follows a test-spec-first, one-task-one-branch workflow. Read
[AGENTS.md](AGENTS.md) (the canonical, harness-neutral briefing) before starting; tasks and their
specs live under [docs/tasks/](docs/tasks/).

## Tech stack

Go 1.26 — memory-I/O gate and IPC daemon over a single static binary. Pure-Go detectors included; Presidio
integration available. See [docs/architecture/tech-stack.md](docs/architecture/tech-stack.md).

## Sponsorship

memory-guard is independent, open-source security tooling. If it saves you time or risk, [sponsoring its development](https://github.com/sponsors/tkdtaylor) is the most direct way to keep it maintained.

## Enterprise support

Commercial support, integration help, and SLAs are available. Apache-2.0 means you can build on memory-guard freely; paid support is a partner if you want one, never a requirement. Contact [tools@taylorguard.me](mailto:tools@taylorguard.me).

## License

[Apache License 2.0](LICENSE) — consistent with the other blocks in the Secure Agent Ecosystem.
See [NOTICE](NOTICE) for attribution and disclaimers, and [CONTRIBUTING.md](CONTRIBUTING.md) for
the inbound=outbound / DCO contribution terms.
