# Roadmap — memory-guard

The agent **memory-I/O gate** for the secure-agent ecosystem (OWASP **ASI06** — Memory & Context
Poisoning). It sits in front of any agent memory store and gates every read and write: poisoned writes
are **rejected at ingestion** (the write-gate, fail-closed), PII is **redacted before storage** and
again on read, and deletions are **verified** — proven gone, not merely `delete()`d. The `Detector`
interface + the `validate_*` verbs are the adapter seams, so a Presidio-backed detection backend and a
real MemoryStore can be swapped without touching callers.

Authoritative design: the project's internal design notes
+ `interface-contracts.md §2`. As-built foundational stack:
[ADR-001](../architecture/decisions/001-foundational-stack.md).

## v0 — write-gate + PII redaction + delete-verification skeleton — ✅ shipped

Working today (`detector.go` / `guard.go` / `ipc.go` / `main.go`): the `validate_write` write-gate
(injection detection **before** storage, fail-closed on `injection_suspected`, redact PII, mint an
opaque `stored_id`, store the redacted content); `validate_read` (substring scan + PII redaction on
the way out); `verify_delete` (delete + re-check absence — post-deletion verification); a `0600`
Unix-socket JSON IPC server (`serve --socket`) dispatching the three verbs + `ping`; and in-process
`write` / `read` demos. The detection lives behind the `Detector` seam (v0 `RegexDetector`, a Presidio
stand-in). Pure Go, **stdlib only**. The `Detector` interface + the `validate_*` verbs are the adapter
seams — a real detection backend and a real MemoryStore slot in behind them without changing the
contract.

> **Not yet tracer-validated.** memory-guard was out of the first tracer-bullet's scope (stateless
> slice, tracer-bullet.md §6); the contract shapes get their own tracer once memory is in play.

## v1 — Detector backend + adversarial gate + real delete-proof + identity + audit

Each item a self-contained task. The contract (`validate_read`/`validate_write`/`verify_delete`) and
the `Detector` interface stay the swap points — hardening and richer backends slot in **without
changing the contract or any caller**. The load-bearing invariants (write-gate fail-closed, PII never
stored/returned raw, delete-verified, detector-seam isolation, fail-closed errors) hold across every
task; a change that violates one is a blocker, not a trade-off.

| # | Work | Status |
|---|------|--------|
| 1 | **Resolve the `Detector` backend (the memory-guard tracer)** — settle Presidio-as-sidecar vs. Presidio-via-ONNX in-process vs. Go-native NER, the hot-path latency budget, and the deployment shape, behind the existing `Detector` seam; record the decision as an ADR. | 🔜 task 001 |
| 2 | **Adversarial context-poisoning test-suite** — the MINJA-/GRAGPoison-/context-window-injection suite the write-gate is measured against; replaces the v0 "a few regex patterns" with a measured recall/precision bar. | 🔜 task 002 |
| 3 | **Post-deletion verification across every index/copy** — extend `verify_delete` from "absent in the in-memory map" to "no semantic residue in any other entry/index" (the documented industry gap); residue-detection method TBD in the tracer. | 🔜 task 003 |
| 4 | **PII recognizer coverage hardening** — broaden the recognizer set (names, phone, IBAN, more credential/API-key shapes) and reduce false-negatives behind the `Detector` seam; measured against a PII corpus. | 🔜 task 004 |
| 5 | **Publish / remote follow-up** — create a git remote and push (TODO.md); confirm public/private visibility; SPDX headers stay on new files. | 🔜 task 005 |

These five are the v1 increment **within this repo** — each self-contained behind the contract +
`Detector` seam. The working v0 source is **not rewritten** — v1 work extends it.

## Remaining work — blocked / decisions needed

### R1 — Identity-scoped read isolation — blocked: external identity
Today `validate_read` matches by substring across the whole store and `identity` is carried but not
enforced. Tenant isolation (a writer's entries readable only under a matching identity) needs the
workload-identity model (SPIFFE SVID issuance / A2A signed identity) from **agent-mesh / vault** before
a task can assert a real identity rather than a free-form map. Until then, the un-scoped substrate read
is the v0/v1 behavior.

### R2 — audit-trail emission — soft-dependency, plannable
Detections are returned as `flags` today; emitting them as **OCSF events to `audit-trail`** is a
plannable task once the audit-trail emit contract is consumed here (a soft runtime dep, not a
build-time blocker). Sequence after the `Detector` backend is settled.

## Notes for the orchestrator

This repo is built out one task at a time by **agent-builder** (and drivable via `/autopilot` /
`/backlog-autopilot`): it reads this roadmap + `docs/tasks/backlog/NNN-*.md`, builds the next ready
task, runs the verification gate (`go build ./... && go test ./...`, plus dep-scan/code-scanner on any
new module), and integrates it. The working v0 source (`detector.go`, `guard.go`, `ipc.go`, `main.go`)
is **not rewritten** — v1 work extends it behind the contract + `Detector` seam. Adding a dependency
(e.g. a Presidio SDK / ONNX runtime for task 001) is an "ask-first" event: it must clear dep-scan and be
recorded in the task's ADR, because memory-guard's whole point is a minimal, auditable gate on the
memory hot path.
</content>
