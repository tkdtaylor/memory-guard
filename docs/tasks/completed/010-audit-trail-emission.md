# Task 010: audit-trail OCSF emission

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog

> Roadmap **T5 / R2**. Today memory-guard returns detections to the caller as `flags`. This task
> **also emits them as OCSF events to the sibling `audit-trail` project** — a **soft runtime
> dependency, not a build-time blocker**. audit-trail being down must never break the memory hot path
> or the fail-closed write-gate: emission is best-effort and **fail-open**, and an emission failure
> **never changes a `validate_*` / `verify_delete` verdict**.

## Goal

Add an audit-emission seam to memory-guard so every detection it already computes — PII redaction on
write, injection rejection at the write-gate, residue found on delete, and the deletion itself — is
**also** emitted as an **OCSF-shaped event** to `audit-trail`, in addition to being returned to the
caller as `flags`. Emission is best-effort: a slow, failing, or absent audit sink must not block the
hot path, must not surface an error to the caller, and must leave the verdict byte-for-byte unchanged.
Crucially, the emitted event carries **redacted/flagged metadata only — never the raw PII** (a
memory-guard invariant: PII never lands anywhere unredacted, and the audit channel is not an
exception). Emission lives behind a small `AuditSink` seam so the transport (socket / HTTP / file) is
swappable and testable with a fake sink.

## Context

- Source: roadmap **T5** (`docs/plans/roadmap.md`, "Toward a true v1") and **R2** ("audit-trail
  emission — soft-dependency, plannable"): *"Detections are returned as `flags` today; emitting them as
  OCSF events to `audit-trail` is a plannable task once the audit-trail emit contract is consumed
  here (a soft runtime dep, not a build-time blocker). Sequence after the `Detector` backend is
  settled."*
- Code under change: `guard.go` (`ValidateWrite` / `ValidateRead` / `VerifyDelete` are where the
  detections are computed — the emit points) plus a **new emitter module** (`audit.go`) holding the
  `AuditSink` seam, the OCSF event mapping, and the fail-open dispatch. `ipc.go` and `main.go` change
  only to wire/configure the sink — the contract response shapes are untouched.
- The detections already exist as `flags` (`guard.go::ValidateWrite` appends `injection_suspected` +
  PII flags; `VerifyDelete` computes `residue_detected` + `deletion_hash`). This task **reuses** those
  — it does not recompute detection. The `deletion_hash` is already specified as the audit-linkage
  field (`docs/CONTRACT.md`, `verify_delete`); this task is its first consumer.
- **Soft runtime dependency, fail-open:** unlike a Presidio backend, audit-trail is **not** a build-
  time dependency and **not** on the critical path. Emission failure is swallowed (optionally logged)
  and the operation proceeds. This is the opposite of the write-gate's fail-*closed* posture, and the
  distinction is deliberate: the write-gate fails closed for *security*; audit emission fails open for
  *availability*. Neither may compromise the other — a down audit sink must never let a poisoned write
  through, and the gate's rejection must never depend on the sink.
- **PII never leaks into the audit event.** The event payload is built from redacted content + flag
  metadata (categories, counts, the redaction placeholders, `deletion_hash`), never the raw input.
  This is a hard invariant, asserted directly in TC-005.
- Reference: [`docs/CONTRACT.md`](../../CONTRACT.md) (the `flags` / `deletion_hash` fields this
  consumes), [`docs/plans/roadmap.md`](../../plans/roadmap.md) (T5/R2), the sibling `audit-trail`
  project's **emit contract** (the OCSF event shape — a prerequisite to confirm/consume; see the
  readiness gate).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | memory-guard **emits an audit event on each detection** it already computes: PII redaction on `validate_write`, injection rejection at the write-gate, residue found on `verify_delete`, and the deletion itself. Detections continue to be returned to the caller as `flags` (this is additive). | must have |
| REQ-002 | Emitted events are **OCSF-shaped**, conforming to audit-trail's consumed emit contract (required OCSF envelope fields present and well-typed; detection detail in the structured fields, not a free-text blob). | must have |
| REQ-003 | Emission lives behind a small **`AuditSink` seam** (new `audit.go`) so the transport (socket / HTTP / file) is swappable and testable with a fake sink. No transport specifics leak into `guard.go` or `ipc.go`. | must have |
| REQ-004 | **No raw PII (or raw deleted content) appears in any emitted event** — the event carries redacted/flagged metadata + `deletion_hash` only. The memory-guard "PII never lands unredacted" invariant holds on the audit channel too. | must have |
| REQ-005 | Emission is **best-effort and fail-open**: a failing, slow, or absent audit sink never blocks the hot path, never surfaces an error to the caller, and **never changes a `validate_*` / `verify_delete` verdict**. The fail-closed write-gate stays fail-closed regardless of sink state. | must have |
| REQ-006 | Emission is **config-gated** (enable / disable), defaulting to disabled until the audit-trail contract is confirmed live; an invalid emission config fails closed to *disabled* (no emission), never crashing the gate. | should have |

## Readiness gate

- [x] Test spec `010-audit-trail-emission-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **audit-trail emit contract (OCSF event shape) confirmed and consumed** here — the prerequisite;
      the event mapping (REQ-002) is pinned to that contract, not invented
- [ ] **Sequenced after task 007 (the `Detector` backend) is settled** per roadmap R2 — the detection
      flags this consumes should be stable before they are emitted

## Acceptance criteria

- [ ] [REQ-001] An event is emitted on each detection class — PII redaction, injection rejection,
      residue found, deletion — and `flags` are still returned to the caller (TC-001).
- [ ] [REQ-002] Emitted events conform to the consumed OCSF shape (TC-002).
- [ ] [REQ-003] Emission is behind a swappable `AuditSink` seam; no transport leak into guard/IPC
      (TC-003); deletion/residue events carry `deletion_hash` linkage (TC-004).
- [ ] [REQ-004] No raw PII appears in any serialized emitted event (TC-005).
- [ ] [REQ-005] Emission failure is fail-open — verdicts identical with a working vs. failing sink;
      write-gate stays fail-closed (TC-006).
- [ ] [REQ-006] Emission is config-gated, default-off, invalid-config → disabled (TC-007).
- [ ] `go build ./... && go test ./...` green; the existing write-gate / read / delete tests pass
      unchanged.

## Verification plan

- **Highest level achievable:** **L5** — the validation harness (`go test`) wires a **fake
  `AuditSink`** into the guard and asserts, on captured events, that (1) the right OCSF-shaped event is
  emitted per detection class, (2) emission failure is fail-open (the verdict maps are byte-for-byte
  identical with a working vs. failing sink, and the write-gate stays fail-closed), and (3) no raw PII
  appears in any serialized event. L6 (a live emission against a real `audit-trail` socket) is
  **deferred** — it depends on the audit-trail emit endpoint being up, which is the soft runtime dep
  this task is explicitly allowed to stub with a fake sink.
- **Level 2/5 — unit/harness:** `go test ./...` → `ok`, including the fake-sink emission suite (TC-001
  through TC-007) and the unchanged existing guard/IPC tests.
- **Level 6 (deferred / optional):** once the audit-trail emit endpoint is live, `go run . serve` with
  emission enabled → drive a PII write + an injection-rejected write + a residue-bearing delete →
  observe the OCSF events arrive at audit-trail and confirm no raw PII in the received payloads. Record
  the observed event shapes in the spec. Gated on the audit-trail contract prereq + task-007 sequencing
  in the readiness gate.
