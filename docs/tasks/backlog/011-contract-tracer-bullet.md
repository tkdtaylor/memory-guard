# Task 011: memory-guard's own tracer-bullet (contract validation)

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog

> **This is the task that earns the v1 label** (roadmap **T6**). memory-guard was **out of the first
> tracer-bullet's scope** (the slice was stateless, tracer-bullet.md §6) — its contract gets its **own**
> tracer once memory is in play. Until *this* slice passes at L5/L6, the repo's honest headline stays
> **"v0 substrate,"** the "**not yet tracer-validated**" caveat in `CONTRACT.md` / `SPEC.md` / `README.md`
> / `roadmap.md` is **correct**, and memory-guard stays **out of ecosystem verification**. This task is
> the gate that flips that.

## Goal

Run memory-guard's **own tracer-bullet**: a thin end-to-end **vertical slice** that drives
`validate_write → validate_read → verify_delete` **over the live IPC socket** (`serve --socket`),
against a **real `MemoryStore` (task 006)** and **ideally the real detection backend (task 007)**, with
a **real consumer process** driving it. The point is to **validate the contract shapes against reality**
and **promote them from "not yet tracer-validated"** — and to **capture any refinement the live path
forces** on `validate_*` / `verify_delete`. The contract may change as a result; **that is expected and
is the deliverable.** On success, the task removes the "not yet tracer-validated" caveat everywhere it
appears, in the same commit as the validating slice.

This is **not** another in-process unit test of `MemoryGuard`. The whole value is exercising the **live
serve path** end-to-end with a real store behind the seam — the dimension every prior task (001–005,
and 006) deliberately left for this one.

## Context

- **Why this is the gating task:** tasks 001–005 hardened the v0 **skeleton**; task 006 makes the
  **store** real (the `MemoryStore` seam + a real adapter); task 007 makes the **detector** real
  (Presidio-backed, behind the unchanged `Detector` seam). None of them **validated the contract
  against a live, stateful, real-backed path** — the contract shapes in `docs/CONTRACT.md` are still a
  **v0 skeleton against a v0 contract shape, not yet tracer-validated** (see the caveat in
  `CONTRACT.md`, `README.md`, `roadmap.md`). A tracer-bullet is the established ecosystem mechanism for
  proving a contract shape against reality; memory-guard was out of the first one's scope because that
  slice was stateless. Now that the store and detector are real, memory-guard gets its own.
- **Code exercised (not necessarily changed):** the live verbs in `guard.go`
  (`ValidateWrite` / `ValidateRead` / `VerifyDelete`) and the dispatch in `ipc.go`
  (`validate_write` / `validate_read` / `verify_delete` / `ping` over a `0600` Unix socket). The slice
  drives them **through `serve`**, decoding the newline-delimited JSON responses off the socket. The
  consumer is a **separate client** (a Go test client, the `main.go` CLI, or a sibling-style driver) —
  not an in-process function call.
- **What may change (the deliverable):** if the live path forces a **refinement** of any verb's
  response shape — a renamed/added/dropped field, a changed type, a new error case the contract didn't
  anticipate — that refinement is recorded in an **ADR** and propagated to `docs/CONTRACT.md` +
  `docs/spec/SPEC.md` (and `ipc.go` / `README.md` if a caller field moves) **in the same commit**. A
  tracer that finds the contract already exact records "validated unchanged" in the ADR — either way,
  the decision is captured.
- **Dependencies (explicit):** **depends on task 006** (real `MemoryStore` adapter) — the slice must
  run against the **real store seam**, not the bare in-memory map, or it cannot earn the v1 label.
  **Ideally depends on task 007** (real detection backend) — if 007 is not yet merged, the slice runs
  against the v0 detector and **records that the contract was validated against the v0 backend**,
  leaving a noted real-backend re-validation follow-up.
- Reference: [`docs/plans/roadmap.md`](../../plans/roadmap.md) (T6 + *Toward a true v1*),
  [`docs/CONTRACT.md`](../../CONTRACT.md) (the v0 shapes under test),
  [`README.md`](../../../README.md) (Status + the Contract note carrying the caveat),
  [`AGENTS.md`](../../../AGENTS.md) (invariants exercised live + the no-smoke-test rule),
  [`docs/tasks/backlog/006-memorystore-seam.md`](006-memorystore-seam.md) (the store dep),
  [`ipc.go`](../../../ipc.go) / [`guard.go`](../../../guard.go) (the live verbs).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | An **end-to-end vertical slice** drives `validate_write → validate_read → verify_delete` **over the live `serve --socket` IPC boundary**, with a **real consumer process** and the **real `MemoryStore` (task 006)** behind the guard (ideally the real detector, task 007). The slice is the contract tracer, not an in-process unit test. | must have |
| REQ-002 | **Each verb's real response shape is asserted against `docs/CONTRACT.md`**, field-by-field, on the JSON **decoded off the socket**: `validate_write → {allow, stored_id, flags}`, `validate_read → {allow, content_redacted, flags}`, `verify_delete → {confirmed, residue_detected, residue_summary?, deletion_hash}`. Presence + type of every contract field is verified — **not** a "doesn't panic" smoke test. | must have |
| REQ-003 | The **load-bearing invariants are exercised live, end-to-end**: a **poisoned write is rejected** (`allow:false`, `stored_id:null`) and **never persists** in the real store (a follow-up read surfaces nothing); **PII is never returned raw** over the socket (redacted in `content_redacted`); a **delete is proven absent** in the real store (a follow-up read for the deleted content returns nothing), not assumed from the `delete()` call. | must have |
| REQ-004 | **Any shape refinement the live path forces is recorded in an ADR and propagated to the spec in the same change** — `docs/CONTRACT.md` + `docs/spec/SPEC.md` (and `ipc.go` / `README.md` if a caller field moves). If no refinement is needed, the ADR records "shapes validated unchanged." An unrecorded shape drift is a BLOCK. | must have |
| REQ-005 | **On success (slice passes at L5/L6), the "not yet tracer-validated" caveat is removed** from `docs/CONTRACT.md`, `docs/spec/SPEC.md`, `README.md` (Status + Contract note), and `docs/plans/roadmap.md` (the v0-block note + the T6 row), reflecting the contract as **tracer-validated**. These are **in-commit spec updates** staged with the feat commit. The caveat is removed **only if** L5/L6 was actually reached. | must have |
| REQ-006 | **Readiness:** the slice runs against the **real store seam (006)**, never the bare map; running without 006 cannot earn the v1 label and the readiness gate blocks it. If task 007 is unavailable, the task completes against the real store + v0 detector and **states explicitly** (task file + ADR) that the *detector* dimension was validated against v0, not the real backend. | must have |

## Readiness gate

- [x] Test spec `011-contract-tracer-bullet-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] **Task 006 (real `MemoryStore` adapter) merged** — the slice runs against the real store seam, not the bare map
- [ ] Task 007 (real detection backend) merged **or** the task explicitly records validation against the v0 detector with a real-backend follow-up
- [ ] A real consumer / client harness for the live socket is identified (Go test client, the `main.go` CLI, or a sibling-style driver)
- [ ] The exact contract shapes to assert are pinned from `docs/CONTRACT.md` before the slice is written

## Acceptance criteria

- [ ] [REQ-001] The slice drives all three verbs over the **live socket** against the **real store**, with a real consumer (TC-001).
- [ ] [REQ-002] Each verb's response shape is asserted field-by-field against `CONTRACT.md` on the decoded socket response (TC-002, TC-003, TC-004).
- [ ] [REQ-003] Poisoned write rejected + never persists; PII never returned raw; delete proven absent — **all end-to-end** (TC-005, TC-006, TC-007).
- [ ] [REQ-004] Any refinement recorded in an ADR + propagated to `CONTRACT.md`/`SPEC.md` in the same change; "validated unchanged" recorded otherwise (TC-008).
- [ ] [REQ-005] On L5/L6 success, the "not yet tracer-validated" caveat is removed from `CONTRACT.md`, `SPEC.md`, `README.md`, `roadmap.md` (TC-009).
- [ ] [REQ-006] Slice runs against the real store seam (006); 007 absence recorded as a v0-detector validation + follow-up (TC-010).
- [ ] `go build ./... && go test ./...` green; the live `serve` slice observed (L5/L6 evidence recorded).

## Verification plan

- **Highest level achievable:** **L6** — this task is **specifically about reaching L5/L6**. The
  contract is not validated until the slice runs against the **live `serve` socket** with a real
  consumer and a real store. L1–L4 (code merged, unit tests, gate, CI) earn only 🟡 and do **not**
  authorize removing the "not yet tracer-validated" caveat — that removal is gated on the live-path
  evidence.
- **Level 5 — validation harness exercises the live path:** the harness starts `serve --socket`
  against a guard backed by the **real `MemoryStore` (006)**, and a consumer drives
  `validate_write → validate_read → verify_delete` over the socket, asserting each decoded response
  against `CONTRACT.md` and exercising the three live invariants (poison rejected + not persisted, PII
  not returned raw, delete proven absent). **No smoke tests** (AGENTS.md): every assertion checks the
  decoded response, not that the call merely returned.
- **Level 6 — operator/live serve observed:** a real `go run . serve --socket <sock>` daemon driven by
  an out-of-process client (the `main.go` CLI or a sibling driver), with the verbatim socket responses
  for all three verbs **quoted as evidence** in the ADR / `docs/spec/SPEC.md`. This is the evidence
  that flips the row to ✅ and authorizes removing the caveat (REQ-005).
- **Record:** the as-validated contract shapes (verbatim) + any refinement in the ADR and `SPEC.md`;
  the live socket transcript; and which detector dimension (real 007 vs. v0) the validation covered.
