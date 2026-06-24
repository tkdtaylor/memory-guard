# ADR-008: Contract Tracer-Bullet — Live-Path Validation of the v0 Contract Shapes

**Date:** 2026-06-24
**Status:** Accepted
**Task:** 011 (memory-guard's own tracer-bullet — roadmap T6, the task that earns the v1 label)

## Context

memory-guard's contract (`docs/CONTRACT.md`, mirroring `interface-contracts.md §2`) shipped as a
**v0 skeleton against a v0 contract shape, not yet tracer-validated**. memory-guard was out of the
ecosystem's *first* tracer-bullet scope because that slice was stateless (`tracer-bullet.md §6`); the
contract gets its own tracer once memory is in play. That precondition is now met:

- **Task 006 (merged):** the real `MemoryStore` seam — `InMemoryStore` (default) + the genuinely
  multi-index `TwoIndexStore`. The slice can run against the real store seam, not a bare map.
- **Task 008 (merged):** multi-index residue in `verify_delete`.
- **Task 009 (merged):** identity is now typed `{spiffe_id, trust_tier}`, bound at write and matched
  at read. The contract's `identity` argument is this typed wire map.
- **Task 010 (merged):** audit emission exists but is **default-off** and does not change any contract
  response shape.
- **Task 007 (Presidio, BLOCKED / not merged):** the real detection backend is unavailable.

A tracer-bullet is the established ecosystem mechanism for proving a contract shape against reality.
Until this slice ran at L5/L6, the "not yet tracer-validated" caveat in `CONTRACT.md` / `SPEC.md` /
`README.md` / `roadmap.md` was correct and the headline stayed v0. This task is the gate that flips it.

## Decision

Validate the contract by driving `validate_write → validate_read → verify_delete` **over the live
`serve` Unix-socket IPC boundary**, with a **real consumer** (a client that dials the socket) and the
**real `MemoryStore` seam** behind the guard — asserting each verb's response **field-by-field on the
JSON decoded off the socket**, and exercising the three load-bearing invariants end-to-end. This is the
contract tracer, not an in-process unit test.

Two levels of evidence were produced:

- **L5 — validation harness (`contract_tracer_test.go`):** starts `serve` against a guard backed by the
  multi-index `TwoIndexStore` (the real store seam, task 006/008) and the v0 `NativeDetector`; a client
  dials the socket and drives all three verbs, asserting each decoded response against `CONTRACT.md`
  (presence + type of every contract key, plus no unexpected keys) and the three live invariants.
- **L6 — out-of-process live serve:** a real `go run . serve --socket <sock>` daemon driven by a
  separate client process; the verbatim socket transcript is recorded below.

## As-validated contract shapes (verbatim, from the L6 socket transcript)

The shapes the live socket actually accepts and returns, captured out-of-process against a real
`serve` daemon (default `InMemoryStore` seam, v0 `NativeDetector`):

```
validate_write -> {"allow":true,"flags":["pii:EMAIL","pii:US_SSN"],"stored_id":"mem-299868a23f02"}
validate_read  -> {"allow":true,"content_redacted":"contact <EMAIL>, SSN <US_SSN>, meeting in room 4","flags":[]}
verify_delete  -> {"confirmed":true,"deletion_hash":"c6bb86ff9740cbd37b195dda7d8a0817398932c739baa3bc1b0a0ae9df57a430","residue_detected":false}
poison_write   -> {"allow":false,"flags":["injection_suspected"],"stored_id":null}
post_del_read  -> {"allow":true,"content_redacted":"","flags":[]}
```

(`<EMAIL>` / `<US_SSN>` appear as `<EMAIL>` etc. in the raw bytes — Go's default HTML-escaping
JSON encoder — and decode back to `<…>` on the consumer; the placeholder semantics are unchanged.)

Field-by-field against `CONTRACT.md`:

- `validate_write(entry, identity) -> {allow, stored_id, flags}` — `allow` bool, `stored_id` string (or
  `null` on rejection), `flags` JSON array. **Matches.**
- `validate_read(query, identity) -> {allow, content_redacted, flags}` — `allow` bool,
  `content_redacted` string, `flags` JSON array. **Matches.**
- `verify_delete(id) -> {confirmed, residue_detected, residue_summary?, deletion_hash}` — `confirmed`
  bool, `residue_detected` bool, `deletion_hash` non-empty string, `residue_summary` present **only**
  when `residue_detected:true`. **Matches.**

The `identity` argument is the typed `{spiffe_id, trust_tier}` wire map (task 009); the IPC's
`req["identity"]` decode and the guard's `principalFromMap` accept exactly this shape. **Matches.**

## Refinement

**Shapes validated unchanged.** The live path forced **no** refinement — no renamed, added, or dropped
field, no changed type, no unanticipated error case. Every verb's decoded socket response carries
exactly the contract keys, with the contract types, and `residue_summary` appears exactly under its
documented condition. `CONTRACT.md` and `docs/spec/SPEC.md` are accurate as written for the response
shapes; the only documentation change this task makes is **removing the "not yet tracer-validated"
caveat** now that the live-path evidence exists (REQ-005). No `ipc.go` / `README.md` caller-field move
was required because no field moved.

## Invariants exercised live (end-to-end, not assumed)

- **Write-gate fail-closed:** `poison_write` returned `{allow:false, stored_id:null,
  flags:["injection_suspected"]}`; a follow-up read surfaced **no** poisoned content — proving it never
  persisted in the real store, not merely that the call returned `allow:false`. The daemon kept serving
  after the rejection (fail-closed on the write, not the process).
- **PII never returned raw:** the write of `contact alice@example.com, SSN 123-45-6789` came back as
  `contact <EMAIL>, SSN <US_SSN>, …` over the socket — the raw email and SSN neither landed in the store
  nor returned over the wire.
- **Deletion proven absent:** `verify_delete` returned `confirmed:true` with `residue_detected:false`,
  and a follow-up read for the deleted content returned empty `content_redacted` — proven absent in the
  real backing store, not assumed from the `delete()` call.

## Detector dimension covered (REQ-006)

The validation covered the **v0 `NativeDetector`** backend (Go-native, in-process, ADR-002), because
**task 007 (Presidio-backed detector) is BLOCKED and not merged**. Per REQ-006 this is allowed and
expected: the contract is validated against the real store seam + the v0 detector. Because all
detector specifics live behind the unchanged `Detector` seam (the contract carries no detector type),
swapping in a Presidio-backed detector is a one-implementation change with no contract impact — so the
*shape* validation here is detector-agnostic. The open dimension is detection **recall/precision**, not
shape.

**Follow-up (noted, not blocking the v1 label):** re-run this tracer against the real Presidio-backed
detector once task 007 merges, to confirm the PII redaction recall delta over the v0 regex baseline
(TC-006 edge case). The contract *shapes* will not change — only which PII classes are masked.

## Store dimension covered

L5 exercises the multi-index `TwoIndexStore` (the real seam that makes "every index/copy" concrete);
L6 exercises the default `InMemoryStore` the production `serve` wiring constructs through the same
`MemoryStore` seam. **Both are real store-seam adapters** (task 006), not the bare in-memory map reached
around the seam — the readiness gate (REQ-006) is satisfied on both evidence levels.

## Consequences

- The contract is **tracer-validated** at L6. The "not yet tracer-validated" / "out of the
  tracer-bullet scope" caveat is removed from `docs/CONTRACT.md`, `docs/spec/SPEC.md`, `README.md`
  (Status + Contract note), and `docs/plans/roadmap.md` (the v0-block note + the T6 row), in the same
  commit as the validating slice.
- `contract_tracer_test.go` is now a standing regression guard: any future shape drift on the live
  socket fails the `mustKeys` exact-key assertions, so the validated contract cannot silently change.
- The headline can move off "v0 substrate" with respect to the contract dimension. The remaining open
  v1 dimension is the real detection backend (task 007), tracked as the follow-up above.
