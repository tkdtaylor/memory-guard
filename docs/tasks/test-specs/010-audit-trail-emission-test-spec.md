# Test Spec 010: audit-trail OCSF emission

**Linked task:** [`docs/tasks/backlog/010-audit-trail-emission.md`](../backlog/010-audit-trail-emission.md)
**Written:** 2026-06-24

> Authored ahead of execution. The emitter seam + OCSF event shape + fail-open behavior are all
> **unit-verifiable locally** with a fake sink — no live `audit-trail` process is required. The
> load-bearing assertions are: (1) an event is emitted on every detection, (2) emission failure is
> fail-open (the `validate_*`/`verify_delete` verdict is byte-for-byte unchanged), and (3) **no raw
> PII ever appears in an emitted event** (the memory-guard invariant). All three are real assertions
> against captured events, not smoke.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004, TC-005 | ✅ | ✅ |
| REQ-005 | TC-006 | ✅ | ✅ |
| REQ-006 | TC-007 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Existing `validate_*` / `verify_delete` verdicts are unchanged with emission on **or** off
      (the gate's behavior must not depend on emission)

## Test fixtures

- **Fake sink (`fakeSink`)** — an in-memory `AuditSink` implementation that captures every emitted
  event into a slice for assertion. Records call count + the full event payload. Used by every TC.
- **Failing sink (`failingSink`)** — an `AuditSink` whose `Emit` always returns an error (and/or
  blocks past a deadline), standing in for an `audit-trail` that is down/unreachable. Used by TC-006.
- **PII corpus rows** — write inputs carrying known raw PII (`alice@example.com`, a credit-card
  number, an SSN) so the emitted-event payload can be scanned for verbatim leakage in TC-005.
- **Detection scenarios** — one input per emit trigger: PII-redacted write, injection-rejected write,
  a `verify_delete` that finds residue, and a plain deletion — so TC-001/TC-004 exercise every
  event class.

## Test cases

### TC-001: an event is emitted on each detection class
- **Requirement:** REQ-001
- **Input:** with a `fakeSink` wired in, run (a) a `validate_write` that redacts PII, (b) a
  `validate_write` that is rejected for `injection_suspected`, (c) a `verify_delete` that detects
  residue, (d) a plain `verify_delete` of an existing id.
- **Expected:** the `fakeSink` captures one event per detection-bearing operation: a PII-redaction
  event, an injection-rejection event, a residue-found event, and a deletion event. Each event names
  the operation and the flag(s)/class that triggered it.
- **Edge cases:** a `validate_write` with **no** flags (benign content) emits a write event with an
  empty flag set OR no event, per the documented policy — assert whichever the implementation chooses,
  but it must be deterministic and documented; a `validate_read` of a benign query does not fabricate
  a detection event.

### TC-002: emitted events are OCSF-shaped
- **Requirement:** REQ-002
- **Input:** capture the events from TC-001 via the `fakeSink`.
- **Expected:** each event conforms to the consumed audit-trail OCSF event shape — the required OCSF
  envelope fields are present and well-typed (e.g. a class/category identifier, an activity/disposition,
  a severity, a UTC timestamp, and a metadata/product block identifying `memory-guard`). The detection
  detail (operation, flag class, `stored_id`/deletion target, `deletion_hash` where applicable) lives
  in the structured fields the contract specifies — not in a free-text blob.
- **Edge cases:** an unknown/uncategorized flag still maps to a valid OCSF event (a default class),
  never an event missing required fields.

### TC-003: emission lives behind a swappable seam
- **Requirement:** REQ-003
- **Input:** construct the guard with the `fakeSink`, then with a no-op/disabled sink, then with the
  `failingSink` — swapping only the `AuditSink` implementation.
- **Expected:** the guard core, the contract responses, and the IPC layer are unchanged across all
  three; only the injected sink differs. No transport detail (socket/HTTP/file) leaks into `guard.go`
  or `ipc.go` — assert by construction (the seam is the only coupling point) and by the diff staying
  inside the emitter module + a single injection point.
- **Edge cases:** a nil sink is treated as "emission disabled" and never panics on the hot path.

### TC-004: deletion + residue events carry linkage metadata, not content
- **Requirement:** REQ-004
- **Input:** `verify_delete` of an entry that leaves residue, with a `fakeSink`.
- **Expected:** the emitted deletion/residue event carries the `deletion_hash` (the audit-linkage field
  from the existing contract) and a residue **class/summary descriptor** — enough for audit correlation
  — but **not** the deleted raw content.
- **Edge cases:** a deletion with no residue emits a deletion event with `residue_detected:false` and
  no residue payload.

### TC-005: NO raw PII appears in any emitted event
- **Requirement:** REQ-004
- **Input:** `validate_write` of each PII corpus row (`alice@example.com`, a credit-card number, an
  SSN) with a `fakeSink`; serialize every captured event to its wire form.
- **Expected:** the verbatim raw PII string appears in **none** of the serialized events — the event
  carries the redacted/flagged metadata (PII category counts, the redaction-placeholder form, the
  flags) only. Scan the full serialized payload for each raw value and assert absence. This is the
  hard, load-bearing assertion: emission must never become a PII side-channel.
- **Edge cases:** PII embedded inside an `injection_suspected` rejection (rejected writes still go
  through `RedactPII` upstream) is likewise absent from the emitted event.

### TC-006: emission failure is fail-open — the verdict is unchanged
- **Requirement:** REQ-005
- **Input:** run the full set of operations from TC-001 twice: once with the `fakeSink` and once with
  the `failingSink` (emit returns an error / times out). Capture each `validate_*` / `verify_delete`
  response map.
- **Expected:** the contract response maps are **identical** across the two runs — same `allow`, same
  `stored_id`, same `flags`, same `confirmed`/`residue_detected`/`deletion_hash`. A failing or absent
  audit sink **never** changes a verdict, never blocks, and never propagates an error to the caller;
  the failure is swallowed (optionally logged) on the hot path. In particular the **fail-closed
  write-gate stays fail-closed** regardless of sink state — an injection-rejected write is still
  `{allow:false, stored_id:null}` whether the sink succeeds or fails.
- **Edge cases:** a sink that blocks past a deadline does not stall the hot path (emission is bounded
  / non-blocking); a panicking sink is recovered and does not crash the guard.

### TC-007: emission is config-gated (enable / disable)
- **Requirement:** REQ-006
- **Input:** run the operation set with emission **enabled** and with emission **disabled** via config.
- **Expected:** enabled → the `fakeSink` captures events; disabled → zero events captured and zero
  transport attempts, with the `validate_*`/`verify_delete` verdicts identical to the enabled run.
  The default state is documented (default-off until the audit-trail contract is confirmed live).
- **Edge cases:** toggling config does not require a guard rebuild beyond re-construction; an invalid
  emission config fails closed to **disabled** (no emission) rather than crashing the gate.
