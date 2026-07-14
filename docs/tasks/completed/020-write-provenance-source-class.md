# Task 020: Write-provenance / source-class tagging

**Project:** memory-guard
**Created:** 2026-07-14
**Status:** 🟡 Code merged (ADR-015; awaiting spec-verifier + L5/L6 for ✅)

## Goal

Carry a write's **provenance** through the write path as a `source_class` tag, one of
`external_tool | user_input | agent_authored | system`, so downstream consumers can key off
*where a write came from*, not just its content. Today `entry` (`guard.go`) records `content`,
`boundIdentity`, and `flags`; it has no notion of origin. The primary ASI06 injection vector is
**external-tool output** landing in memory as if it were trusted first-party content, tagging
provenance is what lets a future behavioral detector treat `agent_authored` writes differently
from `external_tool` writes, and lets an audit event record where a write actually came from
instead of only what the guard found in it.

This task **tags and threads** provenance; it does **not** implement any policy that acts on the
tag (no self-reinforcement detection, no trust-weighted rejection). That consumption is the
planned behavioral-detector work referenced in the roadmap as tasks 018/019 (not yet created in
this repo at time of writing, this task is a **soft prerequisite/enabler** for that work, not a
dependency on it).

## Context

- **Source:** ASI06 write-gate hardening; the identity/scope precedent set by completed task 016
  / ADR-013, which added an optional `scope` key to the same `identity` map **without** changing
  the tracer-validated `validate_write(entry, identity)` shape (`docs/CONTRACT.md`,
  `docs/architecture/decisions/013-scoped-seam-lookup-shared-scope.md`). This task follows the
  identical pattern for a new optional key, `source_class`.
- **Code under change:** `principal.go` (the identity-decode seam; currently
  `principalFromMap` reads `spiffe_id` / `trust_tier` / `scope` out of `identity
  map[string]any`), `guard.go` (`entry` struct, `ValidateWrite`), `audit.go` (`OCSFFinding`,
  the write-triggered event builders `BuildPIIRedactionEvent` / `BuildInjectionRejectedEvent`).
- **Why the identity map, not a new contract field:** `ipc.go` (line ~40) already decodes
  `identity` generically as `req["identity"].(map[string]any)` and passes it straight through to
  `guard.ValidateWrite(text, identity)`, no field-by-field allowlist. `contract_tracer_test.go`
  asserts the **response** shape field-by-field over the live socket; it does not reject unknown
  request keys. Task 016 already proved this precedent live: adding `scope` to the same map
  shipped with the tracer suite passing unmodified. Riding `source_class` on the same envelope
  costs nothing on the wire and keeps `validate_write(entry, identity) -> {allow, stored_id,
  flags}` byte-identical.
- **Rejected alternative (record in the ADR, do not implement):** a new top-level
  `validate_write(entry, identity, source_class)` contract argument. Rejected because (a) it is a
  **breaking** shape change requiring tracer re-validation and touching `ipc.go`'s request
  parsing, ADR-008's tracer-validated contract, and every existing caller construction site; (b)
  `identity` is already the seam this exact kind of caller-supplied, guard-trusted metadata rides
  on (ADR-004's `trust_tier`, ADR-013's `scope`); introducing a second parallel channel for the
  same class of metadata is inconsistent with that precedent for no benefit.
- **Not an access-control concern:** unlike `spiffe_id` / `trust_tier` / `scope`, `source_class`
  never gates `ValidateRead` visibility and is never matched against a reader's visible-key set ,
  it is provenance metadata, not an identity. Keep it out of `Principal`'s three existing
  accessors (`Subject`/`Attested`/`SharedScope`), which are specifically the *access-control*
  seam; decode `source_class` through a **separate, standalone** function
  (`sourceClassFromMap(identity map[string]any) string`) beside `principalFromMap`, not as a
  fourth `Principal` method. This keeps the identity seam single-purpose (who) and the
  provenance seam single-purpose (where-from), mirroring why `Detector` and `MemoryStore` are
  kept as separate seams rather than one god-interface.
- **Default for absent/unrecognized provenance:** a missing `source_class` key, an empty string,
  or any value outside the four-item enum normalizes to the sentinel `sourceClassUnknown =
  "unknown"`, **not** silently treated as `agent_authored` or dropped. `unknown` is the
  documented conservative default: any future trust-weighting policy (task 018/019) MUST treat
  `unknown` at least as cautiously as `external_tool` (untrusted-until-shown-otherwise), per the
  same fail-closed posture the write-gate already uses for suspected injection. This task states
  and documents that policy; it does not implement the weighting.
- **Consumers this task wires (both additive, no behavior change to existing verdicts):**
  1. **The write path / future behavioral seam (018):** `entry` gains a `sourceClass` field, set
     in `ValidateWrite` from `sourceClassFromMap(identity)`, stored alongside `boundIdentity`.
     This is the field a self-reinforcement detector keys on (`sourceClass ==
     "agent_authored"`); this task documents that as the intended read site in code comments and
     `docs/spec/data-model.md` without building the detector.
  2. **Audit events (tasks 010/017):** `OCSFFinding` gains a `SourceClass` field, populated at
     the `ValidateWrite` emission call sites (`BuildPIIRedactionEvent` /
     `BuildInjectionRejectedEvent`) from the same normalized value, never re-derived from the
     stored entry, so the emitted event and the stored entry are provably the same read of
     `identity`. `VerifyDelete`'s event is unaffected (deletion has no writer-provenance
     concept); no change to `BuildDeletionEvent`'s signature.
- **Invariants preserved:** contract shape unchanged (additive optional key only); the `Detector`
  seam is untouched (provenance is guard-side orchestration, not a detection concern); the
  write-gate's fail-closed posture on `injection_suspected` is unchanged, a rejected write still
  emits `BuildInjectionRejectedEvent` (source-class threading through it is additive detail, not
  a policy change); `go.mod` stays require-free; the IPC error shape is untouched.
- Reference: `docs/CONTRACT.md`; `docs/spec/interfaces.md` (identity wire shape); `docs/spec/data-model.md`
  (the `entry` struct); `docs/spec/behaviors.md` (B-001 write behavior, the audit emission
  behaviors); `principal.go` (`principalFromMap`, the `sharedScopeValue`/`sharedScopeKey`
  pattern this task's `sourceClassUnknown` sentinel mirrors); `audit.go` (`OCSFFinding`,
  `BuildPIIRedactionEvent`, `BuildInjectionRejectedEvent`).

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | The `identity` map gains one **optional** key, `source_class`, with enumerated wire values `external_tool` \| `user_input` \| `agent_authored` \| `system`. The `validate_write(entry, identity) -> {allow, stored_id, flags}` tracer-validated shape is **unchanged**, no new top-level argument, no new response field. `validate_read` and `verify_delete` are untouched by this key (it is meaningful on `validate_write` only). | must have |
| REQ-002 | A standalone decode function `sourceClassFromMap(identity map[string]any) string` (beside, not inside, `principalFromMap`) normalizes the raw `source_class` value: one of the four enum literals passes through unchanged; a missing key, empty string, or any other value maps to the sentinel `sourceClassUnknown = "unknown"`. `Principal`'s three existing accessors are unmodified, `source_class` is not exposed through `Subject`/`Attested`/`SharedScope`. | must have |
| REQ-003 | `entry` (`guard.go`) gains a `sourceClass string` field. `ValidateWrite` sets it via `sourceClassFromMap(identity)` at the same read of `identity` that already produces `boundKeyFor(principalFromMap(identity))`, for both accepted and injection-rejected writes (rejected writes do not persist, but the value is available to the injection-rejected audit event per REQ-004). | must have |
| REQ-004 | `OCSFFinding` (`audit.go`) gains a `SourceClass string` field (`json:"source_class"`). `BuildPIIRedactionEvent` and `BuildInjectionRejectedEvent` gain a `sourceClass string` parameter, threaded from the same `ValidateWrite` call-site value (REQ-003), never re-derived from the stored entry. `BuildDeletionEvent`'s signature is unchanged (deletion has no writer-provenance concept). | must have |
| REQ-005 | A write tagged `external_tool` and a write tagged `agent_authored` are distinguishable, value-for-value, both (a) in the `entry.sourceClass` the guard would consult on a later read of the store, and (b) in the `SourceClass` field of the emitted `OCSFEvent.Finding`, for both the PII-redaction and injection-rejected flows. | must have |
| REQ-006 | A write with no `source_class` key (or an unrecognized value, e.g. `"tool_output"` misspelled) results in `entry.sourceClass == sourceClassUnknown` and an emitted event's `Finding.SourceClass == sourceClassUnknown`, never silently defaulting to `agent_authored` or `""`. | must have |
| REQ-007 | ADR (next free number, expected ADR-015) records: the envelope-vs-top-level-field decision (ride on `identity`, optional key, additive) and the rejected top-level-argument alternative, with the explicit contract-impact analysis (tracer shape unaffected, precedent from ADR-013's `scope`); the standalone-decode-function-vs-`Principal`-accessor decision and rationale; the `unknown` default and the fail-closed policy statement for future consumers (018/019); the relationship to the not-yet-created behavioral-detector tasks as a soft enabler, not a hard dependency. `docs/CONTRACT.md` gets a short note that `identity` may carry an optional `source_class` key (shape unchanged); `docs/spec/interfaces.md` (identity wire shape row), `docs/spec/data-model.md` (`entry.sourceClass` field), and `docs/spec/behaviors.md` (B-001 write behavior + the audit-emission behaviors) are updated in the same commit. `docs/architecture/diagrams.md` is checked; no component-boundary or runtime-flow change is expected from this task, so no diagram edit unless the check finds otherwise. | must have |
| REQ-008 | Substrate constraints hold: stdlib-only (`go.mod` require-free), no `Detector`/`MemoryStore`/transport specifics leak into the new code, IPC error shape untouched, `contract_tracer_test.go` passes unmodified (proving the shape claim in REQ-001 is not just asserted but demonstrated), the existing `guard_test.go` / `audit_test.go` / `identity_isolation_test.go` / `identity_durable_test.go` suites pass unmodified except for the additive constructor-argument change to `BuildPIIRedactionEvent`/`BuildInjectionRejectedEvent` call sites (mechanical signature update only, no assertion changes). | must have |

## Readiness gate

- [ ] Test spec `020-write-provenance-source-class-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Confirm at execution time that no other in-flight task is mid-edit on `principal.go`, `guard.go`,
      or `audit.go` (this task touches all three); if task 018/019 exist in the backlog by execution
      time, sequence this task **before** them, not in parallel (they are the intended consumer of
      `entry.sourceClass`)
- [ ] Confirm the next free ADR number against `docs/architecture/decisions/` at execution time (the
      014-numbered file is the latest as of this writing; do not hardcode ADR-015 if a
      concurrently-merged task has since claimed it)

## Acceptance criteria

- [ ] [REQ-001] `validate_write`'s response shape is unchanged; `source_class` is accepted as an
      optional `identity` key with no effect on `validate_read`/`verify_delete` (TC-001).
- [ ] [REQ-002] `sourceClassFromMap` normalizes all four enum values unchanged and every other input
      to `sourceClassUnknown`, as a standalone function distinct from `Principal` (TC-002).
- [ ] [REQ-003] `entry.sourceClass` is set from the same `identity` read that binds `boundIdentity`,
      for both accepted and rejected writes (TC-003).
- [ ] [REQ-004] `OCSFFinding.SourceClass` is populated on both write-triggered event builders from the
      call-site value, not re-derived (TC-004).
- [ ] [REQ-005] `external_tool` vs `agent_authored` are distinguishable end-to-end, in the stored entry
      and in the emitted event, for both write flows (TC-005).
- [ ] [REQ-006] Absent/unrecognized `source_class` yields `sourceClassUnknown` everywhere it is
      threaded, never a silent `agent_authored`/`""` default (TC-006).
- [ ] [REQ-007] ADR + `docs/CONTRACT.md`/`docs/spec/interfaces.md`/`docs/spec/data-model.md`/`docs/spec/behaviors.md`
      updates land in the feat commit; diagram check recorded (TC-007).
- [ ] [REQ-008] `go build ./... && go test ./...` green; `contract_tracer_test.go` and the pre-existing
      identity/audit suites pass with only mechanical (non-assertion) call-site edits (TC-008).

## Verification plan

- **Highest level achievable: L5.** A validation-harness test seeds two writes through
  `MemoryGuard.ValidateWrite`, one with `identity["source_class"] = "external_tool"` and one with
  `"agent_authored"`, against a `CollectingSink`-wired guard (`WithAudit`), and asserts
  field-by-field: (a) the stored `entry.sourceClass` for each (read back via a store-level test
  hook or a subsequent identity-scoped read, per the task-016 pattern), and (b) the emitted
  `OCSFEvent.Finding.SourceClass` for each, using the exact input strings, not a smoke check
  that emission occurred. A third write with no `source_class` key asserts
  `sourceClassUnknown` on both sides. This exercises the real `ValidateWrite` → `entry` → audit
  emission path, not a hand-set field.
- **Level 2, unit:** `go test ./...` → `ok`, including `TestSourceClassFromMapNormalization`
  (REQ-002 table test over all four enum values plus absent/empty/unrecognized cases) and the
  full pre-existing suite unmodified in assertions.
- **Level 3, gate:** `make fitness` / `make check` (or `go build ./... && go test ./...` if no
  `make fitness` target exists yet, per `AGENTS.md`) exit 0.
- **Level 5, validation harness:** `go test -run TestWriteProvenanceThreadsToEntryAndAuditEvent
  ./...`, quoting the final assertion lines showing both `external_tool` and `agent_authored`
  distinguished end-to-end, and the `unknown`-default case.
- **Level 6 (optional, not required for ✅):** live `serve` with `--audit-socket` wired to a real
  `audit-trail` instance (per completed task 017's harness): drive one `validate_write` tagged
  `external_tool` and one tagged `agent_authored` via `nc -U`, then quote the two appended JSONL
  lines in the audit-trail log showing `"source_class":"external_tool"` and
  `"source_class":"agent_authored"` respectively.
- **Trace producer→consumer:** confirm the `source_class` value read inside `ValidateWrite` is the
  **same read** that reaches both `entry.sourceClass` and the emitted event's `Finding.SourceClass`
 , not two independent decodes that could silently drift, by grepping the single call site and
  asserting no second `identity["source_class"]` lookup exists elsewhere in `guard.go`.

## Out of scope

- Any policy that acts on `source_class` (trust-weighted rejection, self-reinforcement detection,
  differential redaction by origin), that is the planned behavioral-detector work (roadmap-referenced
  tasks 018/019, not yet created in this repo).
- Exposing `source_class` on `validate_read` or using it for read-time visibility, it is not an
  access-control key.
- Backfilling `sourceClass` onto entries written before this task ships (pre-existing store data has
  no provenance; a read of such an entry yields the Go zero value `""` for the field, which future
  consumers must treat the same as `sourceClassUnknown`, call this out in the spec, do not attempt a
  migration).
- Verifying the caller-supplied `source_class` claim cryptographically or otherwise, like
  `trust_tier`, it is a caller-supplied, guard-trusted claim across the `0600` socket trust boundary;
  no new verification mechanism is introduced by this task.

## Dependencies

- **Depends on (completed):** task 010 / ADR-007 (`OCSFFinding`, the write-triggered event
  builders); task 016 / ADR-013 (the `identity`-map-optional-key precedent this task follows).
- **Soft-enables:** the not-yet-created behavioral-detector tasks (referenced as 018/019), this
  task is a prerequisite for their `agent_authored` self-reinforcement policy, not the other way
  around.
- **Touches the same files as:** any concurrently in-flight task editing `principal.go`,
  `guard.go`, or `audit.go`, coordinate, do not parallelize (see Readiness gate).
</content>
