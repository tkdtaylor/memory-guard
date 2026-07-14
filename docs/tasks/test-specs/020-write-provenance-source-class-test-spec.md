# Test Spec 020: Write-provenance / source-class tagging

**Linked task:** [`docs/tasks/backlog/020-write-provenance-source-class.md`](../backlog/020-write-provenance-source-class.md)
**Written:** 2026-07-14

> Authored ahead of execution. This spec covers threading an optional `source_class` tag from the
> `identity` map through `ValidateWrite` into `entry.sourceClass` and into the emitted audit
> event's `Finding.SourceClass`, with a documented `unknown` default. Every case asserts the
> **exact value threaded**, never merely "an event was emitted" or "a field exists", the
> load-bearing property is that the stored entry and the audit event agree, value-for-value, with
> the identity read at the `ValidateWrite` call site, and that absent/garbage input degrades to
> the sentinel rather than to a silent, more-trusted default. The pre-existing `guard_test.go`,
> `audit_test.go`, `identity_isolation_test.go`, `identity_durable_test.go`, and
> `contract_tracer_test.go` suites must stay green with no assertion changes (only mechanical
> call-site signature edits where `BuildPIIRedactionEvent`/`BuildInjectionRejectedEvent` gain a
> parameter).

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001, TC-008 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-006 | ✅ | ✅ |
| REQ-007 | TC-007 | ✅ | ✅ |
| REQ-008 | TC-008 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths (absent key, empty string, unrecognized value) are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] The full pre-existing suites (`guard_test.go`, `audit_test.go`, `identity_isolation_test.go`,
      `identity_durable_test.go`, `contract_tracer_test.go`) pass with assertions unchanged

## Test fixtures

- **Identities** (typed wire shape, `map[string]any`, extended with the optional key this task adds):
  - `idExternalTool` = `{"spiffe_id": "spiffe://secure-agents/agent/tool-runner", "trust_tier": "attested", "source_class": "external_tool"}`
  - `idAgentAuthored` = `{"spiffe_id": "spiffe://secure-agents/agent/planner", "trust_tier": "attested", "source_class": "agent_authored"}`
  - `idUserInput` = `{"spiffe_id": "spiffe://secure-agents/agent/operator-cli", "trust_tier": "attested", "source_class": "user_input"}`
  - `idSystem` = `{"trust_tier": "attested", "source_class": "system"}` (no `spiffe_id`, provenance is independent of identity binding)
  - `idNoSourceClass` = `{"spiffe_id": "spiffe://secure-agents/agent/alpha", "trust_tier": "attested"}` (key entirely absent)
  - `idEmptySourceClass` = `idNoSourceClass` plus `"source_class": ""`
  - `idUnrecognizedSourceClass` = `idNoSourceClass` plus `"source_class": "tool_output"` (not in the enum; a plausible typo/legacy value)
  - `nil` identity = the absent-map case (existing `validate_write` behavior, unaffected by this task)
- **Enum constants under test:** `sourceClassExternalTool = "external_tool"`, `sourceClassUserInput = "user_input"`, `sourceClassAgentAuthored = "agent_authored"`, `sourceClassSystem = "system"`, `sourceClassUnknown = "unknown"`.
- **Injection-triggering content:** a string from the existing poisoning corpus (`poisoning_suite_test.go`) that reliably sets `injection_suspected`, reused here (not re-derived) so TC-004/TC-005's rejected-write path is exercised against a known-good fixture.
- **PII-triggering content:** `"contact alice@example.com about the rollout"` (reused pattern from `guard_test.go`), which reliably sets a `pii:EMAIL` flag without tripping injection detection.
- **Sink:** `CollectingSink` wired via `NewMemoryGuard(...).WithAudit(AuditConfig{Enabled: true, Sink: &CollectingSink{}})`, per the task-010 test pattern, synchronous, so every emitted event is visible immediately after the `ValidateWrite` call returns (no `AsyncSink` drain race in these unit-level cases).
- **Reading back `entry.sourceClass`:** a package-internal test helper (or a store-level `Get`/`AllByIndex` call, consistent with how `residue_test.go` inspects stored entries directly), read the field off the store, not off a public IPC response (the field is not, and per REQ-005/out-of-scope must not become, part of any `validate_*` response).

## Test cases

### TC-001: contract shape is unchanged by the new optional key
- **Requirement:** REQ-001
- **Input:** `g := NewMemoryGuard(NewNativeDetector())`; call `g.ValidateWrite("contact alice@example.com about the rollout", idExternalTool)`.
- **Expected:** the returned map has exactly the three keys `allow`, `stored_id`, `flags` (no `source_class` key leaks into the response, reflect the map's key set and assert it equals `{"allow", "stored_id", "flags"}`); `allow == true`; `stored_id` matches `^mem-[0-9a-f]{12}$`. A second call `g.ValidateRead("contact", idExternalTool)` returns exactly `{"allow", "content_redacted", "flags"}` with no `source_class` key, proving the read path is untouched.
- **Edge cases:** `go test -run TestTracer ./...` (the existing `contract_tracer_test.go`) passes with zero edits to its assertions, the live-socket response shapes are unaffected by the new optional request key.

### TC-002: `sourceClassFromMap` normalizes every input to the documented value
- **Requirement:** REQ-002
- **Input:** table test calling `sourceClassFromMap(identity)` directly (no guard involved) over: `{"source_class": "external_tool"}`, `{"source_class": "user_input"}`, `{"source_class": "agent_authored"}`, `{"source_class": "system"}`, `{}` (empty map), `{"source_class": ""}`, `{"source_class": "tool_output"}` (unrecognized), `{"source_class": 42}` (wrong JSON type, a number, not a string), `nil` (nil map).
- **Expected:** the four recognized-string cases return their input unchanged; every other case (empty map, empty string, unrecognized string, wrong type, nil map) returns `sourceClassUnknown` (`"unknown"`). Assert exact string equality per case, not just non-empty.
- **Edge cases:** `sourceClassFromMap` is a package-level function distinct from `principalFromMap`/`PreVerifiedPrincipal`, grep-assert (or reflect-assert) that `Principal`'s method set (`Subject`, `Attested`, `SharedScope`) is unchanged (still exactly 3 methods), proving `source_class` was not added as a 4th accessor.

### TC-003: `entry.sourceClass` is set from the same identity read that binds `boundIdentity`
- **Requirement:** REQ-003
- **Input:** `g := NewMemoryGuard(NewNativeDetector())`; `res := g.ValidateWrite("contact alice@example.com about the rollout", idAgentAuthored)`; read the stored entry back via the test helper using `res["stored_id"]`.
- **Expected:** `entry.sourceClass == "agent_authored"` and `entry.boundIdentity == "spiffe://secure-agents/agent/planner"` (both derived from the same `idAgentAuthored` map, in the same call).
- **Edge cases:** a rejected (injection-suspected) write, `g.ValidateWrite(<poisoning fixture>, idExternalTool)`, has no `stored_id` to read back (fail-closed, unchanged), but the value is still available to the audit event per TC-004; assert this by wiring a `CollectingSink` on the same call and checking the emitted event's `SourceClass` (not a store read, since nothing persisted).

### TC-004: `OCSFFinding.SourceClass` is populated on both write-triggered builders
- **Requirement:** REQ-004
- **Input:** `sink := &CollectingSink{}`; `g := NewMemoryGuard(NewNativeDetector()).WithAudit(AuditConfig{Enabled: true, Sink: sink})`. Call 1: `g.ValidateWrite("contact alice@example.com about the rollout", idUserInput)` (triggers `BuildPIIRedactionEvent`). Call 2: `g.ValidateWrite(<poisoning fixture>, idAgentAuthored)` (triggers `BuildInjectionRejectedEvent`).
- **Expected:** `sink.Events()` has length 2; `events[0].Finding.Type == "pii_redaction"` and `events[0].Finding.SourceClass == "user_input"`; `events[1].Finding.Type == "injection_rejected"` and `events[1].Finding.SourceClass == "agent_authored"`.
- **Edge cases:** `BuildDeletionEvent`'s call sites are unmodified, run the existing `TestAuditTC003...` (deletion event) case unmodified and assert `Finding.SourceClass == ""` (Go zero value; deletion carries no writer-provenance field by design, per Out of scope).

### TC-005: `external_tool` and `agent_authored` are distinguishable end-to-end
- **Requirement:** REQ-005 (also exercises REQ-003 + REQ-004 together as the composed producer→consumer path, this is the task's headline assertion)
- **Input:** `sink := &CollectingSink{}`; `g := NewMemoryGuard(NewNativeDetector()).WithAudit(AuditConfig{Enabled: true, Sink: sink})`. Write A: `resA := g.ValidateWrite("contact alice@example.com about the rollout", idExternalTool)`. Write B: `resB := g.ValidateWrite("contact bob@example.com about the launch", idAgentAuthored)`.
- **Expected:** reading back the stored entries by `resA["stored_id"]` / `resB["stored_id"]`: entry A's `sourceClass == "external_tool"`, entry B's `sourceClass == "agent_authored"`, **not equal to each other**. `sink.Events()`: event for A has `Finding.SourceClass == "external_tool"`; event for B has `Finding.SourceClass == "agent_authored"`, matching their respective stored entries exactly (cross-check `events[i].Finding.StoredID` against `resA`/`resB`'s `stored_id` to pair them correctly rather than assuming slice order).
- **Edge cases:** mutation probe, if the implementation collapsed both to a single shared value (e.g. always `"agent_authored"`, the most-trusted class, or always the first write's value), this assertion fails; this is the case the requirement exists to catch, so the test must fail loudly under that mutation, not pass vacuously.

### TC-006: absent/unrecognized `source_class` never defaults to a more-trusted value
- **Requirement:** REQ-006
- **Input:** three writes through a `CollectingSink`-wired guard: `g.ValidateWrite("contact alice@example.com about the rollout", idNoSourceClass)`, `g.ValidateWrite("contact bob@example.com about the launch", idEmptySourceClass)`, `g.ValidateWrite("contact carol@example.com about the merger", idUnrecognizedSourceClass)`.
- **Expected:** all three stored entries have `sourceClass == "unknown"` (`sourceClassUnknown`); all three emitted events have `Finding.SourceClass == "unknown"`. Explicitly assert `!= "agent_authored"` and `!= ""` for each, the negative assertions are load-bearing (a plausible bug is defaulting the zero-value Go string `""` straight through instead of normalizing it to the sentinel).
- **Edge cases:** `nil` identity (no map at all) on `g.ValidateWrite("contact dana@example.com about the deal", nil)` also yields `sourceClass == "unknown"` on the stored entry (existing `nil`-identity write behavior from prior tasks is unaffected, `boundIdentity` still binds unbound per ADR-004, independently of this new field).

### TC-007: ADR + spec propagation, contract note, seam hygiene
- **Requirement:** REQ-007
- **Input:** inspect the tree after the feat commit; run `make fitness` / `make check` (or `go build ./... && go test ./...` if no fitness target exists); read `go.mod`; read `docs/CONTRACT.md`, `docs/spec/interfaces.md`, `docs/spec/data-model.md`, `docs/spec/behaviors.md`, `docs/architecture/diagrams.md`.
- **Expected:** a new ADR exists in `docs/architecture/decisions/` (number assigned at execution time) and records: the envelope-vs-top-level-field decision with the rejected alternative named explicitly and the contract-impact analysis (tracer shape unaffected, ADR-013 `scope` precedent cited); the standalone-function-vs-`Principal`-accessor decision; the `unknown` default and the fail-closed policy statement for future consumers; the soft-enabler relationship to the not-yet-created behavioral-detector tasks. `docs/CONTRACT.md` carries a short note that `identity` may carry an optional `source_class` key with the shape otherwise unchanged. `docs/spec/interfaces.md` documents the `identity` wire shape's new optional field; `docs/spec/data-model.md` documents `entry.sourceClass`; `docs/spec/behaviors.md`'s B-001 (write) and the audit-emission behaviors describe the threading. `docs/architecture/diagrams.md` is either updated (if a diagrammed flow names the write path's fields) or the task record shows the check was made with no edit needed, not silently skipped.
- **Edge cases:** every spec file is rewritten in place, not appended to (grep for a stray "update:" or "task 020:" paragraph tacked onto an existing section instead of an in-place edit); no future-tense ("will support", "planned to") language enters `docs/spec/`.

### TC-008: substrate constraints and regression fence
- **Requirement:** REQ-001, REQ-008
- **Input:** `go build ./... && go test ./...` on the finished tree; `go test -run 'TestTracer|TestWriteBindsVerifiableIdentity|TestReadReturnsOnlyMatchingIdentity|TestNoCrossIdentityLeakage|TestPIIRedactionUnchangedUnderIdentityScoping|TestAuditTC' ./...`; `grep -c require go.mod`.
- **Expected:** `go test ./...` → `ok` for all packages; the named pre-existing tests all pass with **no assertion edits** (a diff of the test files shows only mechanical additions of a `sourceClass`/`"unknown"` argument at `BuildPIIRedactionEvent`/`BuildInjectionRejectedEvent` call sites, never a changed expected value); `grep -c require go.mod` → `0` (still require-free).
- **Edge cases:** confirm via `grep -n 'identity\["source_class"\]' guard.go` that exactly one call site reads the key (inside the single `sourceClassFromMap` invocation at the top of `ValidateWrite`), a second, independent read elsewhere would be the drift bug the task's "trace producer→consumer" verification step exists to catch.
</content>
