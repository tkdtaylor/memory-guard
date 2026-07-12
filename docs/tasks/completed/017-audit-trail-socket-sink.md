# Task 017: audit-trail socket sink (live emission over the sibling's emit contract)

**Project:** memory-guard
**Created:** 2026-07-11
**Status:** completed

> Roadmap [T5](../../plans/roadmap.md) / R2 calls for emitting detections to the sibling `audit-trail` block. Completed task 010 (ADR-007) built everything **up to** the wire: the `AuditSink` seam, OCSF-shaped event builders for all four detection classes, `emitSafe` fail-open semantics, the `AsyncSink` non-blocking dispatch, and a default-disabled config gate. What never shipped is a **real transport**: `main.go` never wires `WithAudit`, so in production nothing is ever emitted, and the `deletion_hash` that `verify_delete` has returned since task 003 still has **no consumer**. ADR-007 explicitly deferred this ("emission stays disabled until the audit-trail emit endpoint is confirmed live") and flagged that its OCSF shape was "an assumption pending audit-trail confirmation". That confirmation now exists: the sibling's contract is checkable in-repo at `../audit-trail/docs/CONTRACT.md` and it is **not OCSF**. This task builds the confirmed-contract transport, its opt-in wiring, and records the reconciliation.

## Goal

Add an `AuditTrailSink` implementing the `AuditSink` seam over the sibling audit-trail's **confirmed** wire contract: per event, one newline-terminated `{"op":"emit","event":{…}}` request over its Unix socket, expecting `{seq, hash}` back. The sink translates the existing internal `OCSFEvent` into audit-trail's plain event shape `{ts, actor, action, target, decision?, refs[], context?}` (integer/string values only, no floats) at the transport boundary, so `guard.go`, `ipc.go`, the event builders, and the contract are untouched. Wiring is opt-in (`serve --audit-socket`, env fallback `MEMGUARD_AUDIT_SOCKET`, default off) and mandatorily wrapped in `AsyncSink`: guard verdicts never depend on audit-trail availability. Deletion events finally deliver `deletion_hash` to a consumer that chains it.

## Context

- **What task 010 shipped (do not rebuild):** `audit.go` end to end: `AuditSink` (single `Emit(OCSFEvent) error`), `AuditConfig` + `MemoryGuard.WithAudit` (guard.go), `emitSafe` (the only guard-side call site; swallows errors, recovers panics), `AsyncSink` (bounded buffer, drop-on-full, single drain goroutine, ADR-007 §6 mandates it for real transports), the event builders `BuildPIIRedactionEvent` / `BuildInjectionRejectedEvent` / `BuildDeletionEvent`, and the test sinks (`CollectingSink`, `FailingSink`, `PanicSink`, `SlowSink`, `ChannelSink`, `NoOpSink`). The `audit_test.go` suite stays green unmodified.
- **The sibling's confirmed contract** (`/home/kevin/Code/Public/audit-trail/docs/CONTRACT.md`, implemented in its `chain.go::Emit` + `ipc.go`): `emit(event) -> {seq, hash}`; event fields `ts` (unix seconds, int), `actor` (requester identity string), `action` (verb string), `target` (resource string), `decision?` (`allow|deny|require_approval|block`), `refs` (`[{type,id}]`), `context?` (object, **integer/string values only**); server assigns `seq`/`prev_hash`/`hash` and appends to a hash-chained JSONL log. Floats are rejected (`validateEmitEventNoFloats`). Transport: newline-delimited JSON over a `0600` Unix socket, one request per connection. Executor: re-read that CONTRACT.md before coding; it is the source of truth, not this summary.
- **OCSF reconciliation (the decision this task records):** the roadmap and ADR-007 say "OCSF events to audit-trail", but the confirmed audit-trail contract is the plain event above, and a full OCSF mapping on its side does not exist. Resolution: **keep** the internal `OCSFEvent` builders (zero churn in guard/audit internals, exactly the swap ADR-007 designed for) and translate to the plain event **in the sink**; propose plain audit-trail events now and note an OCSF-native export as an explicit follow-on. OCSF detail that survives translation rides in `context` (`ocsf_class_uid`, `severity_id`) so nothing is silently lost.
- **Why `actor` is `"memory-guard"`:** `OCSFEvent` does not carry the calling principal today; the emitting block is the honest actor value. Threading the task-009/016 principal into events (so `actor` becomes the caller's SPIFFE ID) is a noted follow-on, not scope creep here.
- **Fail-safe posture is already law:** ADR-007 §3 (fail-open sink vs. fail-closed write-gate) and the existing TC-006 harness define it; this task extends the same proof to a real socket: dead path, hanging server, and error responses must leave every verdict byte-identical and the hot path unstalled.
- **Consumer for `deletion_hash`:** `guard.go::VerifyDelete` already calls `BuildDeletionEvent(hash, residueDetected, residueFlags)`; once the sink lands, that hash reaches audit-trail's tamper-evident chain as a `refs` entry, closing the "audit-trail linkage" loop promised in `residue.go::deletionHash`'s docstring.

## Contract shapes

memory-guard's own three verbs and IPC error shape: **unchanged**. New wire surface (emitted, not served) per event, mapped from `OCSFEvent`:

| audit-trail field | Source | Value |
|---|---|---|
| `ts` | `OCSFEvent.Time` | unix seconds, int64 |
| `actor` | constant | `"memory-guard"` |
| `action` | `Finding.Operation` | `"validate_write"` \| `"verify_delete"` |
| `decision` | by `Finding.Type` | `injection_rejected` → `"deny"`; `pii_redaction` → `"allow"`; `deletion_verified` / `residue_found` → **omitted** (not a gate verdict) |
| `target` | `Finding.StoredID` | the `mem-<hex>` id when non-empty, else `"memory-store"` |
| `refs` | `Finding.DeletionHash` | `[{"type":"deletion_hash","id":<hash>}]` when non-empty, else `[]` |
| `context` | remaining finding detail | `{"finding_type": <Type>, "flags": <strings.Join(Flags, ",")>, "flag_count": <int>, "severity_id": <int>, "ocsf_class_uid": <int>}` plus `"residue_detected": 0|1` on `verify_delete` events; strings and ints only |

Request/response framing (per audit-trail's CONTRACT.md): dial the Unix socket, write `{"op":"emit","event":{…}}` + `\n`, read one response line: `{"seq":<int>,"hash":"<hex>"}` on success, `{"error":{code,message,retryable}}` on failure; close. New configuration:

```
serve --audit-socket <path>      # opt-in; empty/absent = emission disabled (default)
MEMGUARD_AUDIT_SOCKET=<path>     # env fallback when the flag is not given; flag wins
```

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | An `AuditTrailSink` in a new `audit_trail_sink.go` implements `AuditSink` over the confirmed wire contract: per event, dial-write-read-close with an I/O deadline (default 2s, constructor-settable); any dial/write/read/decode failure or `{error:…}` response returns a non-nil error (which `emitSafe`/`AsyncSink` swallow upstream). No transport code outside this file. | must have |
| REQ-002 | The `OCSFEvent` → audit-trail event mapping matches the table above exactly, including the decision omissions and the `refs` deletion-hash entry; all `context` values are strings or ints. | must have |
| REQ-003 | Opt-in wiring: a construction helper (e.g. `buildAuditConfig(socketPath string) AuditConfig` beside the sink) returns disabled config for an empty path and an enabled `AuditConfig{Enabled: true, Sink: NewAsyncSink(NewAuditTrailSink(path, …), 256)}` otherwise; `main.go`'s `serve` arm parses `--audit-socket` (env fallback `MEMGUARD_AUDIT_SOCKET`, flag wins) and applies `guard.WithAudit(...)`. Default remains completely off: zero connections attempted. | must have |
| REQ-004 | Fail-safe proven against a real socket: dead path, hanging server (async-wrapped, hot path bounded), and error-responding server all leave every `validate_*` / `verify_delete` verdict identical to the disabled configuration, with no surfaced error and no panic. | must have |
| REQ-005 | Deletion events reach the sink with `refs` carrying **the identical** `deletion_hash` string the `verify_delete` response returned (value-for-value assertion), for both `deletion_verified` and `residue_found` (with `residue_detected` 0/1 in context). | must have |
| REQ-006 | No raw or redacted content, and no raw PII, ever crosses the wire: raw captured request bytes are scanned in tests (task-010 REQ-004 extended to the transport). | must have |
| REQ-007 | No floats on the wire: every JSON number in every captured request parses as a base-10 int64 (audit-trail rejects float-bearing events). | must have |
| REQ-008 | ADR (next free number, expected ADR-014) records the reconciliation: confirmed plain contract vs. the roadmap/ADR-007 "OCSF" wording, builders retained + sink-boundary translation, OCSF-native export as an explicit follow-on, `actor` follow-on noted. `docs/spec/configuration.md` (flag + env rows), `docs/spec/interfaces.md` / `behaviors.md` (emission path), and `docs/architecture/diagrams.md` (memory-guard → audit-trail runtime edge) updated in the same commit. | must have |
| REQ-009 | Substrate constraints: stdlib-only (`go.mod` require-free), `make fitness` green, no transport specifics in `guard.go`/`ipc.go`, the task-010 `audit_test.go` suite green unmodified, `emitSafe` still the only guard-side emission call site. | must have |

## Implementation outline

1. `scripts/start-task.sh 017 audit-trail-socket-sink`; move this file to `docs/tasks/active/`.
2. Re-read `/home/kevin/Code/Public/audit-trail/docs/CONTRACT.md` and its `ipc.go`/`chain.go::Emit`; write the ADR; commit `docs: add ADR NNN — audit-trail wire reconciliation (plain events over the confirmed emit contract)`.
3. `audit_trail_sink.go`: `mapToAuditTrailEvent(e OCSFEvent) map[string]any` (the table above; pure function, unit-testable without a socket); `AuditTrailSink{socketPath string, timeout time.Duration}` + `NewAuditTrailSink`; `Emit` = dial with deadline, marshal `{"op":"emit","event":…}`, write line, read + decode response line, map `{error:…}` to an error; `buildAuditConfig(path string) AuditConfig`.
4. `main.go` `serve` arm: add the `--audit-socket` flag to the existing `FlagSet`, env fallback, `guard = guard.WithAudit(buildAuditConfig(path))` when non-empty, and extend the startup stderr line to name the audit target (or `audit: off`).
5. Tests per the spec in a new `audit_trail_sink_test.go`: fake-server harness + TC-001…TC-006; reuse the timing pattern of `TestAuditTC006_FailOpen` for the hanging-server bound.
6. Spec + diagram updates (REQ-008), same commit as the code. Add the 017 row to `coverage-tracker.md` at 🟡.
7. `make check` green; run the L6 observation (below); move this file to `docs/tasks/completed/`; commit `feat: complete task 017 — audit-trail-socket-sink`.

## Readiness gate

- [x] Test spec `017-audit-trail-socket-sink-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Confirm the sibling contract details against `/home/kevin/Code/Public/audit-trail/docs/CONTRACT.md` at execution time (fields, one-request-per-connection framing, error shape); if anything diverges from this task's table, the ADR records the delta and the table yields
- [ ] Confirm a runnable audit-trail binary for the L6 step (`/home/kevin/Code/Public/audit-trail/bin/audit-trail` exists today, or `go build` it from the sibling repo)
- [ ] If task 015 has merged, rebase: both tasks touch `main.go`'s `serve` arm

## Acceptance criteria

- [ ] [REQ-001] Sink speaks the wire contract with deadlines; failures become swallowed errors (TC-001, TC-005).
- [ ] [REQ-002] Field mapping exact per the table, all three detection flows (TC-001, TC-002, TC-003).
- [ ] [REQ-003] Off by default (zero connections); flag + env wiring proven, flag wins (TC-006).
- [ ] [REQ-004] Verdicts identical and hot path bounded across dead/hanging/erroring endpoints (TC-005).
- [ ] [REQ-005] `refs` deletion-hash equals the verb's returned hash, both deletion classes (TC-003).
- [ ] [REQ-006] No content/PII bytes in any captured request (TC-002, TC-003).
- [ ] [REQ-007] Every wire number is an int (TC-004).
- [ ] [REQ-008] ADR + configuration/interfaces/behaviors spec + diagram edge land in the feat commit (TC-007).
- [ ] [REQ-009] `make fitness` green; `go.mod` require-free; task-010 suite untouched and green (TC-008).
- [ ] `go build ./... && go test ./...` green; `make check` green.

## Verification plan

- **Highest level achievable: L6**, operator-observed against the **real sibling binary**: `/home/kevin/Code/Public/audit-trail/bin/audit-trail serve --socket /tmp/at-017.sock --logfile /tmp/at-017.log`, then `go run . serve --socket /tmp/mg-017.sock --audit-socket /tmp/at-017.sock`, drive one poisoned `validate_write` and one write+`verify_delete` cycle via `nc -U /tmp/mg-017.sock`, then quote: the appended JSONL lines in `/tmp/at-017.log` (showing `actor":"memory-guard"`, the `deny` decision, and the `deletion_hash` ref matching the verb response) and the closing line of `/home/kevin/Code/Public/audit-trail/bin/audit-trail verify --logfile /tmp/at-017.log` proving the chain verifies with the new events in it.
- **Level 2 (unit):** `go test ./...` → `ok` (mapping function, fake-server cases, fail-safe matrix, existing audit suite).
- **Level 3 (gate):** `make fitness` and `make check` exit 0.
- **Level 5 (validation harness):** the fake-server integration cases (TC-001…TC-005) exercise the full live path guard → `emitSafe` → `AsyncSink` → `AuditTrailSink` → Unix socket → decoded response; record the final assertion lines in the verify commit. L6 above is preferred evidence since the real consumer exists in the sibling repo.

## Out of scope

- An OCSF-native export or any OCSF mapping work on the audit-trail side (explicit follow-on recorded in the ADR).
- Threading the caller principal into events so `actor` carries a SPIFFE ID (follow-on; depends on plumbing identity into the emission call sites).
- Emitting for `validate_read` detections (reads currently emit nothing in task 010's design; changing that is a separate behavior decision).
- Retry/spooling of dropped events, delivery guarantees, or backpressure beyond `AsyncSink`'s documented drop-on-full (availability over completeness stands).
- Any change to audit-trail itself, to memory-guard's served verbs, or to the IPC error shape.
- Updating the stale roadmap T5/R2 wording: `docs/plans/` is ask-first; flag it to the operator.

## Dependencies

- **Depends on (completed):** task 010 / ADR-007 (`AuditSink` seam, builders, `AsyncSink`, fail-open harness); task 003 (`deletion_hash`).
- **Soft runtime dependency:** a live audit-trail socket, needed only when emission is enabled; never at build/test time (fake server) and never for verdicts (fail-open).
- **Independent of tasks 015/016** functionally; coordinate with 015 on `main.go`'s `serve` arm (sequence, do not parallelize).
