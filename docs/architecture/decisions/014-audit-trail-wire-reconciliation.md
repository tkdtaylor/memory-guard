# ADR-014: audit-trail wire reconciliation (plain events over the confirmed emit contract)

**Status:** Accepted
**Date:** 2026-07-12
**Task:** [017 (audit-trail socket sink)](../../tasks/completed/017-audit-trail-socket-sink.md)
**Relates to:** ADR-007 (the `AuditSink` seam, OCSF event builders, `AsyncSink`, fail-open harness, which this completes with a real transport), ADR-001 §5 / task 003 (`deletion_hash`, which finally reaches a consumer here).

## Context

Task 010 (ADR-007) built everything up to the wire: the `AuditSink` seam, OCSF-shaped event builders for all four detection classes, `emitSafe` fail-open semantics, the `AsyncSink` non-blocking dispatch, and a default-disabled config gate. What never shipped is a **real transport**: `main.go` never wires `WithAudit`, so in production nothing is emitted, and the `deletion_hash` that `verify_delete` has returned since task 003 has **no consumer**.

ADR-007 deferred emission until the audit-trail emit endpoint was confirmed live, and flagged that its OCSF shape was "an assumption pending audit-trail confirmation". That confirmation now exists. The sibling's contract is checkable in-repo at `../audit-trail/docs/CONTRACT.md` (implemented in its `chain.go::Emit` + `ipc.go`), and it is **not OCSF**:

```
emit(event) -> { seq, hash }
event = { ts:int, actor:string, action:string, target:string,
          decision?:string, refs:[{type,id}], context?:object }   # context values int/string only
```

Floats are rejected server-side (`validateEmitEventNoFloats`). Transport is newline-delimited JSON over a `0600` Unix socket, one request per connection; the response is `{seq, hash}` on success or `{"error":{code,message,retryable}}` on failure.

## Decision

**Keep the internal `OCSFEvent` builders unchanged and translate to audit-trail's plain event at the sink boundary.** Add an `AuditTrailSink` (`audit_trail_sink.go`) implementing the `AuditSink` seam over the confirmed wire contract; wire it opt-in in `main.go`'s `serve` arm, mandatorily wrapped in `AsyncSink`.

- **Translation at the boundary, not in the guard.** A pure `mapToAuditTrailEvent(OCSFEvent) map[string]any` function performs the mapping; `guard.go`, `ipc.go`, the event builders, and the memory-guard contract are untouched. This is exactly the swap ADR-007 §1 anticipated: the seam absorbs a transport whose wire shape differs from the internal event.
- **Field mapping** (`OCSFEvent` → audit-trail event):

  | audit-trail field | Source | Value |
  |---|---|---|
  | `ts` | `OCSFEvent.Time` | unix seconds, int64 |
  | `actor` | constant | `"memory-guard"` |
  | `action` | `Finding.Operation` | `"validate_write"` \| `"verify_delete"` |
  | `decision` | by `Finding.Type` | `injection_rejected`→`"deny"`; `pii_redaction`→`"allow"`; `deletion_verified`/`residue_found`→**omitted** |
  | `target` | `Finding.StoredID` | the `mem-<hex>` id when non-empty, else `"memory-store"` |
  | `refs` | `Finding.DeletionHash` | `[{"type":"deletion_hash","id":<hash>}]` when non-empty, else `[]` |
  | `context` | remaining detail | `{finding_type, flags (comma-joined string), flag_count:int, severity_id:int, ocsf_class_uid:int}` plus `residue_detected:0\|1` on `verify_delete`; strings and ints only |

- **No lost OCSF detail.** OCSF specifics that survive translation ride in `context` (`ocsf_class_uid`, `severity_id`), so nothing is silently dropped. A full **OCSF-native export** (an OCSF mapping on the audit-trail side) is an explicit follow-on, not foreclosed.
- **`actor` is `"memory-guard"`.** `OCSFEvent` does not carry the calling principal today; the emitting block is the honest actor value. Threading the task-009/016 principal into events (so `actor` becomes the caller's SPIFFE ID) is a noted follow-on, not scope here.
- **Opt-in wiring, off by default.** `serve --audit-socket <path>` (env fallback `MEMGUARD_AUDIT_SOCKET`, flag wins) applies `guard.WithAudit(buildAuditConfig(path))`. An empty path returns a disabled config: zero connections attempted. An enabled config wraps `AuditTrailSink` in `NewAsyncSink(..., 256)` so a stalled endpoint degrades to dropped events, never a stalled hot path.
- **Fail-safe is law (ADR-007 §3).** Every dial/write/read/decode failure or `{error:…}` response returns a non-nil error that `emitSafe`/`AsyncSink` swallow. Guard verdicts are byte-identical whether audit-trail is up, down, absent, or hanging. The sink dials with an I/O deadline (default 2s) so even the drain goroutine on a hanging server eventually errors out rather than leaking.

## Consequences

- The `deletion_hash` from `verify_delete` reaches audit-trail's tamper-evident hash chain as a `refs` entry, closing the "audit-trail linkage" loop promised in `residue.go::deletionHash`'s docstring.
- No transport code (`net`, dialing, deadlines, socket paths) appears in `guard.go` or `ipc.go`; `audit_trail_sink.go` owns all of it, `main.go` touches only the flag/env strings and the construction helper. `emitSafe` remains the only guard-side emission call site.
- No raw or redacted content and no raw PII ever crosses the wire: only flag labels, ids, the deletion hash, and envelope fields. Every JSON number on the wire is an int64 (audit-trail rejects floats).
- Substrate constraints hold: `net` + `encoding/json` are stdlib, so `go.mod` stays `require`-free; the task-010 `audit_test.go` suite is untouched and green.
- **Deferred, recorded:** OCSF-native export; threading the caller principal into `actor`; emitting for `validate_read` detections; retry/spooling beyond `AsyncSink`'s drop-on-full. The stale roadmap T5/R2 "OCSF emission" wording is flagged to the operator, not edited (`docs/plans/` is ask-first). ADR-007 is not rewritten; this ADR references it as the anticipating decision.
