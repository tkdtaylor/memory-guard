# ADR-007: Audit-Trail OCSF Emission — Seam Design, Event Shape, and Fail-Open Posture

**Date:** 2026-06-24
**Status:** Accepted
**Task:** 010 (audit-trail OCSF emission)

## Context

memory-guard computes detections (PII redaction, injection rejection, residue found, deletion) on
every hot-path call and returns them to the caller as `flags`. Roadmap T5 / R2 calls for also
emitting them as OCSF-shaped events to the sibling `audit-trail` project — a **soft runtime
dependency, not a build-time blocker**.

Three design questions required decision:

1. **What is the OCSF event shape?** The sibling audit-trail's exact consumed wire contract is not
   confirmed in this repo. The public OCSF schema is the only authoritative reference available.

2. **How is the transport wired without leaking it into the guard?** The guard is a security hot path;
   the transport (Unix socket / HTTP / file) must be swappable without touching `guard.go` or `ipc.go`.

3. **What is the failure posture?** Emission is a soft dependency; a down/slow/absent sink must never
   block the hot path and must never change a `validate_*` / `verify_delete` verdict.

## Options considered

### Option A: Inline OCSF emission in guard.go
Direct transport calls inside `ValidateWrite` / `VerifyDelete`. Simple, but leaks transport specifics
into the guard and makes the seam impossible to test in isolation.

**Rejected:** breaks the principle "no transport specifics in guard.go / ipc.go" and makes the sink
untestable except via a live audit-trail endpoint.

### Option B: AuditSink seam (new audit.go) — CHOSEN
A small `AuditSink` interface (single `Emit(OCSFEvent) error` method) added to `audit.go`. The guard
holds a nullable `AuditSink` field; every detection point calls `emitSafe(g.audit, event)`, which is
fully fail-open (swallows errors, recovers panics, no-ops on nil). The concrete transport (socket / HTTP
/ file) lives entirely in the `AuditSink` implementor — never in `guard.go` or `ipc.go`. Tests swap
in a `CollectingSink` or `FailingSink` without touching the guard.

**Accepted:** matches the existing pattern (Detector seam, MemoryStore seam); transport is swappable
with zero guard/IPC/contract impact.

### Option C: Background goroutine / async queue
Buffer events in a channel and flush them on a background goroutine. Adds concurrency complexity and
a subtle "did the test drain the channel?" race. The `CollectingSink` and `ChannelSink` in `audit.go`
provide optional async use for callers who need it; the core `emitSafe` remains synchronous to keep
the latency model simple.

**Deferred:** not needed for v0. `ChannelSink` is provided as an optional async building block for
v1 real transports.

## Decision

**The AuditSink seam (Option B) is adopted.** Specifically:

### 1. Event shape: PUBLIC OCSF standard (pending audit-trail confirmation)

The event is modelled on the **public OCSF 1.1 schema** (`Security Finding` class, `class_uid=2001`,
`category_uid=2`, `activity_id=1`). Required envelope fields:

```
class_uid       — 2001 (Security Finding)
category_uid    — 2 (Findings)
activity_id     — 1 (Create)
severity_id     — 1 (Info) / 2 (Low) / 3 (Medium) / 4 (High); detection-class-dependent
time            — UTC Unix timestamp (int64, seconds)
metadata.product.name — "memory-guard"
metadata.version      — "1.1.0" (OCSF schema version)
finding.type       — "pii_redaction" / "injection_rejected" / "residue_found" / "deletion_verified"
finding.operation  — "validate_write" / "verify_delete"
finding.flags      — []string: the same flag strings guard.go already computes
finding.flag_count — len(flags)
finding.stored_id  — the opaque mem-<hex> id (empty for rejections and deletions)
finding.deletion_hash — SHA-256 audit-linkage value (present on deletion/residue events)
finding.residue_detected — bool pointer, present only on verify_delete events
finding.related_events — [] placeholder for future chaining
```

**Documented assumption:** this shape is pinned to the PUBLIC OCSF standard. The sibling
`audit-trail`'s exact consumed contract has NOT been confirmed live. When audit-trail's emit
endpoint is confirmed, the event shape must be reconciled with whatever audit-trail expects —
the `AuditSink` seam makes that a one-implementation change with zero guard/IPC/contract impact.
This is why emission is **default-DISABLED** (see §3 below).

### 2. AuditSink seam implementation (audit.go)

- `AuditSink` interface: one method, `Emit(OCSFEvent) error`.
- `emitSafe(sink, event)`: the ONLY function that calls `Emit` from the guard. Fail-open: recovers
  panics, swallows errors, no-ops on nil.
- `CollectingSink`: thread-safe in-memory fake for tests.
- `FailingSink`: always returns an error; proves TC-006 (fail-open).
- `PanicSink`: always panics; proves the `recover()` wrapper.
- `SlowSink`: blocks for a fixed delay; proves the async dispatch keeps the hot path unstalled.
- `NoOpSink`: zero-cost no-op; used when emission is disabled.
- `ChannelSink`: non-blocking buffered channel for optional async use.
- `AsyncSink`: the non-blocking dispatch wrapper (see §6).
- `WithAudit(AuditConfig)`: builder method on `*MemoryGuard`; the single injection point.

### 6. Async (non-blocking) dispatch for slow transports

REQ-005 requires that a **slow/blocking** sink must not stall the hot path. `emitSafe` is
**synchronous** — it calls `Emit` inline. A synchronous fast sink (the default `NoOpSink`, the
in-process `CollectingSink`) is correct and keeps tests deterministic (every event is observable
with no drain race). But a real network transport (a Unix socket to audit-trail, an HTTP POST) can
block, and a synchronous blocking `Emit` *would* stall `validate_*`.

**Decision:** real transports are wrapped in `AsyncSink` (added in this task). `AsyncSink`:

- Hot-path `Emit` only **enqueues** the event onto a bounded buffered channel and returns
  immediately (fire-and-forget). It never blocks on the wrapped (slow) sink.
- A single background **drain goroutine** forwards each buffered event to the wrapped transport,
  off the hot path.
- When the buffer is **full**, the event is **dropped** (fail-open — availability over
  completeness; a slow audit-trail degrades to dropped events, never a stalled memory hot path).
- A panic in the wrapped sink is **recovered** inside the drain goroutine, so a misbehaving
  transport never crashes the process.
- `Close()` stops the drain goroutine (idempotent), draining remaining buffered events best-effort.

The synchronous in-process sinks stay synchronous; `AsyncSink` is **opt-in** via `NewAsyncSink`,
intended for the real-transport wiring once the audit-trail endpoint is confirmed. This keeps the
deterministic unit tests free of drain races while making the slow-transport invariant provable
(`TestAuditTC006_FailOpen/slow_sink_does_not_stall_hot_path` wraps a 500 ms `SlowSink` in an
`AsyncSink` and asserts the hot-path call returns under a 50 ms bound, with the slow `Emit`
completing later off the hot path).

### 3. Fail-open posture and config gate

- **Fail-open:** `emitSafe` is the hot-path call. Error from `Emit` is swallowed. Panic from `Emit`
  is recovered. A nil sink is a no-op. A failing sink NEVER changes a `validate_*` / `verify_delete`
  verdict, NEVER blocks the caller, NEVER surfaces an error. The write-gate's fail-CLOSED posture
  is completely independent of the sink's fail-open posture.
- **Config-gated, default-DISABLED:** `AuditConfig.Enabled` defaults to `false`. An invalid config
  (`Enabled: true, Sink: nil`) fails closed to disabled. Emission stays disabled until the
  audit-trail emit endpoint is confirmed live (the soft runtime dependency).

### 4. PII invariant on the audit channel

No raw PII ever appears in an emitted event. The event is built from flags (metadata strings like
`"pii:EMAIL"`) and the opaque `stored_id` and `deletion_hash` — never from the raw input text or
the redacted content string. This is the same invariant as the store (PII never lands anywhere
unredacted) applied to the audit channel. Asserted directly in TC-005.

### 5. Seam isolation — fitness gate

The existing `TestFitnessSeam` grep (`fitness_test.go`) already checks that no store or detector
backend specifics leak into `guard.go` / `ipc.go` / `main.go` / `CONTRACT.md`. The `AuditSink` is
the transport seam — its field name (`audit`) is a plain Go type name in `guard.go`, not a transport
token. The fitness seam check continues to pass clean after this change (verified: `make fitness` →
`All fitness checks passed.`). No new token needs to be added to the banned list because the seam
is correctly wired as an interface, not an import.

## Consequences

- **Positive:** transport is swappable (Unix socket, HTTP, file, or any future audit-trail wire
  format) with zero guard/IPC/contract impact. Tests are fully local with fake sinks — no live
  audit-trail required. The fail-open posture is provably correct (TC-006 harness).
- **Negative:** the OCSF event shape is an assumption pending audit-trail confirmation. The first live
  connection to audit-trail may require shape adjustments — but those live in `audit.go` (the event
  constructors) and the `AuditSink` implementor, not in `guard.go` or the contract.
- **Deferred:** L6 (live emission to a real `audit-trail` socket) is deferred until the audit-trail
  emit endpoint is confirmed live. The `ChannelSink` and `NoOpSink` in `audit.go` are the v1 hooks
  for that wiring.

## Superseded decisions

None. This is the first audit-emission ADR; it extends the existing seam pattern (ADR-002 for the
Detector, ADR-005 for the MemoryStore) to the audit channel.
