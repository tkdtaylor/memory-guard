# ADR-015: Write-provenance `source_class` tagging (optional identity-map key)

**Status:** Accepted
**Date:** 2026-07-14
**Task:** [020 (Write-provenance / source-class tagging)](../../tasks/completed/020-write-provenance-source-class.md)
**Relates to:** ADR-004 (the `Principal` seam and the pre-verified, caller-supplied identity claim across the `0600` socket), ADR-013 (the optional-identity-map-key precedent set by `scope`, this ADR follows the identical carriage pattern for a new optional key), ADR-007 (`OCSFFinding` and the write-triggered event builders this ADR extends), ADR-008 (the tracer-validated contract whose response shapes this ADR leaves byte-identical).

## Context

`entry` (`guard.go`) records `content`, `boundIdentity`, and `flags`. It has no notion of a write's origin. The primary ASI06 injection vector is external-tool output landing in memory as if it were trusted first-party content: today the guard cannot tell an `agent_authored` write from an `external_tool` write once both are stored. Two consumers want that distinction:

1. A future behavioral detector (roadmap 018/019) that treats `agent_authored` self-reinforcement differently from untrusted `external_tool` writes.
2. The audit trail (ADR-007), which today records *what* the guard found in a write but not *where the write came from*.

This task tags and threads provenance. It implements no policy that acts on the tag; trust-weighted rejection and self-reinforcement detection are the deferred behavioral-detector work. This task is a soft prerequisite (an enabler) for that work, not a dependency on it.

## Decision

**Carry provenance as an optional `source_class` key on the existing `identity` map, decode it through a standalone `sourceClassFromMap` function (not a `Principal` accessor), thread the single decoded value to both the stored `entry` and the emitted audit event, and default any absent or unrecognized value to the conservative sentinel `sourceClassUnknown = "unknown"`.**

### 1. Envelope carriage: an optional key on `identity`, not a new contract argument

`source_class` rides on the same free-form `identity` map that already carries `spiffe_id`, `trust_tier`, and `scope`:

```jsonc
"identity": { "spiffe_id": "…", "trust_tier": "attested", "source_class": "external_tool" }
```

The tracer-validated `validate_write(entry, identity) -> {allow, stored_id, flags}` shape is **unchanged**: no new top-level argument, no new response field. `ipc.go` already decodes `identity` generically as `req["identity"].(map[string]any)` and passes it straight through, no field-by-field allowlist, so the new key costs nothing on the wire. `contract_tracer_test.go` asserts the *response* shape field-by-field over the live socket and passes unmodified, demonstrating (not merely asserting) that the shape claim holds. This is the exact precedent ADR-013 set when it added `scope` to the same map.

**Rejected alternative: a new top-level `validate_write(entry, identity, source_class)` argument.** Rejected because (a) it is a breaking shape change requiring tracer re-validation and touching `ipc.go`'s request parsing, ADR-008's contract, and every caller construction site; (b) `identity` is already the seam this class of caller-supplied, guard-trusted metadata rides on (ADR-004's `trust_tier`, ADR-013's `scope`), so a second parallel channel for the same class of metadata is inconsistent for no benefit.

### 2. Standalone decode, not a fourth `Principal` accessor

`source_class` is decoded by a standalone package-level function beside `principalFromMap`:

```go
func sourceClassFromMap(identity map[string]any) string
```

It is deliberately **not** exposed through `Principal`'s three accessors (`Subject`/`Attested`/`SharedScope`). Those are the *access-control* seam: `spiffe_id`/`trust_tier`/`scope` gate read visibility and are matched against a reader's visible-key set. `source_class` is provenance, not identity: it never gates `ValidateRead` visibility and is never matched against any key set. Keeping it out of `Principal` keeps the identity seam single-purpose (who) and the provenance seam single-purpose (where-from), mirroring why `Detector` and `MemoryStore` are separate seams rather than one god-interface. This differs from ADR-013's choice to add `SharedScope()` to `Principal`: `scope` *is* an access-control input (it selects the bound key), so it belongs on the identity seam; `source_class` is not, so it does not.

### 3. `unknown` default and the fail-closed policy for future consumers

A missing key, an empty string, a non-string JSON value, or any value outside the four-item enum (`external_tool | user_input | agent_authored | system`) normalizes to the sentinel `sourceClassUnknown = "unknown"`. It is never silently treated as `agent_authored` (the most-trusted class) or dropped.

`unknown` is the documented conservative default. Any future trust-weighting policy (018/019) **MUST** treat `unknown` at least as cautiously as `external_tool` (untrusted-until-shown-otherwise), the same fail-closed posture the write-gate already uses for suspected injection. Entries written before this task carry the Go zero value `""` for the field; consumers must treat `""` the same as `unknown`. No backfill migration is performed. This ADR states and documents the policy; it does not implement the weighting.

### 4. Single decode, threaded to both consumers

`ValidateWrite` calls `sourceClassFromMap(identity)` exactly once, at the same read of `identity` that produces `boundKeyFor(principalFromMap(identity))`. That single value is threaded to:

- **`entry.sourceClass`** (set on the accepted-write `Put`), the field a future behavioral detector keys on.
- **The audit event**: `OCSFFinding` gains a `SourceClass string` (`json:"source_class"`) field; `BuildPIIRedactionEvent` and `BuildInjectionRejectedEvent` gain a `sourceClass` parameter threaded from the call-site value, never re-derived from the stored entry. An injection-rejected write does not persist but still records provenance on its event. `BuildDeletionEvent` is unchanged: deletion has no writer-provenance concept, so its events carry `SourceClass == ""`.

One decode feeding both sinks means the stored entry and the emitted event provably agree on where a write came from; two independent reads could silently drift.

## Consequences

- The three tracer-validated response shapes are unchanged; `source_class` never enters any `validate_*` response. `validate_read` and `verify_delete` are untouched by the key.
- A write's provenance is now distinguishable value-for-value in both the stored entry and its audit event, for the PII-redaction and injection-rejected flows.
- The `Detector` seam is untouched: provenance is guard-side orchestration, not a detection concern.
- The write-gate's fail-closed posture on `injection_suspected` is unchanged; source-class threading through the rejection event is additive detail, not a policy change.
- Substrate constraints hold: stdlib-only (`go.mod` require-free), no detector/store/transport specifics in the new code, IPC error shape untouched.
- **Not in scope, deferred:** any policy acting on `source_class` (trust-weighted rejection, self-reinforcement detection, differential redaction by origin) is the behavioral-detector work (roadmap 018/019); exposing `source_class` on `validate_read`; cryptographic verification of the caller-supplied claim (like `trust_tier`, it is a guard-trusted claim across the socket trust boundary); backfilling provenance onto pre-existing entries.
