# memory-guard contract (v0 shape — not yet tracer-validated)

Mirrors `interface-contracts.md §2`. memory-guard was out of
the first tracer-bullet's scope (stateless slice); it gets its own tracer when memory is in
play, which may refine these shapes.

- `validate_write(entry, identity) -> { allow, stored_id, flags }` — write-gate: reject
  suspected poisoning (fail-closed), redact PII, store, return flags.
- `validate_read(query, identity) -> { allow, content_redacted, flags }` — return matching
  content with PII redacted.
- `verify_delete(id) -> { confirmed, residue_detected, residue_summary?, deletion_hash }` — delete,
  prove absence, then scan the remaining store for surviving **residue** of the deleted content (the
  industry gap a bare `delete()` misses). `confirmed` keeps its meaning (the id is gone);
  `residue_detected` flags a verbatim/near-verbatim fragment surviving elsewhere (with a
  `residue_summary` when true); `deletion_hash` is a deterministic SHA-256 over the deletion op for
  audit-trail linkage. The residue scan is guard-side stdlib logic (ADR-003), not a `Detector` concern.

## Detector seam
PII + injection detection sits behind the `Detector` interface (detector.go), so Presidio
(v1, Python sidecar / ONNX) can replace the v0 RegexDetector without contract impact.

Transports: IPC `{"op":…}` over a Unix socket; CLI `memory-guard …`.
