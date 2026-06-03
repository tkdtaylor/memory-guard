# memory-guard contract (v0 shape — not yet tracer-validated)

Mirrors `interface-contracts.md §2`. memory-guard was out of
the first tracer-bullet's scope (stateless slice); it gets its own tracer when memory is in
play, which may refine these shapes.

- `validate_write(entry, identity) -> { allow, stored_id, flags }` — write-gate: reject
  suspected poisoning (fail-closed), redact PII, store, return flags.
- `validate_read(query, identity) -> { allow, content_redacted, flags }` — return matching
  content with PII redacted.
- `verify_delete(id) -> { confirmed }` — delete and prove absence (the industry gap).

## Detector seam
PII + injection detection sits behind the `Detector` interface (detector.go), so Presidio
(v1, Python sidecar / ONNX) can replace the v0 RegexDetector without contract impact.

Transports: IPC `{"op":…}` over a Unix socket; CLI `memory-guard …`.
