# memory-guard contract (tracer-validated)

These shapes are **tracer-validated**: memory-guard's own
tracer-bullet (roadmap T6, [ADR-008](architecture/decisions/008-contract-tracer-validation.md))
drives `validate_write → validate_read → verify_delete` over the live `serve` Unix socket against
the real `MemoryStore` seam, asserting each verb's response field-by-field on the JSON decoded off
the socket. The `validate_write` shape gained a `state` tri-state field and a new `review_quarantine`
verb was added in task 022 (ADR-019); both were re-validated over the live socket (the `state` field
type + enum-membership for all three outcomes, and `review_quarantine` field-by-field). The other
verbs' shapes validated **unchanged**. The detector dimension was validated against the v0
`NativeDetector`; a real-Presidio re-validation is a noted follow-up, and the shapes are
detector-agnostic behind the `Detector` seam.

- `validate_write(entry, identity, key?) -> { allow, stored_id, flags, state }`: write-gate with
  three outcomes (ADR-019). `state` is one of `"allow"` | `"quarantine"` | `"block"`, and
  `allow == (state != "block")` always holds (legacy-reader back-compat). `stored_id` is a minted
  `mem-…` id for both `allow` and `quarantine` (both persist an entry), and `null` only for `block`.
  A `block` is the fail-closed reject of suspected poisoning (`injection_suspected`) or a reserved-key
  violation (`protected_key_violation` / `immutable_mismatch`); nothing persists. A `quarantine` is a
  write that tripped the narrow, additive borderline signal (`borderline_suspected`, ADR-019) but not
  the injection gate: it is stored redacted with `quarantined:true`, excluded from every normal
  `validate_read`, and retrievable only via `review_quarantine`. Block wins when both the injection
  and borderline signals fire. `key` is an **optional** logical slot name for the named-key
  write-time policy (ADR-017); an operator-configured (`MEMGUARD_PROTECTED_KEYS` /
  `MEMGUARD_IMMUTABLE_KEYS`) violation adds the flag but allows the write (`state:"allow"`). The
  `key` is never persisted.
- `validate_read(query, identity) -> { allow, content_redacted, flags }`: return matching
  content with PII redacted. Entries with `quarantined:true` are **excluded** regardless of
  identity/scope match (ADR-019).
- `review_quarantine(id) -> { found, content_redacted, flags }`: the explicit, quarantine-only
  retrieval path (ADR-019). `found:false` for an unknown id **or** an id that exists but is not
  quarantined (indistinguishable, so it is never a generic id-lookup bypass of `validate_read`'s
  scoping). `content_redacted` is PII-redacted on the way out. Read-only: it never promotes/demotes
  or deletes the entry.
- `verify_delete(id) -> { confirmed, residue_detected, residue_summary?, deletion_hash }`: delete,
  prove absence, then scan the remaining store for surviving **residue** of the deleted content (the
  industry gap a bare `delete()` misses). `confirmed` keeps its meaning (the id is gone);
  `residue_detected` flags a verbatim/near-verbatim fragment surviving elsewhere (with a
  `residue_summary` when true); `deletion_hash` is a deterministic SHA-256 over the deletion op for
  audit-trail linkage. It scans every backing index unfiltered, so a quarantined entry deletes and
  residue-scans identically to any other. The residue scan is guard-side stdlib logic (ADR-003), not
  a `Detector` concern.

The `identity` map is a caller-supplied, guard-trusted claim (ADR-004). Beyond `spiffe_id` and
`trust_tier`, it may carry two **optional** keys, both meaningful on `validate_write` only and
neither changing the response shape above: `scope` (`"shared"` publish, ADR-013) and `source_class`
(write provenance, one of `external_tool` | `user_input` | `agent_authored` | `system`, anything
absent/unrecognized normalizing to `unknown`, ADR-015). `source_class` is provenance metadata, not
an access-control key: it never gates a read.

## Detector seam
PII + injection detection sits behind the `Detector` interface (detector.go), so Presidio
(v1, Python sidecar / ONNX) can replace the v0 RegexDetector without contract impact.

Transports: IPC `{"op":…}` over a Unix socket; CLI `memory-guard …`.
