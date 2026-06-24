# Interfaces

**Project:** memory-guard
**Last updated:** 2026-06-24 (task 009 — typed identity + identity-scoped reads)

The system's contact surface — what calls in, what it calls out to, and the internal public boundary.
Each is a stable contract; changes here are breaking changes.

Not here: what they *do* ([behaviors.md](behaviors.md)), what data flows
([data-model.md](data-model.md)), how they're configured ([configuration.md](configuration.md)).

---

## Inbound interfaces

### CLI

```
memory-guard <serve|write|read> [args]

Subcommands:
  serve   run the newline-delimited-JSON-over-Unix-socket IPC daemon
  write   run validate_write on the argument in-process; print the WriteResult JSON
  read    seed the store with the argument, then validate_read it; print the ReadResult JSON
```

| Subcommand / flag | Type | Default | Effect |
|-------------------|------|---------|--------|
| `serve` | subcommand | — | Start the IPC daemon (long-running) |
| `serve --socket` | string (path) | — (required) | Unix socket path to bind; a stale socket is removed first; bound `0600`. Missing → `serve: --socket is required`, exit `2` |
| `write` | subcommand | — | One-shot in-process `ValidateWrite(arg, nil)`; stdout only |
| `read` | subcommand | — | One-shot in-process: seed with `arg`, then `ValidateRead(arg, nil)`; stdout only |

**Exit codes:**
- `0` — normal exit
- `2` — usage error (no subcommand, an unknown subcommand, or `serve` without `--socket`)
- `1` — a `serve` bind/serve error (`error: …` on stderr)

### IPC protocol (Unix socket)

The agent surface. Newline-delimited JSON over the Unix socket bound by `serve --socket`. One request
object per connection (read up to the first `\n`); the connection closes after the response. The
`identity` field is the **typed principal** `{ "spiffe_id": string, "trust_tier": string }` (ADR-004) —
parsed (`req["identity"]` as a map) and decoded through the `Principal` seam, then **enforced** on
`validate_read`: a writer's entry is returned only under a **matching attested** identity (see below).
`identity` is **pre-verified upstream** (agent-mesh owns SVID issuance + verification and emits
`trust_tier == "attested"` on success); the guard trusts the claim across the `0600` socket and adds no
in-guard SVID/X.509 verification (deferred behind the `Principal` seam).

| Op | Request | Response |
|----|---------|----------|
| `ping` | `{"op":"ping"}` | `{"ok":true}` |
| `validate_write` | `{"op":"validate_write","entry":…,"identity":{"spiffe_id":…,"trust_tier":…}}` | clean: `{"allow":true,"stored_id":"mem-…","flags":[…]}` · poisoned: `{"allow":false,"stored_id":null,"flags":[…,"injection_suspected"]}` — **the raw value is never returned; a poisoned write never persists; the entry is bound to the writer's identity key** |
| `validate_read` | `{"op":"validate_read","query":…,"identity":{"spiffe_id":…,"trust_tier":…}}` | `{"allow":true,"content_redacted":…,"flags":[…]}` — contents matching the query **AND** the reader's identity, joined and **PII-redacted on the way out**. An attested reader sees only its **exact** `spiffe_id`'s entries; an unattested/absent reader sees only **unbound** entries (never an identity-bound entry, never the whole store) |
| `verify_delete` | `{"op":"verify_delete","id":…}` | `{"confirmed":true,"residue_detected":bool,"residue_summary"?:…,"deletion_hash":…}` — fresh post-delete presence check **plus** a residue scan of the remaining store; `residue_summary` present only when `residue_detected:true`; `deletion_hash` is a deterministic SHA-256 of the deletion op |
| *(other / malformed)* | any unparseable / unknown op | `{"error":{"code","message","retryable":false}}` (`bad_request` / `unknown_op`) |

- Socket permissions are `0600` (owner-only). There is **no** `SO_PEERCRED` peer-uid check in v0 (the
  socket is file-mode-restricted only) — unlike vault's secret-handling socket, this is a v0 scoping
  choice tracked in the spec.
- Error codes and the structured error shape are in [data-model.md](data-model.md).

---

## Outbound interfaces

memory-guard makes **no outbound network calls** in v0. Detections are returned to the caller as
`flags` in the response; emitting them as OCSF events to `audit-trail` is a **v1** integration (not
wired). A Presidio-backed `Detector` (v1) would call out to a sidecar/subprocess or load an ONNX model
— but that call would live **behind the `Detector` interface**, not as a contract-level outbound.

---

## Internal public surface

### Type: `MemoryGuard` — the guard core

```go
type MemoryGuard struct { /* mu sync.Mutex; det Detector; store map[string]entry */ }

func NewMemoryGuard(det Detector, store ...MemoryStore) *MemoryGuard             // det == nil → default RegexDetector; omitted store → default InMemoryStore
func (g *MemoryGuard) ValidateWrite(text string, identity map[string]any) map[string]any  // write-gate: DetectInjection → fail-closed on injection_suspected → RedactPII → store BOUND TO the writer's Principal.Subject() (ADR-004); returns {allow, stored_id, flags}
func (g *MemoryGuard) ValidateRead(query string, identity map[string]any) map[string]any   // substring scan → identity-scoped EXACT filter (attested Subject(), else unbound-only) → RedactPII; returns {allow, content_redacted, flags}
func (g *MemoryGuard) VerifyDelete(id string) map[string]any                                // delete → re-check absence → scan survivors across EVERY backing index/copy for residue; returns {confirmed, residue_detected, residue_summary?, deletion_hash}
```

- **The store backend seam is the `Detector` plus the in-memory `store`** (`guard.go`). The detection
  backend swaps behind the `Detector` interface; a real MemoryStore would swap behind the `store` /
  the `validate_*` verbs. Neither changes the method signatures or the wire contract.
- **`ValidateWrite` is the write-gate** — it runs `DetectInjection` before storing and fails closed
  (`allow:false`, `stored_id:null`, no store mutation) on `injection_suspected`; otherwise it redacts
  PII, mints an opaque `stored_id`, and stores the redacted content.
- **`VerifyDelete` proves absence and scans for residue across every index/copy** — it deletes,
  re-reads the store and reports `confirmed` from that fresh check, then scans the remaining entries in
  **every** backing index/copy (`MemoryStore.AllByIndex()`) for a surviving fragment of the deleted
  content (`residue_detected` + `residue_summary`, the latter naming the index the residue survives
  in), returning a deterministic, index-layout-independent `deletion_hash` for audit linkage. The
  residue scan is guard-side stdlib logic (`residue.go`, ADR-003/ADR-006), not a `Detector` concern —
  no detector-backend type appears in it.
- **Stability:** the argument and return shapes are the contract. Changing them is an ADR-level
  decision. No detector-backend-specific type appears in the signatures — the boundary stays plain
  Go maps / JSON.

### Type: `Detector` — the detection seam (the extension point)

```go
type Detector interface {
    RedactPII(text string) (redacted string, flags []string)  // PII → "<LABEL>" placeholders + "pii:<LABEL>" flags
    DetectInjection(text string) []string                      // ["injection_suspected"] or nil
}

func NewRegexDetector() *RegexDetector                          // the v0 pure-Go Presidio stand-in / parity baseline
func (d *RegexDetector) RedactPII(text string) (string, []string)
func (d *RegexDetector) DetectInjection(text string) []string

func NewNativeDetector() *NativeDetector                        // v1 production backend (ADR-002): Go-native, in-process, zero new deps; CLI/serve default
func (d *NativeDetector) RedactPII(text string) (string, []string)
func (d *NativeDetector) DetectInjection(text string) []string
```

### Type: `Principal` — the identity seam (ADR-004)

```go
type Principal interface {
    Subject() string   // normalized identity key (the SPIFFE ID); "" if none — the EXACT match key
    Attested() bool    // trust_tier == "attested"; isolation enforced ONLY when true
}

type PreVerifiedPrincipal struct { /* spiffeID, trustTier string */ }   // v1 default: TRUSTS the caller-supplied {spiffe_id, trust_tier}
func (p PreVerifiedPrincipal) Subject() string
func (p PreVerifiedPrincipal) Attested() bool
```

- **The identity seam** (`principal.go`) isolates *how identity is obtained/verified* from *how it is
  bound at write and matched at read*. The typed wire shape `{spiffe_id, trust_tier}` is decoded into a
  `Principal` (`principalFromMap`) at the IPC boundary; the guard sees only `Subject()` / `Attested()` —
  no SPIFFE/X.509/Ed25519 detail crosses the seam into `guard.go` or `ipc.go`.
- **`PreVerifiedPrincipal` is the v1 default** (ADR-004 option 1): verification stays upstream
  (agent-mesh); the guard trusts the pre-verified claim across the `0600` socket. A zero-trust
  `SvidVerifyingPrincipal` (parse + verify an SVID + bundle in-process) is **deferred** behind this same
  seam — additive, no guard change. Matching is **exact** on the normalized `Subject()`; binding and
  matching go through one derivation so the key bound at write is exactly the key matched at read.

---

## Extension points

The single extension point is the **`Detector` interface** (`detector.go`). A new detection backend is
adopted by implementing `Detector` and passing it to `NewMemoryGuard`, **never** by changing the guard,
the IPC, or the wire contract. Two implementations ship: `RegexDetector` (v0 stand-in / parity baseline)
and `NativeDetector` (the v1 production backend — Go-native, in-process, zero new dependencies; the
CLI / `serve` default). The backend-choice decision (deployment shape + hot-path latency budget) was
settled by the memory-guard tracer in **ADR-002** (in-process, ~5.6 µs detection cost per `validate_*`
op); a Presidio-backed detector (sidecar / ONNX) is deferred but still slots in additively behind this
same seam. There is no plugin registry in v0; extension is by source modification behind the seam. The
in-memory `store` is the secondary (v1) seam where a real MemoryStore backend slots in behind the
`validate_*` verbs.
</content>
