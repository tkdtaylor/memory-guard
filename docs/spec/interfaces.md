# Interfaces

**Project:** memory-guard
**Last updated:** 2026-07-12 (task 017: real `AuditTrailSink` transport + `serve --audit-socket` wiring, ADR-014; task 016: `ScanScoped` + identity `scope`, ADR-013)

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
`identity` field is the **typed principal** `{ "spiffe_id": string, "trust_tier": string, "scope"?: string }` (ADR-004, ADR-013) —
parsed (`req["identity"]` as a map) and decoded through the `Principal` seam, then **enforced** on
`validate_read`: a writer's entry is returned only under a **matching attested** identity (see below).
The optional `scope` is meaningful on `validate_write` only: `scope == "shared"` from an **attested**
writer publishes the entry to the shared scope (readable under every identity); it is **ignored** from
an unattested writer (binds unbound) and **ignored** on `validate_read`.
`identity` is **pre-verified upstream** (agent-mesh owns SVID issuance + verification and emits
`trust_tier == "attested"` on success); the guard trusts the claim across the `0600` socket and adds no
in-guard SVID/X.509 verification (deferred behind the `Principal` seam).

| Op | Request | Response |
|----|---------|----------|
| `ping` | `{"op":"ping"}` | `{"ok":true}` |
| `validate_write` | `{"op":"validate_write","entry":…,"identity":{"spiffe_id":…,"trust_tier":…,"scope"?:"shared"}}` | clean: `{"allow":true,"stored_id":"mem-…","flags":[…]}` · poisoned: `{"allow":false,"stored_id":null,"flags":[…,"injection_suspected"]}` — **the raw value is never returned; a poisoned write never persists; the entry is bound to the writer's identity key** (the reserved shared marker iff attested **and** `scope=="shared"`, else the writer's `spiffe_id` / the unbound marker) |
| `validate_read` | `{"op":"validate_read","query":…,"identity":{"spiffe_id":…,"trust_tier":…}}` | `{"allow":true,"content_redacted":…,"flags":[…]}` — contents matching the query **AND** the reader's visible-key set, joined and **PII-redacted on the way out**. An attested reader sees its **exact** `spiffe_id`'s entries **plus shared-scope entries**; an unattested/absent reader sees **unbound** entries **plus shared-scope entries** (never an identity-bound entry, never the whole store). Scoping is a single store-side `ScanScoped` call (ADR-013) |
| `verify_delete` | `{"op":"verify_delete","id":…}` | `{"confirmed":true,"residue_detected":bool,"residue_summary"?:…,"deletion_hash":…}` — fresh post-delete presence check **plus** a residue scan of the remaining store; `residue_summary` present only when `residue_detected:true`; `deletion_hash` is a deterministic SHA-256 of the deletion op |
| *(other / malformed)* | any unparseable / unknown op | `{"error":{"code","message","retryable":false}}` (`bad_request` / `unknown_op`) |

- Socket permissions are `0600` (owner-only). There is **no** `SO_PEERCRED` peer-uid check in v0 (the
  socket is file-mode-restricted only) — unlike vault's secret-handling socket, this is a v0 scoping
  choice tracked in the spec.
- Error codes and the structured error shape are in [data-model.md](data-model.md).

---

## Outbound interfaces

memory-guard makes **no outbound network calls** in the default (disabled) configuration. When audit
emission is **enabled** (opt-in via `serve --audit-socket <path>` / `MEMGUARD_AUDIT_SOCKET`),
memory-guard emits one event per detection to the sibling **audit-trail** block over a Unix socket. The
real transport is `AuditTrailSink` (`audit_trail_sink.go`, ADR-014): per event, dial → write
`{"op":"emit","event":{ts, actor, action, target, decision?, refs[], context?}}` → read `{seq, hash}`
→ close. The internal `OCSFEvent` is translated to that **plain** wire shape at the sink boundary
(`mapToAuditTrailEvent`); the transport lives entirely in the sink file, never in `guard.go` or
`ipc.go`. Deletion events deliver `deletion_hash` as a `refs` entry (its first consumer). See
[B-009](behaviors.md#b-009), [ADR-007](../architecture/decisions/007-audit-ocsf-emission.md), and
[ADR-014](../architecture/decisions/014-audit-trail-wire-reconciliation.md).

Emission is **default-OFF** (opt-in), **best-effort** (fail-open — a down/slow/absent/erroring sink
never blocks the hot path or changes a verdict; wrapped in `AsyncSink` for non-blocking dispatch), and
**PII-safe** (no raw PII or content in any emitted event; every wire number is an int). The `AuditSink`
seam (`audit.go`) is the extension point; swapping the transport is a one-implementation change with
zero guard/IPC/contract impact.

The Presidio-backed `Detector` (v1, ADR-009, opt-in via `MEMGUARD_DETECTOR=presidio`) calls out to a
Python **sidecar** subprocess over stdlib JSON IPC — that call lives **behind the `Detector`
interface**, not as a contract-level outbound. The ONNX-in-process alternative is deferred behind the
same seam.

---

## Internal public surface

### Type: `MemoryGuard` — the guard core

```go
type MemoryGuard struct { /* mu sync.Mutex; det Detector; store map[string]entry */ }

func NewMemoryGuard(det Detector, store ...MemoryStore) *MemoryGuard             // det == nil → default RegexDetector; omitted store → default InMemoryStore
func (g *MemoryGuard) ValidateWrite(text string, identity map[string]any) map[string]any  // write-gate: DetectInjection → fail-closed on injection_suspected → RedactPII → store BOUND TO the writer's key (Principal.Subject(), or sharedScopeKey when attested + scope "shared") (ADR-004/ADR-013); returns {allow, stored_id, flags}
func (g *MemoryGuard) ValidateRead(query string, identity map[string]any) map[string]any   // store-side ScanScoped over the reader's visible keys {Subject()|unbound, sharedScopeKey} → RedactPII; returns {allow, content_redacted, flags} (ADR-013)
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

func NewPresidioDetector(cfg presidioConfig) *PresidioDetector  // v1 opt-in (ADR-009): Presidio Python SIDECAR; composite = native structured PII + Presidio NER; injection delegated to native UNCHANGED
func (d *PresidioDetector) RedactPII(text string) (string, []string)  // native structured redaction + Presidio NER overlay (PERSON/LOCATION/...); fail-closed to native on sidecar-down
func (d *PresidioDetector) DetectInjection(text string) []string      // delegates to native heuristic UNCHANGED (Presidio is a PII/NER engine, not an injection classifier)
func (d *PresidioDetector) Start() error                              // spawns + warms the sidecar (one-time model-load cold-start); fail returns err, RedactPII then runs native-only
func (d *PresidioDetector) Close() error                              // terminates the sidecar subprocess

func NewDetectorFromConfig(backend string) (Detector, error)   // config-driven selection: "regex" | "native" | "presidio" (MEMGUARD_DETECTOR); unknown name → fail-closed error
```

- **`NewDetectorFromConfig` is the single backend-selection point** (`detector_config.go`): it maps a
  generic backend NAME (`MEMGUARD_DETECTOR`) to a `Detector`. `main.go` names only the backend string +
  this factory — **no backend Go type** (`PresidioDetector`, etc.) appears in `main.go` / `guard.go` /
  `ipc.go` / `CONTRACT.md`, keeping the seam-isolation fitness gate (F-004) clean. An unknown name is a
  fail-closed construction error (exit `2`), not a silent fallback.
- **`PresidioDetector` is the opt-in third backend** (ADR-009): a **sidecar** (Python subprocess,
  `presidio/sidecar.py`) reached over stdlib JSON IPC — the Go binary stays pure-Go / stdlib-only
  (`go.mod` require-free). It **composes** the native structured recognizers (preserving every PII
  category + the injection heuristic) with Presidio's NER (PERSON / LOCATION / NRP / ... — the recall
  lift). It lifts **PII/NER** recall; **injection** recall is **unchanged** (orthogonal — delegated to
  native). `< 1 ms` is the native default's budget; the Presidio sidecar is **~ms/op** under a revised
  rich-backend budget (ADR-009). On a sidecar-unavailable path it **fails closed** to native structured
  redaction — PII still redacted, never raw — surfacing no Presidio-typed error past the seam.

### Type: `Principal` — the identity seam (ADR-004)

```go
type Principal interface {
    Subject() string     // normalized identity key (the SPIFFE ID); "" if none — the EXACT match key
    Attested() bool      // trust_tier == "attested"; isolation enforced ONLY when true
    SharedScope() bool   // scope == "shared"; HONORED only at write and only when Attested() (ADR-013)
}

type PreVerifiedPrincipal struct { /* spiffeID, trustTier, scope string */ }   // v1 default: TRUSTS the caller-supplied {spiffe_id, trust_tier, scope?}
func (p PreVerifiedPrincipal) Subject() string
func (p PreVerifiedPrincipal) Attested() bool
func (p PreVerifiedPrincipal) SharedScope() bool

// sharedScopeKey = "shared://" is the reserved boundIdentity marker for shared-scope entries.
// boundKeyFor maps any Subject() equal to it → unbound, so no spiffe_id can forge the shared binding.
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

### Type: `AuditSink` — the audit emission seam (ADR-007)

```go
type AuditSink interface {
    Emit(event OCSFEvent) error  // send the OCSF event; error is swallowed by the guard (fail-open)
}

type AuditConfig struct {
    Enabled bool      // default false (disabled); must be true for any emission
    Sink    AuditSink // nil with Enabled==true → fails closed to disabled (no emission)
}

func (g *MemoryGuard) WithAudit(cfg AuditConfig) *MemoryGuard  // builder: injects the sink; returns a new guard

// The REAL transport (task 017 / ADR-014): speaks the audit-trail plain-event wire contract.
type AuditTrailSink struct{ /* socketPath string; timeout time.Duration */ }
func NewAuditTrailSink(socketPath string, timeout time.Duration) *AuditTrailSink
func mapToAuditTrailEvent(e OCSFEvent) map[string]any  // pure OCSFEvent → {ts,actor,action,target,decision?,refs[],context?}
func buildAuditConfig(socketPath string) AuditConfig   // "" → disabled; else AsyncSink-wrapped AuditTrailSink
func resolveAuditSocket(flagVal, envVal string) string // --audit-socket wins over MEMGUARD_AUDIT_SOCKET

// Test implementations:
type NoOpSink struct{}        // zero-cost no-op (default when disabled)
type CollectingSink struct{}  // thread-safe in-memory capture for tests
type FailingSink struct{}     // always returns error (proves fail-open in tests)
type PanicSink struct{}       // always panics (proves recover() wrapper in tests)
type SlowSink struct{}        // blocks per Emit (proves AsyncSink keeps the hot path unstalled)
type ChannelSink struct{}     // non-blocking buffered channel for optional async delivery

// Non-blocking dispatch wrapper for slow real transports (ADR-007 §6):
func NewAsyncSink(inner AuditSink, n int) *AsyncSink  // wraps inner; Emit enqueues + returns; drain goroutine forwards
func (s *AsyncSink) Emit(event OCSFEvent) error        // non-blocking; drops on full buffer (fail-open)
func (s *AsyncSink) Close()                            // stops the drain goroutine (idempotent)
```

- The `AuditSink` is the **third pluggable seam** (alongside `Detector` and `MemoryStore`). The
  transport (Unix socket / HTTP / file) lives in the implementor; nothing transport-specific enters
  `guard.go`, `ipc.go`, or the contract.
- `(*MemoryGuard).WithAudit` is the **single injection point**. The fitness seam check
  (`TestFitnessSeam`) continues to pass after this change — `audit` is an interface field, not a
  transport token.
- A **slow/blocking** transport must be wrapped in `AsyncSink` (non-blocking dispatch — enqueue +
  background drain + drop-on-full) so the hot path never stalls (REQ-005 / ADR-007 §6). The
  synchronous in-process sinks (`CollectingSink`, `NoOpSink`) stay synchronous.
- Emission is always **fail-open** (via `emitSafe`): errors swallowed, panics recovered, nil = no-op.
- The OCSF event shape is defined in `audit.go` (`OCSFEvent` / `OCSFFinding`); see ADR-007 for the
  shape rationale and the documented assumption about the public OCSF schema.

---

## Extension points

Three extension points exist, all seams behind stable interfaces:

1. **`Detector` interface** (`detector.go`) — the detection backend (PII + injection). Two
   implementations ship: `RegexDetector` (v0 stand-in) and `NativeDetector` (Go-native in-process,
   ADR-002; the CLI/serve default). A Presidio-backed detector slots in additively behind this seam.
2. **`MemoryStore` interface** (`store.go`) — the backing store (`Put`/`Get`/`Delete`/`Scan`/`ScanScoped`/`All`/`AllByIndex`;
   `ScanScoped` is the identity-scoped read verb, ADR-013). Three adapters ship: `InMemoryStore`
   (the default single-map v0 backing), `TwoIndexStore` (primary + secondary-content-index, ADR-005),
   and the persistent `FileStore` (JSONL snapshot, opt-in `MEMGUARD_STORE=file`, ADR-012). A real
   MemoryStore (LangChain / vector store / SQLite) slots in behind this seam.
3. **`AuditSink` interface** (`audit.go`) — the audit emission transport. Ships with a no-op default,
   test fakes, and the real `AuditTrailSink` (`audit_trail_sink.go`, ADR-014) speaking the confirmed
   audit-trail Unix-socket emit contract, opt-in via `serve --audit-socket`. Any other transport
   (HTTP / file) slots in additively behind this seam.

There is no plugin registry; extension is by source modification behind each seam. A new implementation
of any seam requires zero changes to `guard.go`, `ipc.go`, `main.go`, or the wire contract.
</content>
