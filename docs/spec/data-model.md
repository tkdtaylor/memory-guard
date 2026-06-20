# Data Model

**Project:** memory-guard
**Last updated:** 2026-06-19

What data exists, how it's structured, and the wire formats crossing the process boundary. The store
is **in-memory only** in v0 — a Go `map` that holds each entry's **redacted** content (PII already
stripped); the raw PII is never stored. There is no persistence: a restart loses the store.

Not here: operations ([behaviors.md](behaviors.md)), how data is accessed
([interfaces.md](interfaces.md)), tunables ([configuration.md](configuration.md)).

---

## Persistent state

**None.** memory-guard holds no database and no files beyond the transient Unix socket it binds. The
store is in-memory and lost on restart. (A real MemoryStore backend — LangChain / LlamaIndex / SQLite /
vector store — sits behind the `validate_*` verbs in v1; v0 is the in-memory stand-in.)

---

## In-memory state

### State: `MemoryGuard.store` — the entry store

- **Shape:** `map[string]entry` keyed by the opaque `stored_id` (a `"mem-"+randHex(6)` string).
  `entry { content string; identity map[string]any; flags []string }` (`guard.go`). `content` is the
  **redacted** content (PII already replaced by `<LABEL>` placeholders by `RedactPII` at write time —
  the raw value is never stored). `flags` is the PII/injection metadata recorded at write.
- **Owner:** the `MemoryGuard` value (`guard.go`), shared by the IPC server across connections.
- **Lifetime:** process lifetime; populated by `ValidateWrite` (clean writes only — a poisoned write
  stores nothing), entries removed by `VerifyDelete`. Nothing persists across a restart.
- **Concurrency rules:** the whole store is guarded by `MemoryGuard.mu` (`sync.Mutex`); each operation
  locks it for the duration of its store access.
- **Bounds:** bounded by the number of clean writes; no eviction or TTL.

### Type: `entry` (a stored memory record)

```go
type entry struct {
    content  string         // the REDACTED content (PII already <LABEL>-replaced); never the raw value
    identity map[string]any // the writer's identity, as supplied to validate_write (not yet enforced)
    flags    []string       // PII/injection metadata recorded at write (e.g. "pii:EMAIL")
}
```

- **Held in:** `MemoryGuard.store` (`guard.go`). It is the only representation of a memory record the
  store keeps. The raw (pre-redaction) value is **never** present at rest.

### Seam: `Detector` (the detection backend) and `RegexDetector` (the v0 implementation)

- **`Detector`** (`detector.go`): the detection seam.

  ```go
  type Detector interface {
      RedactPII(text string) (redacted string, flags []string)  // PII → "<LABEL>"; flags like "pii:EMAIL"
      DetectInjection(text string) []string                      // ["injection_suspected"] or nil
  }
  ```

  This is the boundary that isolates the detection backend (Presidio) from the rest of the block. No
  backend-specific type crosses it — only `string` in, `string` + `[]string` out. The default is
  `RegexDetector`; a Presidio-backed detector (sidecar / ONNX) or a Go-native NER model replaces it
  **behind this interface** with no guard/IPC/contract change (ADR-001 §3).

- **`RegexDetector`** (`detector.go`): the v0 stand-in. `pii []labeledPattern` (label + compiled
  regex) and `injection []*regexp.Regexp`.

  | Category | Label | v0 recognizer (regex, high-signal) |
  |----------|-------|-------------------------------------|
  | PII | `EMAIL` | `[\w.+-]+@[\w-]+\.[\w.-]+` |
  | PII | `US_SSN` | `\b\d{3}-\d{2}-\d{4}\b` |
  | PII | `CREDIT_CARD` | `\b(?:\d[ -]?){13,16}\b` |
  | PII | `API_KEY` | `\b(?:sk\|AKIA\|ghp\|xox[baprs])[-_A-Za-z0-9]{8,}` |
  | Injection | — | `(?i)ignore … instructions`, `(?i)disregard … instructions`, `(?i)system prompt`, `(?i)</?(?:system\|instructions)>` |

  `RedactPII` replaces each matching category in place and appends a `pii:<LABEL>` flag per category
  found. `DetectInjection` returns `["injection_suspected"]` on the first matching pattern, else `nil`.

---

## Wire / interchange formats

All IPC is **newline-delimited JSON over a Unix socket** — one request object per connection, one
response line back.

### Format: `validate_write` request / response

```json
{ "op":"validate_write", "entry":"contact alice@example.com", "identity":{ "agent":"agent-1" } }
```

→ clean write:

```json
{ "allow": true, "stored_id": "mem-1a2b3c", "flags": ["pii:EMAIL"] }
```

→ write-gate rejection (suspected poisoning):

```json
{ "allow": false, "stored_id": null, "flags": ["injection_suspected"] }
```

The stored content is the **redacted** form; the response carries the opaque `stored_id`, **never** the
raw value. `flags` is `[]` (never `null`) on a clean write with no PII.

### Format: `validate_read` request / response

```json
{ "op":"validate_read", "query":"contact", "identity":{ … } }
```

→ `{ "allow": true, "content_redacted": "contact <EMAIL>", "flags": ["pii:EMAIL"] }` — the joined
matching contents, PII-redacted again on the way out. A query matching nothing → empty
`content_redacted` and `flags: []`. v0 always `allow:true`.

### Format: `verify_delete` request / response

```json
{ "op":"verify_delete", "id":"mem-1a2b3c" }   →   { "confirmed": true }
```

`confirmed` is computed from a fresh presence check **after** the delete (post-deletion verification),
not assumed from the `delete()` call. Deleting an unknown/absent id still returns `{confirmed:true}`.

### Format: `ping` request

```json
{ "op":"ping" }   →   { "ok": true }
```

### Format: error shape

```
{ "error": { "code": string, "message": string, "retryable": bool } }
```

All current errors are `retryable:false`. Codes:

| `code` | `retryable` | Trigger |
|--------|-------------|---------|
| `bad_request` | `false` | unparseable request JSON (the JSON-decode error message is echoed) |
| `unknown_op` | `false` | an `op` other than `validate_write`/`validate_read`/`verify_delete`/`ping` |

---

## Data invariants

- **The raw value is never stored.** `MemoryGuard.store` holds only the **redacted** `content`; the
  raw (pre-redaction) value exists transiently in `ValidateWrite` before redaction and is never
  persisted.
- **No poisoned content is stored.** A write flagged `injection_suspected` stores nothing — the store
  contains only content that passed the write-gate.
- **The agent never receives the raw stored value.** A successful `validate_write` returns the opaque
  `stored_id` (`mem-<hex>`, 6 random bytes from `crypto/rand`, hex-encoded); the content is reachable
  only via `validate_read`, redacted.
- **PII appears in no response raw.** Both `validate_write` (before store) and `validate_read` (on the
  way out) redact via the `Detector`; the response carries `<LABEL>` placeholders, never the raw PII.
- **`flags` is never `null` on success.** `flagsOrEmpty` returns `[]` for an empty flag set, so the
  wire shape is a JSON array.
- **`confirmed` reflects a fresh post-delete check.** `verify_delete` re-reads the store after deleting
  and reports absence from that read — not from the `delete()` call's return.
- **No detector-backend-specific type crosses the wire** — the contract is plain JSON
  (`allow`/`stored_id`/`content_redacted`/`flags`/`confirmed`), so a future detection backend
  (Presidio / ONNX / NER) slots in behind the `Detector` interface unchanged.
</content>
