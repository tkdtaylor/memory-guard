# Data Model

**Project:** memory-guard
**Last updated:** 2026-06-19 (task 003)

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

  This is the boundary that isolates the detection backend from the rest of the block. No
  backend-specific type crosses it — only `string` in, `string` + `[]string` out. Two
  implementations ship: `RegexDetector` (the v0 stand-in / parity baseline) and `NativeDetector`
  (the v1 production backend chosen by the memory-guard tracer — Go-native, in-process, zero new
  dependencies; ADR-002). A Presidio-backed detector (sidecar / ONNX) is deferred but still replaces
  either **behind this interface** with no guard/IPC/contract change (ADR-001 §3, ADR-002).

- **`RegexDetector`** (`detector.go`): the v0/v1 stand-in, broadened in task 004. `pii []labeledPattern`
  (label + compiled regex) and `injection []*regexp.Regexp`.

  Recognizer table (v0 = initial set; v1 = added in task 004).  Corpus recall and precision numbers
  are from the `TestCorpusRecallPrecision` harness in `detector_corpus_test.go`
  (run `go test -v -run TestCorpusSummary` to reproduce).

  | Ver | Category | Label | Pattern intent | Recall | Precision |
  |-----|----------|-------|---------------|--------|-----------|
  | v0 | PII | `EMAIL` | `[\w.+-]+@[\w-]+\.[\w.-]+` — user@host.tld | 1.00 (2/2) | 1.00 |
  | v0 | PII | `US_SSN` | `\b\d{3}-\d{2}-\d{4}\b` — NNN-NN-NNNN with hyphens | 1.00 (2/2) | 1.00 |
  | v0 | PII | `CREDIT_CARD` | `\b(?:\d[ -]?){13,16}\b` — 13–16 digit run (spaces/hyphens OK) | 1.00 (2/2) | 1.00 |
  | v0+v1 | PII | `API_KEY` | `\b(?:sk-ant\|sk\|AKIA\|ghp\|xox[baprs]\|hf_\|npm_\|pat_\|xp_)[-_A-Za-z0-9]{8,}` — common credential prefixes (v0: sk/AKIA/ghp/xox; v1 adds sk-ant/hf_/npm_/pat_/xp_) | 1.00 (8/8) | 1.00 |
  | v1 | PII | `PHONE` | `\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b` — US phone with separators | 1.00 (4/4) | 1.00 |
  | v1 | PII | `IBAN` | `\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b` — 2-letter country + 2-digit check + ≥4 alphanums (≥8 total) | 1.00 (3/3) | 1.00 |
  | v1 | PII | `IP_ADDRESS` | Strict IPv4 (4 octets, 0–255 each) or IPv6 (full/compressed) | 1.00 (7/7) | 1.00 |
  | v1 | PII | `DOB` | MM/DD/YYYY, YYYY-MM-DD (ISO 8601), or DD Mon YYYY — 19xx/20xx years only | 1.00 (6/6) | 1.00 |
  | v1 | PII | `CREDENTIAL` | `\b[0-9a-fA-F]{32,}\b` — bare hex strings ≥32 chars (raw secrets/tokens; UUIDs excluded because their hyphens break the run) | 1.00 (2/2) | 1.00 |
  | v0 | Injection | — | `(?i)ignore … instructions`, `(?i)disregard … instructions`, `(?i)system prompt`, `(?i)</?(?:system\|instructions)>` | — | — |

  **Overall corpus precision: 1.00 (0 FP / 9 hard negatives).** Hard negatives in the corpus:
  9-digit order number (not SSN), `v1.2.3` 3-part semver (not IP — requires 4 octets), UUID with
  hyphens (not CREDENTIAL — hyphens break continuous hex runs), `#1a2b3c` short hex color (not
  CREDENTIAL — under 32 chars), `867530` bare 6-digit string (not PHONE — requires separators),
  two benign sentences.

  `RedactPII` replaces each matching category in place and appends a `pii:<LABEL>` flag per category
  found. `DetectInjection` returns `["injection_suspected"]` on the first matching pattern, else `nil`.

- **`NativeDetector`** (`detector.go`): the v1 production backend (ADR-002) — Go-native, in-process,
  zero new dependencies. It reaches parity with `RegexDetector` on the v0 categories/patterns by
  composing the same recognizers internally (`base *RegexDetector`), and is the CLI / `serve` default
  (`NewMemoryGuard(NewNativeDetector())` in `main.go`). It is a distinct, swappable `Detector`;
  broadening recall (task 004) is detector-internal behind `RedactPII`, with no guard/IPC/contract
  impact. Measured detection cost ~5.6 µs per `validate_*` op (budget `< 1 ms`).

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
{ "op":"verify_delete", "id":"mem-1a2b3c" }
```

→ no surviving residue:

```json
{ "confirmed": true, "residue_detected": false,
  "deletion_hash": "64daabe2…bedf49" }
```

→ a fragment of the deleted content survives elsewhere:

```json
{ "confirmed": true, "residue_detected": true,
  "residue_summary": "normalized residue of deleted content survives in entry mem-…: \"5000\"",
  "deletion_hash": "64daabe2…bedf49" }
```

- `confirmed` is computed from a fresh presence check **after** the delete (post-deletion
  verification), not assumed from the `delete()` call. Deleting an unknown/absent id still returns
  `{confirmed:true}` (with `residue_detected:false`, no scan).
- `residue_detected` is the result of a guard-side scan (ADR-003) of the **remaining** store for a
  verbatim or near-verbatim fragment of the just-deleted content (a tiered normalized substring /
  contiguous-phrase / token-overlap match, stdlib-only — **not** a `Detector` concern). Because the
  scan runs over the survivors (after the target is removed), a deleted entry can never flag itself.
- `residue_summary` (string) is present **only** when `residue_detected:true`; it names the match
  class (`verbatim` / `normalized` / `phrase` / `token-overlap N%`) and the surviving entry id +
  fragment. Callers that ignored the new fields are unaffected (additive).
- `deletion_hash` is a deterministic **SHA-256** hex over the canonical deletion op (`id` + the
  deleted content), for later audit-trail (RFC-6962-style) chaining. Same logical deletion → same
  hash; different deleted content → different hash.

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
- **`residue_detected` reflects a scan of the survivors, never of the deleted entry itself.** The scan
  runs over the store *after* the target id is removed, so a deleted entry cannot flag itself (no
  self-residue false positive). The residue scan is guard-side stdlib logic; no detector-backend type
  participates.
- **`deletion_hash` is deterministic.** It is a pure function (SHA-256) of the deletion op (`id` +
  deleted content) — reproducible across runs and processes, with no randomness.
- **No detector-backend-specific type crosses the wire** — the contract is plain JSON
  (`allow`/`stored_id`/`content_redacted`/`flags`/`confirmed`), so a future detection backend
  (Presidio / ONNX / NER) slots in behind the `Detector` interface unchanged.
</content>
