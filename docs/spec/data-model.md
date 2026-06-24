# Data Model

**Project:** memory-guard
**Last updated:** 2026-06-24 (task 009 — entry bound-identity key + typed identity)

What data exists, how it's structured, and the wire formats crossing the process boundary. The store
sits behind the **`MemoryStore` seam** (`store.go`, ADR-005) — the guard talks to it only through the
verbs `Put` / `Get` / `Delete` / `Scan` / `All`, never a raw map. Two stdlib-only backings ship: the
default `InMemoryStore` (a single map) and `TwoIndexStore` (a primary map plus a secondary
content-keyed index). Every backing holds each entry's **redacted** content (PII already stripped); the
raw PII is never stored. There is no persistence: a restart loses the store.

Not here: operations ([behaviors.md](behaviors.md)), how data is accessed
([interfaces.md](interfaces.md)), tunables ([configuration.md](configuration.md)).

---

## Persistent state

**None.** memory-guard holds no database and no files beyond the transient Unix socket it binds. Both
shipped `MemoryStore` backings (`InMemoryStore`, `TwoIndexStore`) are in-memory and lost on restart. A
persistent or third-party backend — LangChain / LlamaIndex / SQLite / vector store — slots in behind
the **unchanged `MemoryStore` seam** (`store.go`, ADR-005) with no guard/IPC/contract change; that is
deferred, not foreclosed.

---

## In-memory state

### State: `MemoryGuard.store` — the entry store (behind the `MemoryStore` seam)

- **Shape:** a `MemoryStore` (interface, `store.go`), **not** a raw map. Entries are keyed by the
  opaque `stored_id` (a `"mem-"+randHex(6)` string). `entry { content string; boundIdentity string;
  flags []string }` (`guard.go`). `content` is the **redacted** content (PII already replaced by
  `<LABEL>` placeholders by `RedactPII` at write time — the raw value is never stored). `boundIdentity`
  is the **normalized identity key** bound at write (the writer's `Principal.Subject()` when attested,
  else the unbound marker) — the key `validate_read` matches **exactly** against (ADR-004). `flags` is
  the PII/injection metadata recorded at write.
- **Owner:** the `MemoryGuard` value (`guard.go`), shared by the IPC server across connections. The
  guard reaches the store **only** through the seam verbs — `Put` (clean write), `Scan` (read), `Get`
  (the post-delete absence proof), `Delete`, and `All` (the residue-scan survivors).
- **Backing:** the default `InMemoryStore` (a single `map[string]entry`) when no store is supplied;
  `TwoIndexStore` (a primary `id → entry` map plus a secondary `content → ids` index) when wired
  explicitly. Both are stdlib-only (ADR-005).
- **Lifetime:** process lifetime; populated by `ValidateWrite` (clean writes only — a poisoned write
  calls **no** `Put` and stores nothing), entries removed by `VerifyDelete` (which `Delete`s from
  **every** backing index). Nothing persists across a restart.
- **Concurrency rules:** the whole store is guarded by `MemoryGuard.mu` (`sync.Mutex`); each operation
  locks it for the duration of its store access. A multi-index backing keeps its indexes consistent
  across the verbs within that lock.
- **Bounds:** bounded by the number of clean writes; no eviction or TTL.

### Type: `entry` (a stored memory record)

```go
type entry struct {
    content       string   // the REDACTED content (PII already <LABEL>-replaced); never the raw value
    boundIdentity string   // the writer's normalized identity key (Principal.Subject() if attested, else "" — the unbound marker); the EXACT key validate_read matches against (ADR-004)
    flags         []string // PII/injection metadata recorded at write (e.g. "pii:EMAIL")
}
```

- **Held in:** the `MemoryStore` behind `MemoryGuard.store` (`guard.go`, `store.go`). It is the only
  representation of a memory record the store keeps. The raw (pre-redaction) value is **never** present
  at rest.
- **`boundIdentity` is set ONLY in `ValidateWrite`** (via `boundKeyFor(principalFromMap(identity))`) and
  read ONLY in `ValidateRead`'s identity filter — one write site, one read site, one derivation, so the
  key bound at write is exactly the key matched at read (ADR-004). An attested writer binds its
  `Subject()` (the SPIFFE ID); an unattested/absent writer binds the **unbound** marker (`""`) — **not**
  a wildcard. The typed identity wire shape (`{spiffe_id, trust_tier}`) is decoded into a `Principal` at
  the IPC boundary and never stored as a raw map; only the normalized key persists.

### Seam: `MemoryStore` (the storage backend) and its two stdlib adapters

- **`MemoryStore`** (`store.go`): the storage seam — the storage analogue of the `Detector` seam. The
  guard talks to whatever backs agent memory **only** through these verbs; no backend-specific type
  crosses the boundary (only `string` / `entry` / `[]entry`), so swapping the backing is a one-line
  construction change (`NewMemoryGuard(det, store)`) with no guard/IPC/contract impact (ADR-005).

  ```go
  type MemoryStore interface {
      Put(id string, e entry)        // store/overwrite the REDACTED entry (only after the write-gate clears)
      Get(id string) (entry, bool)   // the post-delete absence proof; unknown id → (zero, false)
      Delete(id string)              // remove id from EVERY backing index/copy; idempotent
      Scan(query string) []entry     // substring match for validate_read; any order
      All() []entry                  // every survivor (primary), non-nil
      AllByIndex() map[string][]entry // survivors grouped by backing-index NAME; the residue scan iterates this across EVERY index/copy (ADR-006)
  }
  ```

  `AllByIndex()` returns a map from an index **name** (a plain `string` label the store chooses — no
  backend type crosses the seam) to that index's survivors. A single-index store returns exactly one
  entry keyed `"primary"`, so the multi-index residue scan reduces exactly to the task-003 single-map
  scan (REQ-005). `verify_delete` scans every index here, so a residue surviving only in a secondary
  copy is caught and the index is named in `residue_summary`.

- **`InMemoryStore`** (`store.go`): the default backing — `type InMemoryStore map[string]entry`, the
  extracted v0 map, unchanged in behavior. `NewMemoryGuard` constructs it when no store is supplied
  (a nil/omitted store falls back to it, mirroring nil-`Detector` → `RegexDetector`). The CLI /
  `serve` default.

- **`TwoIndexStore`** (`store.go`): the second backing with a genuinely different representation — a
  **primary** `id → entry` map PLUS a **secondary** `content → set of ids` index. `Delete` purges
  **both** indexes (and `Put` re-links them on overwrite), so a deleted entry leaves no copy lingering
  in the second index. This is the smallest store that makes "residue absent from **every**
  index/copy" (task 008) a concrete claim. Stdlib-only — `go.mod` stays require-free (ADR-005,
  REQ-006). The guard-behavior suite (`TestGuardBehaviorParityAcrossStores`,
  `TestInvariantsThroughSeam`) runs identically against both backings, proving the seam behaviorally.

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
{ "op":"validate_write", "entry":"contact alice@example.com",
  "identity":{ "spiffe_id":"spiffe://example.org/agent/agent-1", "trust_tier":"attested" } }
```

The `identity` is the typed principal `{spiffe_id, trust_tier}` (ADR-004), decoded through the
`Principal` seam. The stored entry records the writer's normalized **bound-identity key** (the attested
`spiffe_id`, else the unbound marker), not the raw map.

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
{ "op":"validate_read", "query":"contact",
  "identity":{ "spiffe_id":"spiffe://example.org/agent/agent-1", "trust_tier":"attested" } }
```

→ `{ "allow": true, "content_redacted": "contact <EMAIL>", "flags": ["pii:EMAIL"] }` — the contents
matching the query **and** the reader's identity, joined and PII-redacted again on the way out. The
result is **identity-scoped** (ADR-004): an attested reader sees only entries bound to its **exact**
`spiffe_id`; an unattested/absent reader sees only **unbound** entries (never an identity-bound entry,
never the whole store). A query (or identity) matching nothing → empty `content_redacted` and
`flags: []`. v0 always `allow:true`.

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
  "residue_summary": "normalized residue of deleted content survives in index \"primary\", entry \"note: John's balance is $5k…\": \"5000\"",
  "deletion_hash": "64daabe2…bedf49" }
```

- `confirmed` is computed from a fresh presence check **after** the delete (post-deletion
  verification), not assumed from the `delete()` call. Deleting an unknown/absent id still returns
  `{confirmed:true}` (with `residue_detected:false`, no scan).
- `residue_detected` is the result of a guard-side scan (ADR-003/ADR-006) of the **remaining** store
  across **every** backing index/copy — the store's `AllByIndex()` survivors (ADR-005) — for a
  verbatim or near-verbatim fragment of the just-deleted content (a tiered normalized substring /
  contiguous-phrase / token-overlap match, with number canonicalization that folds spelled-out
  number-words `five thousand` ⇆ `5000`; stdlib-only — **not** a `Detector` concern). Scanning every
  index means a residue surviving only in a secondary copy is caught. Because the scan runs over the
  survivors (after the target is removed from every index), a deleted entry can never flag itself.
- `residue_summary` (string) is present **only** when `residue_detected:true`; it names the match
  class (`verbatim` / `normalized` / `phrase` / `token-overlap N%`), the **backing index** the residue
  survives in (e.g. `"primary"`, `"secondary-content-index"`), and the surviving entry — referenced by
  a short **content snippet** (the scan operates over `AllByIndex()` survivors, which carry no map id)
  — plus the matched fragment. Callers that ignored the new fields are unaffected (additive).
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
- **`residue_detected` reflects a scan of the survivors across every index/copy, never of the deleted
  entry itself.** The scan runs over the store *after* the target id is removed from every backing
  index, so a deleted entry cannot flag itself (no
  self-residue false positive). The residue scan is guard-side stdlib logic; no detector-backend type
  participates.
- **`deletion_hash` is deterministic.** It is a pure function (SHA-256) of the deletion op (`id` +
  deleted content) — reproducible across runs and processes, with no randomness.
- **Each entry carries exactly one bound-identity key, set at write and matched exactly at read.**
  `boundIdentity` is written only by `ValidateWrite` and read only by `ValidateRead`'s identity filter;
  matching is **exact** on the normalized key (no substring/fuzzy — `tenant-1` never matches
  `tenant-12`). An unattested/absent principal binds and matches the **unbound** marker only — it never
  reaches an identity-bound entry (fail-closed w.r.t. bound entries).
- **No identity-backend-specific type crosses the wire or the store.** `identity` is plain JSON
  (`{spiffe_id, trust_tier}`) decoded into a `Principal` at the boundary; no SPIFFE/X.509/Ed25519 type
  enters `guard.go`, `ipc.go`, or the stored `entry` — only the normalized key persists (ADR-004).
- **No detector-backend-specific type crosses the wire** — the contract is plain JSON
  (`allow`/`stored_id`/`content_redacted`/`flags`/`confirmed`), so a future detection backend
  (Presidio / ONNX / NER) slots in behind the `Detector` interface unchanged.
</content>
