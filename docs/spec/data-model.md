# Data Model

**Project:** memory-guard
**Last updated:** 2026-07-14 (task 021: in-process immutable-baseline registry + `protected_key_violation` / `immutable_mismatch` flag vocabulary, ADR-017; task 018: `SelfReinforcementDetector` per-subject write-history in-memory state behind the `WriteInspector` seam, ADR-016; task 020: `entry.sourceClass` write-provenance field + `OCSFFinding.SourceClass`, ADR-015; task 016: `ScanScoped` verb + shared-scope marker + `scope` identity field, ADR-013; task 015: persistent `FileStore` backing, ADR-012)

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

**Opt-in, one file.** By default (`MEMGUARD_STORE=memory`) memory-guard holds no database and no files
beyond the transient Unix socket it binds; the default `InMemoryStore` and `TwoIndexStore` backings are
in-memory and lost on restart. When `MEMGUARD_STORE=file` (`FileStore`, ADR-012) the store is **one
JSONL snapshot file** at `MEMGUARD_STORE_PATH`, mode `0600`, rewritten atomically on every mutation
(temp file + fsync + `os.Rename`) so a delete physically removes the deleted entry's bytes. This is the
first persistent backing, and it makes `verify_delete`'s absence proof and the residue scan a claim
about disk-backed state rather than a map. It slots in behind the **unchanged `MemoryStore` seam**
(`store.go`, ADR-005) with no guard/IPC/contract change. A third-party backend (LangChain / LlamaIndex
/ SQLite / vector store) would slot in the same way; that remains deferred, not foreclosed.

### Format: persisted store record (`FileStore`, internal to `store_file.go`)

One JSON object per line; never crosses the `MemoryStore` seam. All three `entry` fields round-trip
(`bound_identity` is the load-bearing isolation key, task 016 depends on it persisting):

```jsonc
{"id": "mem-a1b2c3", "content": "<redacted content>", "bound_identity": "spiffe://…|\"\"", "flags": ["pii:EMAIL"]}
```

- **`id`**: the opaque `mem-<hex>` stored id; a record with an empty/absent `id` is a construction
  error (fail-closed, never a zero-value entry).
- **`content`**: the **redacted** content (raw PII never lands on disk; a poisoned write never reaches
  disk at all).
- **`bound_identity`**: the normalized identity key (`""` for an unbound/unattested writer).
- **`flags`**: the PII/injection metadata (`null`/absent round-trips as nil).

A file that is missing or empty is a valid empty store; an unparseable line is a construction error and
the file is left untouched.

---

## In-memory state

### State: `MemoryGuard.store` — the entry store (behind the `MemoryStore` seam)

- **Shape:** a `MemoryStore` (interface, `store.go`), **not** a raw map. Entries are keyed by the
  opaque `stored_id` (a `"mem-"+randHex(6)` string). `entry { content string; boundIdentity string;
  sourceClass string; flags []string }` (`guard.go`). `content` is the **redacted** content (PII already replaced by
  `<LABEL>` placeholders by `RedactPII` at write time — the raw value is never stored). `boundIdentity`
  is the **normalized identity key** bound at write (the writer's `Principal.Subject()` when attested,
  else the unbound marker) — the key `validate_read` matches **exactly** against (ADR-004). `flags` is
  the PII/injection metadata recorded at write.
- **Owner:** the `MemoryGuard` value (`guard.go`), shared by the IPC server across connections. The
  guard reaches the store **only** through the seam verbs — `Put` (clean write), `Scan` (read), `Get`
  (the post-delete absence proof), `Delete`, and `All` (the residue-scan survivors).
- **Backing:** the default `InMemoryStore` (a single `map[string]entry`); `TwoIndexStore` (a primary
  `id → entry` map plus a secondary `content → ids` index); or the persistent `FileStore` (a JSONL
  snapshot on disk, opt-in via `MEMGUARD_STORE=file`, ADR-012). All three are stdlib-only, selected
  through `NewStoreFromConfig` (ADR-005, ADR-012).
- **Lifetime:** populated by `ValidateWrite` (clean writes only — a poisoned write calls **no** `Put`
  and stores nothing), entries removed by `VerifyDelete` (which `Delete`s from **every** backing
  index). With the in-memory backings, state is process lifetime and nothing persists across a restart;
  with `FileStore` the state lives in the on-disk JSONL snapshot and **survives a restart** (an
  independently constructed store on the same path sees the persisted entries).
- **Concurrency rules:** the whole store is guarded by `MemoryGuard.mu` (`sync.Mutex`); each operation
  locks it for the duration of its store access. A multi-index backing keeps its indexes consistent
  across the verbs within that lock.
- **Bounds:** bounded by the number of clean writes; no eviction or TTL.

### State: `SelfReinforcementDetector` per-subject write history (behind the `WriteInspector` seam, task 018 / ADR-016)

- **Shape:** an in-memory `map[string][]writeRecord` keyed by the writer's bound identity key (`WriteContext.Key`),
  where `writeRecord { tokens map[string]struct{}; at time.Time }` holds the token set of a past write
  and the instant it was seen. It records the minimal state needed to detect `self_reinforcement_suspected`
  (a repetition pattern over a cooldown window); the raw content is **not** retained, only its token set.
- **Owner:** the `SelfReinforcementDetector` value (`self_reinforcement.go`), guarded by its own
  `sync.Mutex` (independent of `MemoryGuard.mu`). It is **detection-internal working state**, deliberately
  **not** part of the persisted `MemoryStore`: it never round-trips to disk, is never returned by any
  `validate_*` verb, and is lost on restart.
- **Lifetime / bounds:** populated on every accepted, agent-authored `Inspect` call. Bounded two ways so
  a single identity's history cannot grow without limit: records older than the cooldown window are
  evicted on each `Inspect`, and a hard per-subject size cap trims the oldest records. Bounding the
  *number of distinct tracked identities* is a noted follow-up, not enforced in v0.

### State: `MemoryGuard.baselines` — the immutable-key baseline registry (task 021 / ADR-017)

- **Shape:** an in-memory `map[string]string` keyed by the caller-supplied logical `key`, mapping to
  `immutableBaselineHash(redactedContent) = hex(SHA-256("immutable\x00" + content))`: the first-seen
  redacted-content digest under each immutable-checked key (reserved `memguard:*` or an operator
  `MEMGUARD_IMMUTABLE_KEYS` glob). It records only the digest, never the content.
- **Owner:** the `MemoryGuard` value (`guard.go` / `keys.go`), guarded by `MemoryGuard.mu`. It is
  allocated in `NewMemoryGuard` and shared by reference across every builder copy (`WithAudit` /
  `WithKeyPolicy` / `WithWriteInspector`), so a baseline established on the guard survives builder
  chaining. It is **not** part of the persisted `MemoryStore`, never round-trips to disk, and is never
  returned by any `validate_*` verb.
- **Lifetime / bounds:** an entry is written on the FIRST accepted write under an immutable-checked key
  and **never overwritten** by a later mismatching value (the baseline stays pinned to the first-seen
  hash, so drift is detectable on every subsequent write). A write rejected by the protected check (or
  by the injection gate) establishes no baseline.
- **Durability limitation (ADR-017, explicit future work):** the registry is **in-process only** and is
  lost on restart, so a reserved/immutable key's baseline resets to the first post-restart write. This
  mirrors task 009's identity model before task 016 made it durable; persisting it is deferred.

### Type: `entry` (a stored memory record)

```go
type entry struct {
    content       string   // the REDACTED content (PII already <LABEL>-replaced); never the raw value
    boundIdentity string   // the writer's normalized identity key (Principal.Subject() if attested, else "" — the unbound marker); the EXACT key validate_read matches against (ADR-004)
    sourceClass   string   // WRITE PROVENANCE (ADR-015): external_tool|user_input|agent_authored|system, or "unknown" for absent/unrecognized; WHERE the write came from, distinct from WHO (boundIdentity)
    flags         []string // PII/injection metadata recorded at write (e.g. "pii:EMAIL")
}
```

- **Held in:** the `MemoryStore` behind `MemoryGuard.store` (`guard.go`, `store.go`). It is the only
  representation of a memory record the store keeps. The raw (pre-redaction) value is **never** present
  at rest.
- **`boundIdentity` is set ONLY in `ValidateWrite`** (via `boundKeyFor(principalFromMap(identity))`) and
  read ONLY in `ValidateRead`'s store-side `ScanScoped` — one write site, one read site, one derivation,
  so the key bound at write is exactly the key matched at read (ADR-004 / ADR-013). An attested writer
  binds its `Subject()` (the SPIFFE ID), or the reserved `sharedScopeKey` (`"shared://"`) when it
  requested `scope:"shared"`; an unattested/absent writer binds the **unbound** marker (`""`) — **not**
  a wildcard. The reserved marker is forge-proof: a `Subject()` equal to `"shared://"` maps to unbound.
  The typed identity wire shape (`{spiffe_id, trust_tier, scope?}`) is decoded into a `Principal` at
  the IPC boundary and never stored as a raw map; only the normalized key persists.
- **`sourceClass` is WRITE PROVENANCE, not identity** (ADR-015). It is set ONLY in `ValidateWrite`,
  via `sourceClassFromMap(identity)` at the SAME read of `identity` that binds `boundIdentity`, so the
  stored provenance and the write's audit event (`OCSFFinding.SourceClass`) come from one decode and
  cannot drift. Value is one of `external_tool` / `user_input` / `agent_authored` / `system`, or
  `unknown` for an absent/empty/unrecognized `source_class` key (never a silent `agent_authored`).
  Unlike `boundIdentity` it never gates a read: `ValidateRead` and `ScanScoped` ignore it entirely. It
  is the field a future behavioral detector (roadmap 018/019) keys on; this task tags and threads it,
  no policy acts on it yet. An entry read back with `sourceClass == ""` (written before this field
  existed) must be treated the same as `unknown` by consumers.

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
      Scan(query string) []entry     // substring match; any order
      ScanScoped(query string, visibleKeys []string) []entry // substring AND exact-membership on boundIdentity; the validate_read path (ADR-013)
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
  `TestInvariantsThroughSeam`) runs identically against all backings, proving the seam behaviorally.

- **`FileStore`** (`store_file.go`, ADR-012): the first **persistent** backing, opt-in via
  `MEMGUARD_STORE=file`. A single JSONL snapshot at `MEMGUARD_STORE_PATH`, rewritten atomically on
  every mutation (temp file + fsync + `os.Rename`, mode `0600`) and read through to disk on every verb
  (no in-memory cache). A `Delete` physically removes the deleted entry's bytes, so `verify_delete`'s
  absence proof and the residue scan run against real persistence and survive a restart. All four
  `entry` fields (`content`, `boundIdentity`, `sourceClass`, `flags`) round-trip through the persisted
  record (`source_class` is `omitempty`, so a snapshot written before this field existed stays
  byte-identical and its entries load with `sourceClass == ""`, treated as `unknown`).
  Corruption at construction is a fail-closed error (the file is left untouched); a runtime I/O failure
  panics (fail fast). Stdlib-only — `go.mod` stays require-free. Selected through the
  `NewStoreFromConfig` factory (`store_config.go`), mirroring the `Detector` config pattern.

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

The request may also carry an optional top-level `key` (a plain string, ADR-017) for the named-key
write-time policy. A reserved `memguard:*` key violation (unattested writer or baseline drift) is
fail-closed like a poisoned write (`{ "allow": false, "stored_id": null, "flags": [… "protected_key_violation" | "immutable_mismatch"] }`);
an operator-configured `MEMGUARD_PROTECTED_KEYS` / `MEMGUARD_IMMUTABLE_KEYS` glob violation is flag-only
(`{ "allow": true, "stored_id": "mem-…", "flags": [… "protected_key_violation" | "immutable_mismatch"] }`).
The `key` is never persisted on the entry. The `{allow, stored_id, flags}` response shape is unchanged;
the two new flag strings are additive values in the existing `flags` array.

**`flags` vocabulary (all additive values in the same array):** `pii:<LABEL>` (a PII category was
redacted, `validate_write` / `validate_read`), `injection_suspected` (fail-closed write-gate rejection),
`self_reinforcement_suspected` (behavioral near-duplicate finding, non-blocking, ADR-016),
`protected_key_violation` (a protected-key write from an unattested/absent writer, ADR-017), and
`immutable_mismatch` (a keyed write whose redacted content drifts from the pinned baseline, ADR-017).
Reserved-key violations reject; operator-configured violations flag-and-allow.

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
- **No reserved-key violation is stored (ADR-017).** A write to a `memguard:*` reserved key from an
  unattested/absent writer (`protected_key_violation`), or one whose redacted content drifts from the
  pinned baseline (`immutable_mismatch`), is rejected fail-closed and stores nothing. The injection gate
  runs first, so a write that trips both injection and a key violation is rejected via the injection
  path and establishes no baseline. Operator-configured key violations are flag-only and DO persist.
- **The immutable baseline is pinned to the first value.** Once established, a key's baseline is never
  advanced by a later mismatching write, so drift is detectable on every subsequent write, not just the
  first. The `key` itself is never stored on the entry.
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
  `boundIdentity` is written only by `ValidateWrite` and read only by `ValidateRead`'s store-side
  `ScanScoped` over the reader's visible-key set; matching is **exact** on the normalized key (no
  substring/fuzzy — `tenant-1` never matches `tenant-12`). An unattested/absent principal binds and
  matches the **unbound + shared** set only — it never reaches an identity-bound entry (fail-closed
  w.r.t. bound entries).
- **Shared scope is attested-only and forge-proof (ADR-013).** The reserved `sharedScopeKey`
  (`"shared://"`) is bound only by an attested writer that requested `scope:"shared"`; every reader's
  visible-key set includes it, so shared entries are readable under every identity class. No `spiffe_id`
  can forge the marker: a `Subject()` equal to `"shared://"` maps to the unbound key.
- **No identity-backend-specific type crosses the wire or the store.** `identity` is plain JSON
  (`{spiffe_id, trust_tier, scope?}`) decoded into a `Principal` at the boundary; no SPIFFE/X.509/Ed25519
  type enters `guard.go`, `ipc.go`, or the stored `entry` — only the normalized key persists (ADR-004).
- **No detector-backend-specific type crosses the wire** — the contract is plain JSON
  (`allow`/`stored_id`/`content_redacted`/`flags`/`confirmed`), so a future detection backend
  (Presidio / ONNX / NER) slots in behind the `Detector` interface unchanged.
</content>
