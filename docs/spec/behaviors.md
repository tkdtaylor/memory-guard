# Behaviors

**Project:** memory-guard
**Last updated:** 2026-07-14 (task 020: write-provenance `source_class` tag on the write path + audit event, ADR-015; task 016: store-side `ScanScoped` + shared scope + restart-surviving isolation, ADR-013)

What the system does, observably — triggering condition, response, externally-visible side effects,
failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry points*
([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Validate a memory write (`validate_write`) — the write-gate, fail-closed on poisoning

- **Trigger:** `{"op":"validate_write","entry":…,"identity":{…}}` over IPC, or
  `MemoryGuard.ValidateWrite(text, identity)` in-process (the `write` CLI subcommand).
- **Response:** the guard runs **injection detection first** (`Detector.DetectInjection`). If the
  content is flagged `injection_suspected`, the write is **rejected fail-closed** —
  `{ "allow": false, "stored_id": null, "flags": [ …, "injection_suspected" ] }` — and **nothing is
  stored**. Otherwise the content is **PII-redacted** (`Detector.RedactPII`, PII → `<LABEL>`
  placeholders), an opaque `stored_id` of the form `mem-<hex>` is minted from `crypto/rand`, the
  **redacted** content is inserted into the in-memory store under that id **bound to the writer's
  identity**, and the guard returns `{ "allow": true, "stored_id": "mem-…", "flags": […] }`. `flags`
  carries the PII categories found (e.g. `pii:EMAIL`) as informational metadata.
- **Identity binding (ADR-004 / ADR-013):** the typed `identity` (`{spiffe_id, trust_tier, scope?}`) is
  decoded through the `Principal` seam and the entry records a **normalized bound-identity key** — the
  writer's `Subject()` (the SPIFFE ID) when the principal is **attested**, else the **unbound** marker.
  A write that is **attested AND carries `scope == "shared"`** binds the reserved `sharedScopeKey`
  instead (readable under every identity, B-008). An unattested writer requesting shared binds unbound
  (no privilege escalation). This key is what `validate_read` matches against (B-002, B-008). A write
  with no attested identity binds the unbound marker — **not** a wildcard that matches everyone. The
  reserved marker is **forge-proof**: a `spiffe_id` equal to `sharedScopeKey` maps to unbound, so only
  an explicit attested `scope:"shared"` reaches the shared binding. No SPIFFE/X.509 specifics enter the
  guard; only `Principal` crosses the seam.
- **Write provenance (ADR-015):** the guard decodes an optional `source_class` key off the same
  `identity` map, once, via `sourceClassFromMap`, and records it on the entry as `sourceClass`. It is
  one of `external_tool` / `user_input` / `agent_authored` / `system`, or `unknown` when the key is
  absent, empty, or unrecognized (never a silent `agent_authored`). Provenance is **where** the write
  came from, distinct from the bound identity (**who** wrote it); it never gates a read. The same single
  decoded value is stamped onto the write's audit event (`OCSFFinding.SourceClass`, B-009) for both
  accepted (PII-redaction) and rejected (injection) writes, so the stored entry and the event agree
  value-for-value. This tags and threads provenance; no policy acts on it yet (the behavioral-detector
  work, roadmap 018/019, is the intended consumer). The `validate_write` response shape is unchanged:
  `source_class` never appears in the response.
- **Side effects:** on a clean write, mutates the in-memory store (with the **redacted** content +
  the bound-identity key + the source-class provenance tag + flags). On a rejected write, no store mutation.
- **Failure modes:** a write flagged for poisoning never persists (the write-gate). The raw PII is
  **never** stored — only the redacted form. The agent receives the opaque `stored_id`, **never** the
  raw value. *(Tests: `TestWriteGateRejectsSuspectedInjection`, `TestWriteRedactsPIIAndStores`, `TestPoisoningRecallPrecision`, `TestPoisoningFailClosedPerCase` — adversarial recall=0.69, precision=0.85 on the v0 4-pattern regex; measured 2026-06-19 against 32-case corpus; see fitness-functions.md F-006.)*

### B-002: Validate a memory read (`validate_read`) — identity-scoped, redact PII on the way out

- **Trigger:** `{"op":"validate_read","query":…,"identity":{…}}` over IPC, or
  `MemoryGuard.ValidateRead(query, identity)` in-process (the `read` CLI subcommand).
- **Response:** the guard derives the reader's **visible-key set** and makes a single store-side
  `ScanScoped(query, visibleKeys)` call (ADR-013): the store returns entries whose content **contains
  the query substring** AND whose bound-identity key is an **exact member** of the visible-key set. It
  joins the surviving contents with newlines, runs `Detector.RedactPII` over the joined result (defense
  in depth — PII redacted again on read), and returns `{ "allow": true, "content_redacted": "…",
  "flags": […] }`. v0 always returns `allow:true`; `flags` carries any PII categories the read-time
  redaction found.
- **Identity scoping (ADR-004 / ADR-013):** the reader's visible-key set comes from the `Principal`
  seam plus the shared marker:
  - an **attested** reader's keys are `{Subject(), sharedScopeKey}`: it sees entries bound to its
    **exact** `Subject()` (no substring/fuzzy on the identity — `tenant-1` never matches `tenant-12`)
    **plus** shared-scope entries;
  - an **unattested or absent** reader's keys are `{unboundKey, sharedScopeKey}`: it sees entries
    written with **no** bound identity **plus** shared-scope entries — **never** an identity-bound
    entry, **never** the whole store.
  - The scoping is now store-side (a single `ScanScoped` call), replacing the guard-side filter loop
    over `Scan` (ADR-004's deferred durable-lookup item, realized at seam level). `scope` on a read
    identity is ignored.
- **Side effects:** none (read-only).
- **Failure modes:** a query matching no entries — or no entries under the reader's identity — yields an
  empty `content_redacted` and an empty `flags`. A non-matching entry is **excluded entirely** (invisible,
  not merely redacted). PII that somehow reached the store is still redacted on the way out. *(Tests:
  `TestReadReturnsOnlyMatchingIdentity`, `TestNoCrossIdentityLeakage`,
  `TestIdentityScopedLookupReplacesWholeStoreScan`, `TestNoIdentityReadIsUnboundOnly`,
  `TestPIIRedactionUnchangedUnderIdentityScoping`, and `TestWriteRedactsPIIAndStores` — the read half
  asserts `<EMAIL>` present and `alice@example.com` absent.)*

### B-003: Verify a deletion (`verify_delete`) — prove absence **and** scan for surviving residue

- **Trigger:** `{"op":"verify_delete","id":…}` over IPC, or `MemoryGuard.VerifyDelete(id)` in-process.
- **Response:** the guard (1) removes the entry keyed by `id` from the store **and every backing
  index/copy**, (2) **re-checks** the store for that id (`confirmed:true` iff no longer present — the
  v0 proof), then (3) **scans every backing index/copy of the remaining store for residue** of the
  just-deleted content (via the `MemoryStore` seam's `AllByIndex()`, ADR-005/ADR-006) and returns
  `{ "confirmed", "residue_detected", "residue_summary"?, "deletion_hash" }`. `residue_detected:true`
  means a verbatim or near-verbatim fragment of the deleted content survives in another entry **in any
  index/copy** — including a secondary index a primary-only scan would miss (the documented industry
  gap a bare `delete()` misses); when true, `residue_summary` names the match class (`verbatim` /
  `normalized` / `phrase` / `token-overlap N%`), **the backing index the residue survives in**, and
  the surviving entry. The residue scan is a tiered, normalized substring / contiguous-phrase /
  token-overlap match, with number canonicalization that now also folds **spelled-out number-words**
  (`five thousand` ⇆ `5000`) (ADR-003/ADR-006) — deterministic, **stdlib-only guard-side
  orchestration**, with **no** detector backend involvement. `deletion_hash` is a deterministic
  SHA-256 over the deletion op (`id` + deleted content), **independent of index layout**, for
  audit-trail linkage.
- **Side effects:** removes the entry from the store and every secondary index/copy (idempotent —
  deleting an absent id is a no-op that still confirms gone). The scan is read-only over the survivors.
- **Failure modes:** deleting an unknown or already-deleted id still returns `confirmed:true,
  residue_detected:false` (no scan — there is no deleted content to scan for). Because the scan runs
  over the survivors *after* the target is removed from every index, a deleted entry never flags
  itself (no self-residue false positive). The number-word paraphrase class is now caught (e.g. `$5000`
  ⇆ "five thousand dollars"); **free-form synonym paraphrase** with no shared distinctive token
  ("potted plant" → "planter") is the residual known-miss of the stdlib method (ADR-006), recorded
  honestly per residue class. *(Tests: `TestVerifyDeleteConfirmsAbsence` (v0 compat),
  `TestVerifyDeleteReturnsResidueFields`, `TestVerifyDeleteTruthTable`, `TestResidueCorpusDetectionRate`,
  `TestDeletionHashDeterministic`, `TestResidueScanCoversEveryIndex`, `TestTruthTableAcrossIndexes`,
  `TestMultiIndexResidueRate`, `TestParaphraseSubCorpusImprovedSeparately`,
  `TestDeletionHashIndexIndependent`, `TestSingleIndexReducesToTask003Scan`.)*

### B-004: Serve over a `0600` Unix-socket IPC server (`serve`)

- **Trigger:** `memory-guard serve --socket <path>`.
- **Response:** removes any stale socket at `<path>`, binds a Unix socket, sets permissions to `0600`
  (owner-only), logs `memory-guard serving on <path>` to stderr, and accepts connections — spawning a
  goroutine per connection over a shared `*MemoryGuard`. Each accepted connection sends one
  newline-delimited JSON object `{op, …}`; ops are `validate_write` (B-001), `validate_read` (B-002),
  `verify_delete` (B-003), and `ping` (→ `{"ok":true}`).
- **Side effects:** creates the socket file; spawns one goroutine per connection. The shared
  `MemoryGuard`'s `sync.Mutex` guards the store across concurrent connections.
- **Failure modes:** a missing `--socket` exits with a usage error (`2`). A bind failure returns a
  non-zero exit (`1`) with `error: …` on stderr. An empty / unreadable first line closes the connection
  with no response. *(No automated test — runtime-observable via a live `serve`.)*

### B-005: Reject a malformed or unknown request (fail-closed)

- **Trigger:** unparseable request JSON, or an `op` that is not `validate_write` / `validate_read` /
  `verify_delete` / `ping`.
- **Response:** the structured error shape `{ "error": { "code": …, "message": …, "retryable": false } }`.
  Codes in use: `bad_request` (unparseable JSON — the parse error message is echoed) and `unknown_op`
  (an unsupported op — `"unsupported op"`).
- **Side effects:** none; the connection is closed after the single response.
- **Failure modes:** the caller must treat any `error` response as a non-result (fail-closed); no store
  mutation occurs on a malformed/unknown request. *(No automated test — runtime-observable.)*

### B-006: One-shot in-process write demo (`write`)

- **Trigger:** `memory-guard write "<text>"`.
- **Response:** constructs a fresh `MemoryGuard` (default `RegexDetector`), runs `ValidateWrite(text,
  nil)` in-process, and prints the `WriteResult` as indented JSON to stdout — either a redacted-and-
  stored result (`allow:true`, a `stored_id`, `pii:*` flags) or a write-gate rejection (`allow:false`,
  `stored_id:null`, `injection_suspected`).
- **Side effects:** stdout only; no socket, no persistence across the process.
- **Failure modes:** an absent text argument validates the empty string (a benign clean write). *(No
  automated test for the CLI wrapper; the underlying `ValidateWrite` is unit-tested.)*

### B-007: One-shot in-process read demo (`read`)

- **Trigger:** `memory-guard read "<query>"`.
- **Response:** constructs a fresh `MemoryGuard`, **seeds** the store by running `ValidateWrite(query,
  nil)` (so the one-shot demo has something to read), then runs `ValidateRead(query, nil)` and prints
  the `ReadResult` as indented JSON — the redacted content and any flags.
- **Side effects:** stdout only; the seeded entry lives only for the process.
- **Failure modes:** if the seed text itself trips the write-gate (looks like injection), nothing is
  stored and the read returns empty content. *(No automated test for the CLI wrapper.)*

### B-008: Identity-scoped read isolation — a writer's entries are visible only under a matching identity

- **Trigger:** any `validate_read` carrying an `identity` (`{spiffe_id, trust_tier}`), against a store
  holding entries bound to different identities at write time (B-001).
- **Response:** the read result is **scoped by identity** (ADR-004 / task 009 / ADR-013): writer A's
  entry is returned to a reader **only** when the reader is **attested** and its `Subject()` **exactly**
  matches A's bound key. Writer A's entry is **never** returned to reader B — even when B's query
  substring matches A's content **verbatim**. The isolation holds **because of identity**, not because
  the query failed to match. An unattested/absent reader gets the **unbound + shared** set (B-002).
  **Shared scope (ADR-013):** an attested writer may bind the reserved `sharedScopeKey` (`scope:"shared"`);
  shared entries are readable under **every** identity class (attested tenants, unattested, absent), the
  one cross-tenant channel. An unattested writer cannot publish shared (binds unbound), and no `spiffe_id`
  can forge the marker.
- **Side effects:** none (read-only). Enforced via a single store-side `ScanScoped(query, visibleKeys)`
  call over the `MemoryStore` seam (ADR-013: the durable, store-side form of ADR-004's deferred scoped
  lookup, replacing the guard-side linear filter over `Scan`). The reader's visible-key set is
  `{Subject()|unboundKey, sharedScopeKey}`; deriving it is the only policy site, the store enforces exact
  membership. **Durable:** over `FileStore` (task 015), an independently constructed guard on the same
  path re-enforces the full matrix across a restart. Identity matching is guard-side orchestration
  through the `Principal` seam — **not** a `Detector` concern; no detector backend specifics enter the
  identity path.
- **Failure modes:** a forged or unverified (`trust_tier != "attested"`) identity matches **no**
  identity-bound entry — it falls to the unbound + shared set, never through to the whole store
  (fail-closed w.r.t. bound entries). PII redaction still runs on whatever the scoped set returns.
  *(Tests: `TestNoCrossIdentityLeakage` (load-bearing), `TestReadReturnsOnlyMatchingIdentity`,
  `TestWriteBindsVerifiableIdentity`, `TestIdentityScopedLookupReplacesWholeStoreScan`,
  `TestNoIdentityReadIsUnboundOnly`, `TestPrincipalSeamSemantics`; task 016:
  `TestScanScopedExactMembershipPerAdapter`, `TestValidateReadUsesScanScoped`,
  `TestSharedScopeVisibilityMatrix`, `TestSharedMarkerCannotBeForged`,
  `TestDurableIsolationSurvivesRestart`; L6 over a live `serve` socket, restart-surviving.)*

---

## Behavioral invariants

- **No poisoned write persists.** `validate_write` runs injection detection before storage; an
  `injection_suspected` flag rejects the write (`allow:false`, `stored_id:null`) and nothing enters the
  store. The write-gate is fail-closed.
- **PII is never stored or returned raw.** `validate_write` redacts before storing; `validate_read`
  redacts again on the way out. The raw PII is replaced by `<LABEL>` placeholders and appears in no
  response and in no stored entry.
- **The agent never receives the raw stored value.** `validate_write` returns an opaque `stored_id`
  (`mem-<hex>` from `crypto/rand`); the stored content is reachable only via `validate_read`, and only
  in redacted form.
- **Deletion is verified, and residue is hunted.** `verify_delete` re-checks the store after the
  delete and reports `confirmed` from that fresh check — never an assumed success from the `delete()`
  call — and additionally scans the remaining entries for a surviving fragment of the deleted content
  (`residue_detected`), the documented industry gap. A deleted entry never flags itself.
- **The detection backend is isolated behind the `Detector` seam, and is selectable.** All PII +
  injection detection goes through the `Detector` interface; the guard, the IPC, and the contract carry
  no backend-specific detail. The backend is chosen by `MEMGUARD_DETECTOR` (`native` default / `regex` /
  `presidio`). The **set of `pii:<LABEL>` flags a write can return depends on the selected backend**:
  the native/regex backends emit the structured categories (EMAIL / US_SSN / CREDIT_CARD / API_KEY /
  PHONE / IBAN / IP_ADDRESS / DOB / CREDENTIAL); the opt-in Presidio backend (ADR-009) emits those
  **plus** NER categories (PERSON / LOCATION / NRP / DATE_TIME / …). Injection detection is identical
  across all three backends (the Presidio backend delegates `DetectInjection` to the native heuristic
  unchanged — it lifts PII/NER recall, not injection recall).
- **Every malformed / unknown request fails closed.** An unparseable request or an unknown op returns
  the structured error shape; nothing is stored or returned.
- **Reads are identity-scoped (fail-closed w.r.t. bound entries).** A writer's entry is visible only to
  an **attested** reader with an **exactly** matching `Subject()`; an unattested/absent reader sees only
  **unbound** (public/system) entries. A non-matching identity is never returned an identity-bound entry
  and never the whole store. Identity verification stays upstream (agent-mesh); the guard trusts the
  pre-verified `trust_tier` across the `0600` socket (ADR-004) and keeps SPIFFE/X.509 specifics behind
  the `Principal` seam.

### B-009: Audit-trail emission — fail-open, opt-in, default-off, real socket transport (task 010 / ADR-007; task 017 / ADR-014)

- **Trigger:** any detection that `ValidateWrite` or `VerifyDelete` computes — PII redaction, injection
  rejection, residue found, or deletion — when audit emission is enabled in the `AuditConfig` and a
  non-nil `AuditSink` is wired in.
- **Response:** the guard emits an **OCSF-shaped event** through the `AuditSink` seam (`audit.go`) for
  each detection, **in addition to** returning the verdict and `flags` to the caller (additive — the
  contract response shapes are unchanged). Events carry the **OCSF Security Finding envelope**
  (`class_uid=2001`, `category_uid=2`, `activity_id=1`, `severity_id` by detection class, a UTC
  `time` timestamp, and a `metadata.product.name="memory-guard"` block) plus a structured `finding`
  block (`type`, `operation`, `flags`, `flag_count`, `stored_id`, `source_class`, `deletion_hash`, `residue_detected`).
  The two **write-triggered** builders (`BuildPIIRedactionEvent`, `BuildInjectionRejectedEvent`) stamp
  `source_class` from the write's provenance (ADR-015, B-001), the SAME decoded value stored on the
  entry, so the event and the entry agree value-for-value. `verify_delete` events carry `source_class`
  empty (deletion has no writer-provenance concept). Detection detail is in **structured fields, never a free-text blob** (REQ-002). Severity:
  `injection_rejected` → High (4); `pii_redaction` → Low (2); `residue_found` → Medium (3);
  `deletion_verified` → Informational (1). A benign write with no detection flags emits no event
  (deterministic).
- **Emission policy:** emission is **best-effort and fail-open**. A failing, slow, or absent sink
  **never** blocks the hot path, **never** surfaces an error to the caller, and **never** changes a
  `validate_*` / `verify_delete` verdict. `emitSafe` (the only call site in the guard) swallows
  errors and recovers panics. The write-gate's **fail-closed** posture is completely independent of
  the sink's fail-open posture: a poisoned write stays rejected even when the sink is down.
- **PII invariant:** no raw PII or raw deleted content ever appears in an emitted event. Events carry
  the guard-computed flag metadata (`"pii:EMAIL"`, `"injection_suspected"`) and the opaque `stored_id`
  / deterministic `deletion_hash` — **never** the raw input text. The memory-guard invariant "PII
  never lands anywhere unredacted" extends to the audit channel.
- **Transport (task 017 / ADR-014):** the real sink is `AuditTrailSink` (`audit_trail_sink.go`),
  speaking the sibling audit-trail block's **confirmed plain-event** wire contract (`{"op":"emit",
  "event":{ts, actor, action, target, decision?, refs[], context?}}` → `{seq, hash}`), **not** OCSF.
  The internal `OCSFEvent` is translated to the plain event at the sink boundary (`mapToAuditTrailEvent`),
  so `guard.go` / `ipc.go` / the event builders / the contract are untouched. Deletion events carry the
  `deletion_hash` as a `refs` entry (`[{type:"deletion_hash", id:<hash>}]`), its first consumer;
  `actor` is `"memory-guard"`; every wire number is an int (audit-trail rejects floats). No raw content
  or PII crosses the wire. An OCSF-native export is a noted follow-on (ADR-014).
- **Config gate:** emission is **opt-in and OFF by default**. `serve --audit-socket <path>` (env
  fallback `MEMGUARD_AUDIT_SOCKET`, flag wins) wires `guard.WithAudit(buildAuditConfig(path))`, whose
  sink is the `AuditTrailSink` wrapped in `AsyncSink` (non-blocking dispatch). An empty path leaves
  emission disabled (zero connections). An unreachable path still constructs (soft dependency,
  fail-open at runtime); an invalid config (`Enabled: true, Sink: nil`) fails closed to disabled.
  *(Tests: task-010 `TestAudit*` suite unchanged; task-017 `TestAuditSinkTC001…TC008` — field-by-field
  wire mapping, deletion_hash value-for-value, no-floats, fail-safe across dead/hanging/erroring
  endpoints, opt-in wiring; L6 against the real `audit-trail` binary, chain verifies with the new
  events in it.)*
  Toggling emission requires reconstructing the guard with a new `WithAudit` call; no live config
  reload in v0.
- **OCSF event shape note (reconciled, ADR-014):** the **internal** event is modelled on public OCSF
  1.1 (`audit.go` builders, unchanged). The sibling audit-trail's consumed contract is now confirmed
  and is the **plain hash-chained event**, not OCSF; the internal event is translated at the sink
  boundary (`mapToAuditTrailEvent`), so the OCSF builders stayed intact and the guard/IPC/contract took
  zero impact. Surviving OCSF detail (`ocsf_class_uid`, `severity_id`) rides in `context`. An
  OCSF-native export is a noted follow-on.
- **Side effects:** each call to `emitSafe` is a synchronous call to `Sink.Emit`; the default
  `NoOpSink` has zero allocation cost. A real transport (socket/HTTP/file) would add round-trip
  latency only when enabled — not on the default disabled path.
- **Failure modes:** a nil or missing sink is silently treated as disabled. A panicking `Emit`
  implementation is recovered (the guard continues). A **slow/blocking** sink must be wrapped in
  `AsyncSink` (the non-blocking dispatch wrapper — bounded buffered channel + background drain
  goroutine + drop-on-full + panic recovery in the drain) so the hot path never stalls waiting for a
  slow transport: `AsyncSink.Emit` enqueues and returns immediately, and the slow forward happens off
  the hot path; when the buffer is full the event is dropped (fail-open). Real network transports
  (Unix socket / HTTP) are intended to be wired through `AsyncSink`; the synchronous in-process sinks
  (`CollectingSink`, `NoOpSink`) stay synchronous. *(Tests: `TestAuditTC001_EventPerDetectionClass`
  through `TestAuditTC007_ConfigGated`, including `TestAuditTC005_NoPIIInEvents` — the load-bearing
  no-raw-PII assertion — `TestAuditTC006_FailOpen` (fail-open + panic-recovery +
  `slow_sink_does_not_stall_hot_path`), `TestAsyncSinkNonBlocking`, and
  `TestDeletionHashIndependentOfSinkState`.)*

### B-010: Flag self-reinforcement on repetitive self-authored writes (task 018 / ADR-016)

- **Trigger:** a `validate_write` accepted by the write-gate (past the injection check) when the guard
  is wired with a behavioral `WriteInspector` via `WithWriteInspector`. The CLI `serve` / `write` path
  wires the shipped `SelfReinforcementDetector` by default; the off-switch is
  `MEMGUARD_SELF_REINFORCEMENT=off`. A guard built without the inspector never exhibits this behavior.
- **Response:** the inspector sees the write's content plus a `WriteContext` (`{Key, SourceClass}`:
  the writer's bound identity key and the raw `source_class` hint). `SelfReinforcementDetector` keeps a
  bounded per-subject history and adds `self_reinforcement_suspected` to `flags` when the incoming
  write's token-set overlap coefficient meets or exceeds the similarity threshold against at least
  `max_self_writes` prior same-subject writes inside the cooldown window. Defaults on the CLI path:
  similarity `0.85`, cooldown `5m`, `max_self_writes 3` (so the 4th near-duplicate in a window is the
  first to flag). All three, plus an injectable clock, are constructor-configurable.
- **Additive, non-blocking (policy boundary):** the flag is **additive** on the existing `flags` array
  and **never blocks**: a write carrying `self_reinforcement_suspected` is still `{ "allow": true,
  "stored_id": "mem-…" }`, stored exactly as it would be without the inspector. The `validate_write`
  response shape stays byte-for-byte `{allow, stored_id, flags}`. Whether the flag should ever block,
  quarantine, or escalate is a policy-engine decision, deferred to a future quarantine-outcome task
  (this behavior computes the signal, it does not act on it). The existing fail-closed injection path
  is untouched: the inspector runs only on the accepted path, so a rejected poisoned write never
  reaches it and never carries the flag.
- **Source-class routing:** only an explicit `source_class: "human_authored"` opts a write out of
  scrutiny (human repetition is out of scope). Every other value, including an absent hint, an empty
  string, and any unrecognized value, defaults to agent-authored (fail-closed toward scrutiny). This is
  forward-compatible with the durable provenance signal (ADR-015): when an explicit `agent_authored`
  arrives it behaves identically to the missing-hint default.
- **Bounded memory:** the per-subject history is evicted by cooldown expiry and capped at a hard
  per-subject size, so one identity's history cannot grow without bound. The history is
  detection-internal working state; it is **not** part of the persisted `MemoryStore`.
- **Seam isolation:** the flag is produced entirely behind the `WriteInspector` seam; no
  implementation specifics appear in `guard.go`, `ipc.go`, or the contract, and `docs/CONTRACT.md`
  needs no edit (the `flags []string` shape already admits new string values).
- **Known audit gap:** a write flagged `self_reinforcement_suspected` with **no PII** present emits no
  audit-trail event, because emission is gated on `len(piiFlags) > 0` (B-009). Wiring a dedicated
  emission path for the behavioral flag is out of scope for this task (recorded in ADR-016).
  *(Tests: `TestTC001SeamIsDistinctFromDetector` through `TestTC011ADRAndSpecPropagation`,
  `TestSelfReinforcementHarnessL5` (recall + precision in one run), `TestSelfReinforcementOverSocket`
  (flag observed on the live socket).)*

### B-011: Flag a size anomaly on a write outsized relative to its key's own history (task 019 / ADR-018)

- **Trigger:** a `validate_write` accepted by the write-gate (past the injection check) when the guard
  is wired with the `SizeAnomalyDetector` behavioral `WriteInspector`. The CLI `serve` / `write` path
  wires it by default alongside `SelfReinforcementDetector` (composed via `CombineInspectors`); the
  off-switch is `MEMGUARD_SIZE_ANOMALY=off`. A guard built without the inspector never exhibits this
  behavior.
- **Response:** the detector sizes the write on `len(content)` and keeps a bounded ring buffer of the
  `WindowSize` most recent sizes per `WriteContext.Key`. It adds `size_anomaly_suspected` to `flags`
  when that key's buffer already holds at least `MinSamples` samples **and** the new size deviates
  more than `SigmaThreshold` population standard deviations from the buffer's mean (strict `>`). The
  test runs against the existing buffer, then the new size is appended (compare-then-update), so an
  anomalous write never dilutes the baseline it is judged against. Defaults: `WindowSize 20`,
  `SigmaThreshold 3.0`, `MinSamples 5`; a zero-value config resolves to these.
- **Cold-start and zero-variance:** the first `MinSamples - 1` writes for a fresh key never flag,
  regardless of size spread (the buffer is still seeding). When every prior sample is identical
  (`stddev == 0`), any size other than the mean flags and a size equal to the mean does not.
- **Per-key, provenance-blind:** each key's buffer and statistics are fully independent (including the
  reserved shared and unbound marker keys, each an ordinary key here). The detector never consults
  `WriteContext.SourceClass`; only `Key` groups the baselines.
- **Additive, non-blocking (policy boundary):** the flag is additive on `flags` and never blocks: a
  write carrying only `size_anomaly_suspected` is still `{ "allow": true, "stored_id": "mem-…" }`,
  stored as usual. The `validate_write` shape stays byte-for-byte `{allow, stored_id, flags}`. Whether
  a size anomaly should block, quarantine, or escalate is a policy-engine decision, deferred to the
  future quarantine-outcome task (task 022). The fail-closed injection path is untouched: a rejected
  poisoned write never reaches the inspector, never carries the flag, and never enters the size
  baseline.
- **Bounded memory:** the per-key ring buffer holds at most `WindowSize` sizes, evicting the oldest at
  capacity, so one key's history cannot grow without bound. It is detection-internal working state, not
  part of the persisted `MemoryStore`, and not durable across a process restart.
- **Composition:** `CombineInspectors` fans one accepted write out to every wrapped inspector in order
  and returns the deduplicated, order-stable union of their flags, so `SizeAnomalyDetector` runs
  alongside `SelfReinforcementDetector` behind the single `WithWriteInspector` field.
- **Seam isolation:** the flag is produced entirely behind the `WriteInspector` seam; no implementation
  specifics appear in `guard.go`, `ipc.go`, or the contract, and `docs/CONTRACT.md` needs no edit (the
  `flags []string` shape already admits new string values).
  *(Tests: `TestTC001SizeCompareThenUpdate` through `TestTC011SizeSpecPropagation`, covering
  compare-then-update ordering, config defaults, the sigma boundary and zero-variance edge, cold-start,
  per-key isolation, the unchanged `validate_write` shape, `CombineInspectors` fan-out, disabled-by-default
  parity, and concurrency under `-race`.)*

---

> **v0 scope note.** The store is an in-memory map and the detector is regex; reads are now
> **identity-scoped** (ADR-004 / task 009 — a writer's entries are returned only under a matching
> attested identity, with an unbound-only fallback), via a **linear identity filter** (the durable form
> is a per-identity index behind the `MemoryStore` seam — deferred). Identity is **pre-verified
> upstream** (agent-mesh); in-guard SVID verification (`SvidVerifyingPrincipal`) is deferred behind the
> `Principal` seam. Audit emission is **opt-in and default-off** (ADR-007/ADR-014): the real
> `AuditTrailSink` speaks the confirmed audit-trail plain-event wire contract (internal OCSF translated
> at the sink boundary), wired via `serve --audit-socket`.
> These are stated facts about v0, tracked as limitations in [SPEC.md](SPEC.md) and
> [fitness-functions.md](fitness-functions.md), not behaviors to rely on as final.
</content>
