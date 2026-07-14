// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
)

// MemoryGuard gates all agent memory I/O (ASI06).
//
// Contract (docs/CONTRACT.md):
//
//	validate_write(entry, identity) -> { allow, stored_id, flags }
//	validate_read(query, identity)  -> { allow, content_redacted, flags }
//	verify_delete(id)               -> { confirmed, residue_detected, residue_summary?, deletion_hash }
//
// The PII/injection detection lives behind the Detector seam (detector.go). The value-add
// the block OWNS is here: the write-gate (fail-closed on suspected poisoning) and
// post-deletion verification (prove an entry is actually gone — the industry gap).
//
// Audit emission (task 010 / ADR-007) is additive: every detection the guard already computes
// is ALSO emitted as an OCSF event through the AuditSink seam (audit.go). Emission is
// BEST-EFFORT and FAIL-OPEN — a down sink never blocks this path and never changes a verdict.
// The audit field is nil when emission is disabled (the default).
type MemoryGuard struct {
	mu    sync.Mutex
	det   Detector
	store MemoryStore
	audit AuditSink // nil = emission disabled (default); non-nil = emit on each detection
	// inspector is the opt-in behavioral WriteInspector seam (task 018 / ADR-016): a stateful
	// detector that sees the write's content plus backend-agnostic write metadata and returns
	// ADDITIVE, NON-BLOCKING flags. nil = seam disabled (default); a guard built without
	// WithWriteInspector is byte-for-byte behaviorally unchanged from pre-task. The guard holds
	// only the interface, never a concrete implementation, mirroring how it holds Detector and
	// MemoryStore.
	inspector WriteInspector
	// keyPolicy is the operator-configured named-key write-time policy (task 021 / ADR-017): the
	// glob-pattern lists for the flag-only Protected / Immutable checks. The zero value (empty
	// lists) still enforces the always-on reserved "memguard:" namespace fail-closed, so a guard
	// built without WithKeyPolicy still guards reserved keys. Set via WithKeyPolicy.
	keyPolicy KeyPolicy
	// baselines is the in-process immutable-baseline registry: a key -> namespaced-SHA-256 map
	// recording the first-seen redacted-content hash under each immutable-checked key (reserved or
	// configured). It is allocated in NewMemoryGuard and shared by reference across every builder
	// copy, so the baseline established on a guard survives builder chaining and every later write.
	// It is in-process only (lost on restart) — the durability limitation is documented in ADR-017,
	// mirroring the 009->016 identity-durability precedent. Access is guarded by mu.
	baselines map[string]string
}

type entry struct {
	content string
	// boundIdentity is the normalized identity key bound to this entry at write time
	// (the writer's Principal.Subject(), or unboundKey for an unattested/absent
	// writer). This is the load-bearing key the read path matches EXACTLY against —
	// it replaces the inert free-form identity map as the basis for isolation
	// (ADR-004). It is set ONLY in ValidateWrite via boundKeyFor; nothing else writes
	// it, so the bound-at-write key is exactly the matched-at-read key.
	boundIdentity string
	// sourceClass is the write's PROVENANCE tag (task 020 / ADR-015): one of
	// external_tool | user_input | agent_authored | system, or sourceClassUnknown for
	// absent/unrecognized input. It records WHERE a write came from, distinct from the
	// boundIdentity (WHO wrote it). It is set ONLY in ValidateWrite via sourceClassFromMap
	// at the SAME read of identity that binds boundIdentity, so the stored provenance and
	// the emitted audit event's provenance are provably the same decode. This is the field
	// a future behavioral detector (roadmap 018/019) keys on (e.g. sourceClass ==
	// "agent_authored" for self-reinforcement); this task tags and threads it, no policy
	// acts on it yet. Entries written before this task carry "" (Go zero value); consumers
	// must treat "" the same as sourceClassUnknown. It is NOT part of any validate_*
	// response, provenance is not an access-control key and never gates a read.
	sourceClass string
	flags       []string
}

// NewMemoryGuard wires the guard with a Detector and (optionally) a MemoryStore. Both
// dependencies are pluggable seams: a nil Detector falls back to the v0 RegexDetector,
// and an omitted (or nil) store falls back to the default InMemoryStore — so the CLI /
// serve defaults are unchanged from v0. The store argument is variadic purely to keep
// the v0 single-argument call sites (NewMemoryGuard(nil), NewMemoryGuard(det))
// compiling unmodified; pass exactly one store to swap the backing (the one-line change
// that proves the seam, e.g. NewMemoryGuard(det, someStore) where someStore is any
// MemoryStore implementation — the concrete backings live behind the seam in store.go).
//
// Audit emission (task 010): pass a non-nil AuditConfig to enable OCSF event emission.
// The zero-value (disabled) config is the default — call WithAudit to enable.
func NewMemoryGuard(det Detector, store ...MemoryStore) *MemoryGuard {
	if det == nil {
		det = NewRegexDetector()
	}
	var s MemoryStore
	if len(store) > 0 {
		s = store[0]
	}
	if s == nil {
		s = NewInMemoryStore()
	}
	return &MemoryGuard{det: det, store: s, baselines: map[string]string{}}
}

// WithAudit returns a copy of the guard with the given AuditSink wired in (immutable
// builder-style). An invalid config (nil sink, disabled) safely wires in nil (no emission).
// The original guard is unchanged. This is the injection point the tests use to swap sinks
// without rebuilding the guard from scratch.
func (g *MemoryGuard) WithAudit(cfg AuditConfig) *MemoryGuard {
	var sink AuditSink
	if cfg.isActive() {
		sink = cfg.Sink
	}
	return &MemoryGuard{det: g.det, store: g.store, audit: sink, inspector: g.inspector,
		keyPolicy: g.keyPolicy, baselines: g.baselines}
}

// WithWriteInspector returns a copy of the guard with the given behavioral WriteInspector wired
// in (immutable builder-style, mirroring WithAudit; task 018 / ADR-016). A nil inspector wires
// the seam OFF: a guard built without this call, or with nil, is behaviorally identical to
// pre-task, and no behavioral flag can ever appear in its flags. The original guard is
// unchanged. This is the injection point main.go's serve/write path and the tests use to wire the
// behavioral inspector; the guard holds only the WriteInspector interface, never the concrete
// implementation, so no behavioral-backend specifics leak past the seam.
func (g *MemoryGuard) WithWriteInspector(wi WriteInspector) *MemoryGuard {
	return &MemoryGuard{det: g.det, store: g.store, audit: g.audit, inspector: wi,
		keyPolicy: g.keyPolicy, baselines: g.baselines}
}

// WithKeyPolicy returns a copy of the guard with the given named-key write-time policy wired in
// (immutable builder-style, mirroring WithAudit / WithWriteInspector; task 021 / ADR-017). The
// zero-value KeyPolicy (empty pattern lists) still enforces the always-on reserved "memguard:"
// namespace fail-closed, so even NewMemoryGuard(det).WithKeyPolicy(KeyPolicy{}) guards reserved
// keys. It preserves every other already-set field (audit sink, inspector, the shared baseline
// registry), so it composes with WithAudit and WithWriteInspector in ANY call order without
// clobbering them. The original guard is unchanged. This is main.go's serve-path injection point
// for the MEMGUARD_PROTECTED_KEYS / MEMGUARD_IMMUTABLE_KEYS configuration.
func (g *MemoryGuard) WithKeyPolicy(policy KeyPolicy) *MemoryGuard {
	baselines := g.baselines
	if baselines == nil {
		baselines = map[string]string{}
	}
	return &MemoryGuard{det: g.det, store: g.store, audit: g.audit, inspector: g.inspector,
		keyPolicy: policy, baselines: baselines}
}

// ValidateWrite is the write-gate: flag poisoning (fail-closed), redact PII, then store.
//
// It also BINDS the writer's verifiable identity to the stored entry (ADR-004 /
// task 009): the typed identity ({spiffe_id, trust_tier}) is parsed through the
// Principal seam and the entry records the writer's normalized identity key
// (boundKeyFor — the attested Subject(), else the unbound marker). That key is what
// the read path matches EXACTLY against; the inert free-form map is no longer the
// basis for isolation. No SPIFFE/X.509 specifics enter here — only Principal.
// The optional variadic key is a caller-supplied logical slot name (task 021 / ADR-017) used ONLY
// to run the named-key write-time policy; it is NOT persisted on the entry, not part of the store,
// and not readable back by key. The variadic form keeps every pre-021 2-arg call site
// (g.ValidateWrite(text, identity)) compiling and behaving byte-identically: an omitted key (or an
// empty-string key) matches no reserved or configured pattern and runs zero key-policy logic.
func (g *MemoryGuard) ValidateWrite(text string, identity map[string]any, key ...string) map[string]any {
	flags := g.det.DetectInjection(text)
	redacted, piiFlags := g.det.RedactPII(text)
	flags = append(flags, piiFlags...)

	// Decode the write's provenance ONCE, here, from the same identity map that binds the
	// writer's key below. This single value is threaded to BOTH the stored entry and every
	// emitted audit event (rejected or accepted), so the store and the audit trail agree on
	// where the write came from, value-for-value. This sourceClassFromMap call is the ONLY
	// provenance decode on the write path; the guard never reads the raw key a second time
	// (task 020 / ADR-015).
	srcClass := sourceClassFromMap(identity)

	if contains(flags, "injection_suspected") {
		// fail-closed on suspected context poisoning: do not store.
		// Emit the injection-rejection event AFTER the verdict is computed — the sink
		// failure never changes the verdict (fail-open for the sink, fail-closed for the gate).
		// The provenance still rides the event even though nothing persists.
		emitSafe(g.audit, BuildInjectionRejectedEvent(flags, srcClass))
		return map[string]any{"allow": false, "stored_id": nil, "flags": flags}
	}
	p := principalFromMap(identity)
	boundKey := boundKeyFor(p) // producer: the identity bound at write

	// Named-key write-time policy (task 021 / ADR-017). This runs AFTER the injection gate (so a
	// poisoned write is already rejected and never reaches here — REQ-009) and BEFORE storage. A
	// reserved "memguard:" key violation is FAIL-CLOSED (reject, nothing stored); an
	// operator-configured pattern violation is FLAG-ONLY (allow, flag added). The key is used only
	// for policy: it is never persisted on the entry. An absent/empty key matches nothing and runs
	// zero key-policy logic, so pre-021 2-arg call sites are byte-identical.
	if writeKey := firstKey(key); writeKey != "" {
		policyFlags, reject := g.evaluateKeyPolicy(writeKey, redacted, p.Attested())
		flags = append(flags, policyFlags...)
		if reject {
			// fail-closed on a reserved-key violation: do not store, mint no id.
			return map[string]any{"allow": false, "stored_id": nil, "flags": flags}
		}
	}

	// Behavioral inspection (task 018 / ADR-016): the opt-in WriteInspector sees the write's
	// content plus backend-agnostic write metadata (the writer's bound key + the raw source-class
	// hint). Its flags are ADDITIVE and NON-BLOCKING (fail-open): a behavioral finding is appended
	// to flags but never changes allow / stored_id. This runs ONLY on the accepted path, after the
	// injection gate, so the fail-closed injection invariant is untouched. The seam is nil by default
	// (behavior unchanged). This is the single behavioral-seam call site; the concrete inspector
	// stays behind the WriteInspector interface. writeProvenanceHint is the raw source-class hint
	// (distinct concern from srcClass above, which is the normalized provenance the entry and audit
	// event record); both read the same immutable key, so they cannot drift (ADR-016 §4).
	if g.inspector != nil {
		flags = append(flags, g.inspector.Inspect(text, WriteContext{Key: boundKey, SourceClass: writeProvenanceHint(identity)})...)
	}

	g.mu.Lock()
	id := "mem-" + randHex(6)
	g.store.Put(id, entry{content: redacted, boundIdentity: boundKey, sourceClass: srcClass, flags: flags})
	g.mu.Unlock()

	// Emit a PII-redaction event only when PII was actually found (non-empty piiFlags).
	// A benign write with no flags emits nothing (no fabricated event — deterministic).
	// The event is built from the already-computed flags and the opaque stored_id only:
	// the raw text and the redacted content NEVER enter the event (REQ-004).
	if len(piiFlags) > 0 {
		emitSafe(g.audit, BuildPIIRedactionEvent(flags, id, srcClass))
	}

	return map[string]any{"allow": true, "stored_id": id, "flags": flagsOrEmpty(flags)}
}

// ValidateRead returns matching content for the READER'S identity, with PII redacted
// (defense in depth). Identity is LOAD-BEARING (ADR-004 / task 009); the scoping is now
// pushed into the store as a single ScanScoped call over the reader's visible-key set
// (ADR-013), replacing the guard-side filter loop over Scan.
//
//   - An attested reader's visible keys are {Subject(), sharedScopeKey}: it sees ONLY
//     entries bound to its EXACT Subject() plus shared-scope entries (no substring/fuzzy
//     on the identity — "tenant-1" never matches "tenant-12").
//   - An unattested or absent reader's visible keys are {unboundKey, sharedScopeKey}: it
//     sees ONLY unbound (public/system) entries plus shared entries — NEVER an
//     identity-bound entry, NEVER the whole store. Fail-closed w.r.t. bound entries, and
//     it keeps the v0 identity-less demo working.
//
// Deriving the visible-key set is the only policy site; the store enforces exact
// membership. PII redaction on the scoped result set is unchanged, and no detector
// specifics enter the identity path. The read path ignores any scope on the identity.
func (g *MemoryGuard) ValidateRead(query string, identity map[string]any) map[string]any {
	wantKey, _ := readerVisibilityKey(principalFromMap(identity)) // consumer: the key matched at read
	visibleKeys := []string{wantKey, sharedScopeKey}              // + shared: readable by every class
	g.mu.Lock()
	scoped := g.store.ScanScoped(query, visibleKeys) // store-side identity scoping (ADR-013)
	g.mu.Unlock()
	hits := make([]string, 0, len(scoped))
	for _, e := range scoped {
		hits = append(hits, e.content)
	}
	redacted, flags := g.det.RedactPII(strings.Join(hits, "\n"))
	return map[string]any{"allow": true, "content_redacted": redacted,
		"flags": flagsOrEmpty(flags)}
}

// VerifyDelete deletes an entry and PROVES it is gone (post-deletion verification — ADR-001 §5,
// ADR-003, ADR-006). It (1) removes the entry, (2) re-checks absence (the v0 proof), and (3) scans
// EVERY backing index/copy of the REMAINING store for residue of the deleted content — a verbatim
// or near-verbatim fragment that survives in another entry, in any index (the documented industry
// gap a bare delete() misses). The residue scan is deterministic, stdlib-only guard-side
// orchestration (residue.go); it is NOT a Detector concern, so no detector backend specifics leak
// into it, and it reaches the store only through the seam's AllByIndex().
//
// Returns { confirmed, residue_detected, residue_summary?, deletion_hash }:
//   - confirmed       — the target id is gone (the v0 meaning, preserved). Deleting an absent id
//     still confirms gone (idempotent).
//   - residue_detected — a fragment of the deleted content survives elsewhere, in ANY backing index.
//   - residue_summary  — present only when residue_detected; names the class, the BACKING INDEX the
//     residue survives in, and the surviving entry.
//   - deletion_hash    — deterministic SHA-256 over (id + deleted content) for audit-trail linkage,
//     independent of index layout.
func (g *MemoryGuard) VerifyDelete(id string) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Read the entry (and whether it existed) BEFORE deleting so the residue scan has the
	// deleted content, then prove absence with a FRESH post-delete Get — not the Delete
	// return value (the industry gap: a bare delete() that is never re-checked).
	deleted, existed := g.store.Get(id)
	g.store.Delete(id)
	_, stillPresent := g.store.Get(id)

	hash := deletionHash(id, deleted.content)
	out := map[string]any{
		"confirmed":        !stillPresent,
		"residue_detected": false,
		"deletion_hash":    hash,
	}

	// Residue is only meaningful for content that actually existed and was removed. Scanning the
	// SURVIVORS across EVERY backing index/copy (the store after delete, via AllByIndex()) means a
	// deleted entry can never flag itself (no self-residue false positive — the truth-table edge
	// case), and a residue surviving only in a secondary index is caught and NAMED (task 008).
	residueDetected := false
	var residueFlags []string
	if existed {
		if detected, summary := residueScanIndexes(deleted.content, g.store.AllByIndex()); detected {
			out["residue_detected"] = true
			out["residue_summary"] = summary
			residueDetected = true
			residueFlags = []string{"residue_detected"}
		}
	}

	// Emit a deletion/residue event AFTER the verdict map is fully computed.
	// The event carries ONLY the deletion_hash (audit linkage) and the residue flag —
	// NEVER the raw deleted content (REQ-004). A failing sink NEVER changes the verdict.
	emitSafe(g.audit, BuildDeletionEvent(hash, residueDetected, residueFlags))

	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func flagsOrEmpty(flags []string) []string {
	if flags == nil {
		return []string{}
	}
	return flags
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
