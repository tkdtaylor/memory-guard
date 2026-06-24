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
// Contract (interface-contracts.md §2):
//
//	validate_write(entry, identity) -> { allow, stored_id, flags }
//	validate_read(query, identity)  -> { allow, content_redacted, flags }
//	verify_delete(id)               -> { confirmed, residue_detected, residue_summary?, deletion_hash }
//
// The PII/injection detection lives behind the Detector seam (detector.go). The value-add
// the block OWNS is here: the write-gate (fail-closed on suspected poisoning) and
// post-deletion verification (prove an entry is actually gone — the industry gap).
type MemoryGuard struct {
	mu    sync.Mutex
	det   Detector
	store MemoryStore
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
	flags         []string
}

// NewMemoryGuard wires the guard with a Detector and (optionally) a MemoryStore. Both
// dependencies are pluggable seams: a nil Detector falls back to the v0 RegexDetector,
// and an omitted (or nil) store falls back to the default InMemoryStore — so the CLI /
// serve defaults are unchanged from v0. The store argument is variadic purely to keep
// the v0 single-argument call sites (NewMemoryGuard(nil), NewMemoryGuard(det))
// compiling unmodified; pass exactly one store to swap the backing (the one-line change
// that proves the seam, e.g. NewMemoryGuard(det, someStore) where someStore is any
// MemoryStore implementation — the concrete backings live behind the seam in store.go).
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
	return &MemoryGuard{det: det, store: s}
}

// ValidateWrite is the write-gate: flag poisoning (fail-closed), redact PII, then store.
//
// It also BINDS the writer's verifiable identity to the stored entry (ADR-004 /
// task 009): the typed identity ({spiffe_id, trust_tier}) is parsed through the
// Principal seam and the entry records the writer's normalized identity key
// (boundKeyFor — the attested Subject(), else the unbound marker). That key is what
// the read path matches EXACTLY against; the inert free-form map is no longer the
// basis for isolation. No SPIFFE/X.509 specifics enter here — only Principal.
func (g *MemoryGuard) ValidateWrite(text string, identity map[string]any) map[string]any {
	flags := g.det.DetectInjection(text)
	redacted, piiFlags := g.det.RedactPII(text)
	flags = append(flags, piiFlags...)

	if contains(flags, "injection_suspected") {
		// fail-closed on suspected context poisoning: do not store
		return map[string]any{"allow": false, "stored_id": nil, "flags": flags}
	}
	boundKey := boundKeyFor(principalFromMap(identity)) // producer: the identity bound at write
	g.mu.Lock()
	id := "mem-" + randHex(6)
	g.store.Put(id, entry{content: redacted, boundIdentity: boundKey, flags: flags})
	g.mu.Unlock()
	return map[string]any{"allow": true, "stored_id": id, "flags": flagsOrEmpty(flags)}
}

// ValidateRead returns matching content for the READER'S identity, with PII redacted
// (defense in depth). Identity is now LOAD-BEARING (ADR-004 / task 009): the whole-
// store substring scan is REPLACED by an identity-scoped lookup.
//
//   - An attested reader sees ONLY entries bound to its EXACT Subject() (no
//     substring/fuzzy on the identity — "tenant-1" never matches "tenant-12").
//   - An unattested or absent reader hits the unbound-only fallback (REQ-005): it
//     sees ONLY entries written with no bound identity (public/system entries) —
//     NEVER an identity-bound entry, NEVER the whole store. Fail-closed w.r.t. bound
//     entries, and it keeps the v0 identity-less demo working.
//
// Matching is guard-side orchestration through the Principal seam; PII redaction on
// the scoped result set is unchanged, and no detector specifics enter the identity path.
func (g *MemoryGuard) ValidateRead(query string, identity map[string]any) map[string]any {
	wantKey, _ := readerVisibilityKey(principalFromMap(identity)) // consumer: the key matched at read
	g.mu.Lock()
	var hits []string
	for _, e := range g.store.Scan(query) {
		if e.boundIdentity == wantKey { // EXACT identity match — the isolation gate
			hits = append(hits, e.content)
		}
	}
	g.mu.Unlock()
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

	out := map[string]any{
		"confirmed":        !stillPresent,
		"residue_detected": false,
		"deletion_hash":    deletionHash(id, deleted.content),
	}

	// Residue is only meaningful for content that actually existed and was removed. Scanning the
	// SURVIVORS across EVERY backing index/copy (the store after delete, via AllByIndex()) means a
	// deleted entry can never flag itself (no self-residue false positive — the truth-table edge
	// case), and a residue surviving only in a secondary index is caught and NAMED (task 008).
	if existed {
		if detected, summary := residueScanIndexes(deleted.content, g.store.AllByIndex()); detected {
			out["residue_detected"] = true
			out["residue_summary"] = summary
		}
	}
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
