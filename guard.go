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
	store map[string]entry
}

type entry struct {
	content  string
	identity map[string]any
	flags    []string
}

func NewMemoryGuard(det Detector) *MemoryGuard {
	if det == nil {
		det = NewRegexDetector()
	}
	return &MemoryGuard{det: det, store: map[string]entry{}}
}

// ValidateWrite is the write-gate: flag poisoning (fail-closed), redact PII, then store.
func (g *MemoryGuard) ValidateWrite(text string, identity map[string]any) map[string]any {
	flags := g.det.DetectInjection(text)
	redacted, piiFlags := g.det.RedactPII(text)
	flags = append(flags, piiFlags...)

	if contains(flags, "injection_suspected") {
		// fail-closed on suspected context poisoning: do not store
		return map[string]any{"allow": false, "stored_id": nil, "flags": flags}
	}
	g.mu.Lock()
	id := "mem-" + randHex(6)
	g.store[id] = entry{content: redacted, identity: identity, flags: flags}
	g.mu.Unlock()
	return map[string]any{"allow": true, "stored_id": id, "flags": flagsOrEmpty(flags)}
}

// ValidateRead returns matching content with PII redacted (defense in depth).
func (g *MemoryGuard) ValidateRead(query string, identity map[string]any) map[string]any {
	g.mu.Lock()
	var hits []string
	for _, e := range g.store {
		if strings.Contains(e.content, query) {
			hits = append(hits, e.content)
		}
	}
	g.mu.Unlock()
	redacted, flags := g.det.RedactPII(strings.Join(hits, "\n"))
	return map[string]any{"allow": true, "content_redacted": redacted,
		"flags": flagsOrEmpty(flags)}
}

// VerifyDelete deletes an entry and PROVES it is gone (post-deletion verification — ADR-001 §5,
// ADR-003). It (1) removes the entry, (2) re-checks absence (the v0 proof), and (3) scans the
// REMAINING store for residue of the deleted content — a verbatim or near-verbatim fragment that
// survives in another entry (the documented industry gap a bare delete() misses). The residue
// scan is deterministic, stdlib-only guard-side orchestration (residue.go); it is NOT a Detector
// concern, so no detector backend specifics leak into it.
//
// Returns { confirmed, residue_detected, residue_summary?, deletion_hash }:
//   - confirmed       — the target id is gone (the v0 meaning, preserved). Deleting an absent id
//     still confirms gone (idempotent).
//   - residue_detected — a fragment of the deleted content survives elsewhere in the store.
//   - residue_summary  — present only when residue_detected; names the class + the surviving entry.
//   - deletion_hash    — deterministic SHA-256 over (id + deleted content) for audit-trail linkage.
func (g *MemoryGuard) VerifyDelete(id string) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()

	deleted, existed := g.store[id]
	delete(g.store, id)
	_, stillPresent := g.store[id]

	out := map[string]any{
		"confirmed":        !stillPresent,
		"residue_detected": false,
		"deletion_hash":    deletionHash(id, deleted.content),
	}

	// Residue is only meaningful for content that actually existed and was removed. Scanning the
	// SURVIVORS (the store after delete) means a deleted entry can never flag itself (no
	// self-residue false positive — the truth-table edge case).
	if existed {
		if detected, summary := residueScan(deleted.content, g.store); detected {
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
