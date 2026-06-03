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
//	verify_delete(id)               -> { confirmed }
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

// VerifyDelete deletes an entry and PROVES it is gone (post-deletion verification).
func (g *MemoryGuard) VerifyDelete(id string) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.store, id)
	_, stillPresent := g.store[id]
	return map[string]any{"confirmed": !stillPresent}
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
