// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// identity_durable_test.go — task 016 / test-spec 016.
//
// Covers the remaining T4 deltas on top of task 009's shipped exact-string isolation
// (identity_isolation_test.go stays green unmodified, the regression fence TC-006):
//   TC-001 — ScanScoped returns exactly the visible-key matches, per adapter (REQ-001)
//   TC-002 — ValidateRead goes through ScanScoped, not guard-side filtering (REQ-002)
//   TC-003 — shared scope: attested-writer-only publish, readable by everyone (REQ-003)
//   TC-004 — the reserved shared marker cannot be forged via spiffe_id (REQ-004)
//   TC-005 — isolation survives restart on the persisted FileStore (REQ-005)
//   TC-007 — PII redaction unchanged over every scope class (REQ-006)
// Every negative is a set/substring assertion, never a "result is non-empty" smoke check.

const (
	spiffeAlpha = "spiffe://secure-agents/agent/alpha"
	spiffeBeta  = "spiffe://secure-agents/agent/beta"
)

// attestedShared builds an attested identity requesting the shared publish scope.
func attestedShared(spiffe string) map[string]any {
	return map[string]any{"spiffe_id": spiffe, "trust_tier": "attested", "scope": sharedScopeValue}
}

// unattestedID builds an identity that failed attestation upstream.
func unattestedID(spiffe string) map[string]any {
	return map[string]any{"spiffe_id": spiffe, "trust_tier": "unattested"}
}

// contentSet returns the set of entry contents (order-free comparison).
func contentSet(entries []entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		out[e.content] = true
	}
	return out
}

func sameSet(a map[string]bool, want ...string) bool {
	if len(a) != len(want) {
		return false
	}
	for _, w := range want {
		if !a[w] {
			return false
		}
	}
	return true
}

// TC-001: the scoped seam verb returns exactly the visible-key matches, per adapter.
func TestScanScopedExactMembershipPerAdapter(t *testing.T) {
	for name, mk := range allStores(t) {
		mk := mk
		t.Run(name, func(t *testing.T) {
			s := mk()
			s.Put("mem-1", entry{content: "memo alpha-private", boundIdentity: spiffeAlpha})
			s.Put("mem-2", entry{content: "memo beta-private", boundIdentity: spiffeBeta})
			s.Put("mem-3", entry{content: "memo broadcast", boundIdentity: sharedScopeKey})
			s.Put("mem-4", entry{content: "memo public", boundIdentity: unboundKey})

			// Call 1: alpha's subject + shared → {alpha-private, broadcast}, exactly 2.
			c1 := contentSet(s.ScanScoped("memo", []string{spiffeAlpha, sharedScopeKey}))
			if !sameSet(c1, "memo alpha-private", "memo broadcast") {
				t.Fatalf("%s: call 1 want {alpha-private, broadcast}, got %v", name, c1)
			}
			// Call 2: {unbound} → exactly {public}.
			c2 := contentSet(s.ScanScoped("memo", []string{unboundKey}))
			if !sameSet(c2, "memo public") {
				t.Fatalf("%s: call 2 want {public}, got %v", name, c2)
			}
			// Call 3: query matches alpha-private's content but the key filter wins → empty.
			c3 := s.ScanScoped("alpha", []string{spiffeBeta})
			if len(c3) != 0 {
				t.Fatalf("%s: call 3 must be empty (key filter wins over content), got %v", name, c3)
			}
			// Edge: empty visibleKeys → empty (never a fallback to unscoped).
			if got := s.ScanScoped("memo", nil); len(got) != 0 {
				t.Fatalf("%s: empty visibleKeys must yield empty, got %v", name, got)
			}
			// Edge: ScanScoped("", keys) matches every VISIBLE entry (empty-substring).
			cAll := contentSet(s.ScanScoped("", []string{spiffeAlpha, sharedScopeKey}))
			if !sameSet(cAll, "memo alpha-private", "memo broadcast") {
				t.Fatalf("%s: empty query must match every visible entry, got %v", name, cAll)
			}
			// Edge: exact membership — spiffeAlpha never matches a longer key.
			if got := s.ScanScoped("memo", []string{spiffeAlpha + "2"}); len(got) != 0 {
				t.Fatalf("%s: key membership must be EXACT, got %v", name, got)
			}
		})
	}
}

// spyStore counts which seam verb the read path uses (the dead-wire trap: the new verb
// EXISTING is not enough — the live ValidateRead line must call it). scanScopedBlackhole
// is the mutation probe: force ScanScoped to return nothing and assert the read goes empty.
type spyStore struct {
	inner               MemoryStore
	scanCalls           int
	scanScopedCalls     int
	lastVisibleKeys     []string
	scanScopedBlackhole bool
}

func newSpyStore() *spyStore { return &spyStore{inner: NewInMemoryStore()} }

func (s *spyStore) Put(id string, e entry)     { s.inner.Put(id, e) }
func (s *spyStore) Get(id string) (entry, bool) { return s.inner.Get(id) }
func (s *spyStore) Delete(id string)           { s.inner.Delete(id) }
func (s *spyStore) All() []entry               { return s.inner.All() }
func (s *spyStore) AllByIndex() map[string][]entry { return s.inner.AllByIndex() }

func (s *spyStore) Scan(query string) []entry {
	s.scanCalls++
	return s.inner.Scan(query)
}

func (s *spyStore) ScanScoped(query string, visibleKeys []string) []entry {
	s.scanScopedCalls++
	s.lastVisibleKeys = append([]string(nil), visibleKeys...)
	if s.scanScopedBlackhole {
		return nil
	}
	return s.inner.ScanScoped(query, visibleKeys)
}

// TC-002: ValidateRead goes through ScanScoped, not guard-side filtering.
func TestValidateReadUsesScanScoped(t *testing.T) {
	spy := newSpyStore()
	g := NewMemoryGuard(NewNativeDetector(), spy)
	g.ValidateWrite("memo alpha-private", attestedIdentity(spiffeAlpha)) // Put only, no scan

	out := g.ValidateRead("memo", attestedIdentity(spiffeAlpha))

	if spy.scanScopedCalls != 1 {
		t.Fatalf("ValidateRead must call ScanScoped exactly once, got %d", spy.scanScopedCalls)
	}
	if spy.scanCalls != 0 {
		t.Fatalf("ValidateRead must NOT call Scan (guard-side filter removed), got %d", spy.scanCalls)
	}
	if !sortedEqual(spy.lastVisibleKeys, []string{spiffeAlpha, sharedScopeKey}) {
		t.Fatalf("visible keys must be {A's subject, sharedScopeKey}, got %v", spy.lastVisibleKeys)
	}
	// Verdict shape unchanged.
	if out["allow"] != true {
		t.Fatalf("allow must be true, got %v", out)
	}
	if _, ok := out["content_redacted"].(string); !ok {
		t.Fatalf("content_redacted must be a string, got %v", out["content_redacted"])
	}
	if _, ok := out["flags"].([]string); !ok {
		t.Fatalf("flags must be []string, got %v", out["flags"])
	}
	if !strings.Contains(out["content_redacted"].(string), "alpha-private") {
		t.Fatalf("attested reader must see its own entry, got %q", out["content_redacted"])
	}

	// Edge: an unattested reader triggers ScanScoped with {unboundKey, sharedScopeKey}.
	spy.scanScopedCalls = 0
	g.ValidateRead("memo", unattestedID(spiffeAlpha))
	if !sortedEqual(spy.lastVisibleKeys, []string{unboundKey, sharedScopeKey}) {
		t.Fatalf("unattested reader keys must be {unbound, shared}, got %v", spy.lastVisibleKeys)
	}

	// Mutation probe: force ScanScoped to return nothing → the read result must go empty,
	// proving the live ValidateRead consumes ScanScoped's return (not a dead wire).
	spy.scanScopedBlackhole = true
	mutated := g.ValidateRead("memo", attestedIdentity(spiffeAlpha))
	if c := mutated["content_redacted"].(string); c != "" {
		t.Fatalf("black-holed ScanScoped must yield empty read, got %q", c)
	}
}

func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// seedSharedCorpus writes the four-entry visibility corpus through the guard and returns it.
func seedSharedCorpus(t *testing.T, g *MemoryGuard) {
	t.Helper()
	g.ValidateWrite("memo alpha-private", attestedIdentity(spiffeAlpha))
	g.ValidateWrite("memo beta-private", attestedIdentity(spiffeBeta))
	g.ValidateWrite("memo broadcast", attestedShared(spiffeAlpha))
	g.ValidateWrite("memo public", nil)
}

// TC-003: shared scope is writable by attested writers only, readable by everyone.
func TestSharedScopeVisibilityMatrix(t *testing.T) {
	for name, mk := range allStores(t) {
		mk := mk
		t.Run(name, func(t *testing.T) {
			g := NewMemoryGuard(NewNativeDetector(), mk())
			seedSharedCorpus(t, g)

			assertRead := func(id map[string]any, wantSubs, notSubs []string) {
				t.Helper()
				c := g.ValidateRead("memo", id)["content_redacted"].(string)
				for _, w := range wantSubs {
					if !strings.Contains(c, w) {
						t.Fatalf("%s: reader %v must see %q, got %q", name, id, w, c)
					}
				}
				for _, n := range notSubs {
					if strings.Contains(c, n) {
						t.Fatalf("%s: reader %v must NOT see %q, got %q", name, id, n, c)
					}
				}
			}

			// idA → alpha-private + broadcast; never beta-private, never public.
			assertRead(attestedIdentity(spiffeAlpha),
				[]string{"alpha-private", "broadcast"}, []string{"beta-private", "public"})
			// idB → beta-private + broadcast only.
			assertRead(attestedIdentity(spiffeBeta),
				[]string{"beta-private", "broadcast"}, []string{"alpha-private", "public"})
			// idUnattested + nil → public + broadcast only (attested-only bound entries hidden).
			assertRead(unattestedID(spiffeAlpha),
				[]string{"public", "broadcast"}, []string{"alpha-private", "beta-private"})
			assertRead(nil,
				[]string{"public", "broadcast"}, []string{"alpha-private", "beta-private"})

			// Edge: an UNATTESTED writer requesting shared binds UNBOUND, not shared —
			// visible to nil/unattested, invisible to idA/idB (no privilege escalation).
			g.ValidateWrite("memo sneak", map[string]any{
				"spiffe_id": spiffeAlpha, "trust_tier": "unattested", "scope": sharedScopeValue})
			assertRead(nil, []string{"sneak"}, nil)
			assertRead(attestedIdentity(spiffeBeta), nil, []string{"sneak"})
			assertRead(attestedIdentity(spiffeAlpha), nil, []string{"sneak"})

			// Edge: an unknown scope value is ignored (binds normally to the writer's subject).
			g.ValidateWrite("memo teamnote", map[string]any{
				"spiffe_id": spiffeBeta, "trust_tier": "attested", "scope": "team"})
			assertRead(attestedIdentity(spiffeBeta), []string{"teamnote"}, nil) // B sees its own
			assertRead(attestedIdentity(spiffeAlpha), nil, []string{"teamnote"}) // A does not
			assertRead(nil, nil, []string{"teamnote"})                          // nor unbound
		})
	}
}

// TC-004: the reserved shared marker cannot be forged via spiffe_id.
func TestSharedMarkerCannotBeForged(t *testing.T) {
	for name, mk := range allStores(t) {
		mk := mk
		t.Run(name, func(t *testing.T) {
			g := NewMemoryGuard(NewNativeDetector(), mk())
			// Attested writer whose spiffe_id IS the reserved marker, with NO scope:"shared".
			forged := map[string]any{"spiffe_id": sharedScopeKey, "trust_tier": "attested"}
			g.ValidateWrite("memo forged-broadcast", forged)

			// The entry bound UNBOUND (boundKeyFor neutralized the marker subject): idA does
			// not see it; the unbound reader does.
			aView := g.ValidateRead("memo", attestedIdentity(spiffeAlpha))["content_redacted"].(string)
			if strings.Contains(aView, "forged-broadcast") {
				t.Fatalf("%s: forged marker reached an attested tenant: %q", name, aView)
			}
			nilView := g.ValidateRead("memo", nil)["content_redacted"].(string)
			if !strings.Contains(nilView, "forged-broadcast") {
				t.Fatalf("%s: forged-marker entry must land in the unbound namespace, got %q", name, nilView)
			}

			// Edge: tenant-1 vs tenant-12 exactness through the scoped path.
			g2 := NewMemoryGuard(NewNativeDetector(), mk())
			g2.ValidateWrite("memo tenant-one-data", attestedIdentity("spiffe://secure-agents/tenant-1"))
			cross := g2.ValidateRead("memo", attestedIdentity("spiffe://secure-agents/tenant-12"))["content_redacted"].(string)
			if strings.Contains(cross, "tenant-one-data") {
				t.Fatalf("%s: tenant-12 saw tenant-1's entry (substring bleed): %q", name, cross)
			}
		})
	}
}

// TC-005: isolation survives restart on the persisted store (FileStore only).
func TestDurableIsolationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.jsonl")
	g1 := NewMemoryGuard(NewNativeDetector(), mustFileStore(t, path))
	seedSharedCorpus(t, g1)

	// POSITIVE control: the binding really persisted (guards against a store that drops
	// boundIdentity and passes vacuously by returning nothing to anyone).
	fileBytes, _ := os.ReadFile(path)
	if !strings.Contains(string(fileBytes), spiffeAlpha) {
		t.Fatalf("positive control: alpha's binding must be on disk, file=%s", fileBytes)
	}

	// Drop g1; construct g2 over a NEW FileStore on the same path (simulated restart).
	g2 := NewMemoryGuard(NewNativeDetector(), mustFileStore(t, path))

	aView := g2.ValidateRead("memo", attestedIdentity(spiffeAlpha))["content_redacted"].(string)
	bView := g2.ValidateRead("memo", attestedIdentity(spiffeBeta))["content_redacted"].(string)
	nilView := g2.ValidateRead("memo", nil)["content_redacted"].(string)

	if !strings.Contains(aView, "alpha-private") || !strings.Contains(aView, "broadcast") {
		t.Fatalf("restart: A must see {alpha-private, broadcast}, got %q", aView)
	}
	if !strings.Contains(bView, "beta-private") || !strings.Contains(bView, "broadcast") {
		t.Fatalf("restart: B must see {beta-private, broadcast}, got %q", bView)
	}
	if !strings.Contains(nilView, "public") || !strings.Contains(nilView, "broadcast") {
		t.Fatalf("restart: nil must see {public, broadcast}, got %q", nilView)
	}
	// The load-bearing negative: A's entry is unreadable by B ACROSS process lifetimes.
	if strings.Contains(bView, "alpha-private") {
		t.Fatalf("restart LEAK: B read A's entry across a restart: %q", bView)
	}

	// Edge: verify_delete of A's entry through g2 removes it from A's read and the file bytes.
	// Find A's stored id by writing a fresh marker we can delete deterministically.
	idA2 := g2.ValidateWrite("memo alpha-erasable veloheliotrope", attestedIdentity(spiffeAlpha))["stored_id"].(string)
	if !strings.Contains(g2.ValidateRead("memo", attestedIdentity(spiffeAlpha))["content_redacted"].(string), "veloheliotrope") {
		t.Fatalf("restart: A must first see its erasable entry")
	}
	g2.VerifyDelete(idA2)
	if strings.Contains(g2.ValidateRead("memo", attestedIdentity(spiffeAlpha))["content_redacted"].(string), "veloheliotrope") {
		t.Fatalf("restart: deleted entry still visible to A")
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "veloheliotrope") {
		t.Fatalf("restart: deleted entry bytes still on disk: %s", b)
	}
}

// TC-007: PII redaction unchanged over every scope class.
func TestPIIRedactionOverScopeClasses(t *testing.T) {
	for name, mk := range allStores(t) {
		mk := mk
		t.Run(name, func(t *testing.T) {
			g := NewMemoryGuard(NewNativeDetector(), mk())
			g.ValidateWrite("reach me at carol@example.com about the merger", attestedShared(spiffeAlpha)) // shared
			g.ValidateWrite("call dana@example.com re: alpha", attestedIdentity(spiffeAlpha))              // bound A

			for _, id := range []map[string]any{
				attestedIdentity(spiffeAlpha), attestedIdentity(spiffeBeta), nil,
			} {
				for _, q := range []string{"about", "re:"} {
					c := g.ValidateRead(q, id)["content_redacted"].(string)
					if strings.Contains(c, "carol@example.com") || strings.Contains(c, "dana@example.com") {
						t.Fatalf("%s: raw PII reached reader %v: %q", name, id, c)
					}
				}
			}
			// Visibility still follows TC-003: only idA sees the dana (bound) entry.
			aMerger := g.ValidateRead("re:", attestedIdentity(spiffeAlpha))["content_redacted"].(string)
			if !strings.Contains(aMerger, "<EMAIL>") {
				t.Fatalf("%s: A must see the redacted dana entry, got %q", name, aMerger)
			}
			bMerger := g.ValidateRead("re:", attestedIdentity(spiffeBeta))["content_redacted"].(string)
			if strings.Contains(bMerger, "alpha") {
				t.Fatalf("%s: B must not see A's bound dana entry, got %q", name, bMerger)
			}
		})
	}
}
