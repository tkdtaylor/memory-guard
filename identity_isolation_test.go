// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

// identity_isolation_test.go — task 009: identity-scoped read isolation (ADR-004).
//
// TC coverage (009-identity-scoped-read-isolation-test-spec.md):
//   TC-001 — validate_write binds the writer's normalized verifiable identity (REQ-001)
//   TC-002 — validate_read returns an entry ONLY under a matching identity (REQ-002)
//   TC-003 — no cross-identity leakage: A's entry never reaches B (REQ-003, LOAD-BEARING)
//   TC-004 — whole-store substring read REPLACED by identity-scoped EXACT lookup (REQ-004)
//   TC-005 — no-identity read = unbound-only fallback, not return-everything (REQ-005)
//   TC-006 — PII redaction on read unchanged; no detector specifics in identity path (REQ-006)
//   (TC-007 is the ADR-004 ratification — a docs deliverable, not a Go test.)
//
// Identity fixtures are typed {spiffe_id, trust_tier} maps — the wire shape the IPC
// carries — decoded through the Principal seam exactly as the live path does.

// attestedIdentity builds the typed identity wire shape for an attested principal —
// the same map shape ipc.go pulls from req["identity"]. Using the wire shape (not a
// hand-constructed Principal) keeps the test on the LIVE decode path.
func attestedIdentity(spiffeID string) map[string]any {
	return map[string]any{"spiffe_id": spiffeID, "trust_tier": "attested"}
}

const (
	idA = "spiffe://example.org/agent/alice"
	idB = "spiffe://example.org/agent/bob"
)

// content_redacted asserts a read result and returns the joined redacted content.
func readContent(t *testing.T, out map[string]any) string {
	t.Helper()
	c, ok := out["content_redacted"].(string)
	if !ok {
		t.Fatalf("read result missing content_redacted: %v", out)
	}
	return c
}

// TC-001 — REQ-001: validate_write binds the writer's normalized identity key to the
// entry (a real bound key, not the inert map). Asserted via the observable read path:
// the attested writer can read its own entry back; an unbound reader cannot — which is
// only possible if a concrete, matchable key was bound at write.
func TestWriteBindsVerifiableIdentity(t *testing.T) {
	g := NewMemoryGuard(nil)
	w := g.ValidateWrite("alice's note", attestedIdentity(idA))
	if w["allow"] != true || w["stored_id"] == nil {
		t.Fatalf("expected stored write, got %v", w)
	}

	// The writer (same attested subject) sees the entry: the key bound at write matches.
	own := readContent(t, g.ValidateRead("note", attestedIdentity(idA)))
	if !strings.Contains(own, "alice's note") {
		t.Fatalf("writer should read its own bound entry, got %q", own)
	}

	// An unbound (no-identity) reader does NOT see it — proving the entry carries A's
	// bound key, not the unbound marker (the edge: a write with identity is NOT unbound).
	unbound := readContent(t, g.ValidateRead("note", nil))
	if strings.Contains(unbound, "alice's note") {
		t.Fatalf("identity-bound entry leaked to an unbound reader: %q", unbound)
	}
}

// TC-002 — REQ-002: validate_read returns an entry only under a matching identity.
func TestReadReturnsOnlyMatchingIdentity(t *testing.T) {
	g := NewMemoryGuard(nil)
	g.ValidateWrite("alice's note", attestedIdentity(idA))

	got := readContent(t, g.ValidateRead("note", attestedIdentity(idA)))
	if !strings.Contains(got, "alice's note") {
		t.Fatalf("identityA should see A's entry, got %q", got)
	}

	// identityB: the entry is EXCLUDED entirely (invisible, not merely redacted).
	none := readContent(t, g.ValidateRead("note", attestedIdentity(idB)))
	if strings.Contains(none, "alice's note") {
		t.Fatalf("identityB must not see A's entry, got %q", none)
	}
	if none != "" {
		t.Fatalf("identityB matching nothing should yield empty content, got %q", none)
	}
}

// TC-003 — REQ-003 (LOAD-BEARING): no cross-identity leakage. A and B both write
// content matching the SAME query substring; B must receive ONLY B's entry — A's is
// absent even though its content matches the query verbatim. Isolation holds BECAUSE
// of identity, not because the query failed to match.
func TestNoCrossIdentityLeakage(t *testing.T) {
	g := NewMemoryGuard(nil)
	g.ValidateWrite("shared keyword balance alice-secret", attestedIdentity(idA))
	g.ValidateWrite("shared keyword balance bob-secret", attestedIdentity(idB))

	// B reads: sees only B's entry; A's is absent.
	bView := readContent(t, g.ValidateRead("shared keyword", attestedIdentity(idB)))
	if !strings.Contains(bView, "bob-secret") {
		t.Fatalf("B must see its own entry, got %q", bView)
	}
	if strings.Contains(bView, "alice-secret") {
		t.Fatalf("LEAK: A's entry reached B despite matching the query: %q", bView)
	}

	// Symmetric: A reads, sees only A's entry.
	aView := readContent(t, g.ValidateRead("shared keyword", attestedIdentity(idA)))
	if !strings.Contains(aView, "alice-secret") {
		t.Fatalf("A must see its own entry, got %q", aView)
	}
	if strings.Contains(aView, "bob-secret") {
		t.Fatalf("LEAK: B's entry reached A despite matching the query: %q", aView)
	}

	// An attacker-supplied UNATTESTED identity (verification absent) matches NOTHING
	// bound — it must never fall through to the whole store.
	forged := map[string]any{"spiffe_id": idA, "trust_tier": "unattested"}
	atkView := readContent(t, g.ValidateRead("shared keyword", forged))
	if strings.Contains(atkView, "alice-secret") || strings.Contains(atkView, "bob-secret") {
		t.Fatalf("unattested forged identity must match no bound entry, got %q", atkView)
	}
}

// TC-004 — REQ-004: the whole-store substring read is replaced by an identity-scoped
// EXACT lookup. Same identity still returns the writer's matching entry (no happy-path
// regression); an identity key that is a SUBSTRING of another must NOT match.
func TestIdentityScopedLookupReplacesWholeStoreScan(t *testing.T) {
	g := NewMemoryGuard(nil)
	g.ValidateWrite("note one from A", attestedIdentity(idA))
	g.ValidateWrite("note two from A", attestedIdentity(idA))
	g.ValidateWrite("note one from B", attestedIdentity(idB))

	// Same identity returns A's matching entries only — happy path intact.
	aView := readContent(t, g.ValidateRead("note", attestedIdentity(idA)))
	if !strings.Contains(aView, "note one from A") || !strings.Contains(aView, "note two from A") {
		t.Fatalf("A should see both of its entries, got %q", aView)
	}
	if strings.Contains(aView, "from B") {
		t.Fatalf("A must not see B's entry, got %q", aView)
	}

	// Substring-of-another identity must NOT match (exact, no substring bleed):
	// tenant-1 vs tenant-12.
	g2 := NewMemoryGuard(nil)
	g2.ValidateWrite("tenant one data", attestedIdentity("spiffe://example.org/tenant-1"))
	sub := readContent(t, g2.ValidateRead("tenant", attestedIdentity("spiffe://example.org/tenant-12")))
	if strings.Contains(sub, "tenant one data") {
		t.Fatalf("substring identity bleed: tenant-12 saw tenant-1's entry: %q", sub)
	}
}

// TC-005 — REQ-005: no-identity / unattested read follows the UNBOUND-ONLY fallback —
// it returns ONLY entries written with no bound identity, NEVER an identity-bound entry,
// and in NO case returns every entry.
func TestNoIdentityReadIsUnboundOnly(t *testing.T) {
	g := NewMemoryGuard(nil)
	g.ValidateWrite("alice bound note", attestedIdentity(idA))
	g.ValidateWrite("bob bound note", attestedIdentity(idB))
	g.ValidateWrite("public unbound note", nil) // written with no identity → unbound

	// nil identity: sees ONLY the unbound entry.
	nilView := readContent(t, g.ValidateRead("note", nil))
	if !strings.Contains(nilView, "public unbound note") {
		t.Fatalf("unbound reader should see the unbound entry, got %q", nilView)
	}
	if strings.Contains(nilView, "alice bound note") || strings.Contains(nilView, "bob bound note") {
		t.Fatalf("UNBOUND-ONLY violated: a bound entry reached the no-identity reader: %q", nilView)
	}

	// empty-map identity is treated identically to nil (no spiffe_id → unbound).
	emptyView := readContent(t, g.ValidateRead("note", map[string]any{}))
	if emptyView != nilView {
		t.Fatalf("empty-map and nil identity must behave identically: %q vs %q", emptyView, nilView)
	}

	// An identity present but FAILING verification (unattested) is NOT treated as
	// "no identity that matches everything" — it matches the unbound set only, never
	// the bound entries (TC-005 edge / TC-003 edge).
	unattested := map[string]any{"spiffe_id": idA, "trust_tier": "unattested"}
	uView := readContent(t, g.ValidateRead("note", unattested))
	if strings.Contains(uView, "alice bound note") {
		t.Fatalf("unattested principal must not reach a bound entry, got %q", uView)
	}
	if !strings.Contains(uView, "public unbound note") {
		t.Fatalf("unattested principal should still see unbound entries, got %q", uView)
	}
}

// TC-006 — REQ-006: PII redaction on read is unchanged; it runs on whatever the
// identity-scoped set returns. An entry visible under the reader's identity but
// containing PII is still redacted — identity matching never bypasses redaction.
func TestPIIRedactionUnchangedUnderIdentityScoping(t *testing.T) {
	g := NewMemoryGuard(nil)
	g.ValidateWrite("call alice@example.com now", attestedIdentity(idA))

	out := g.ValidateRead("call", attestedIdentity(idA))
	content := readContent(t, out)
	if strings.Contains(content, "alice@example.com") {
		t.Fatalf("PII reached the identity-scoped read raw: %q", content)
	}
	if !strings.Contains(content, "<EMAIL>") {
		t.Fatalf("expected redacted <EMAIL> in scoped result, got %q", content)
	}
	// The stored content is already redacted at write (defense in depth), so the
	// read-time redaction over the identity-scoped set finds the <EMAIL> placeholder,
	// not raw PII — the key assertion is that no raw email survives the scoped read
	// (redaction runs on whatever the scoped lookup returns), which the checks above
	// establish. flags on read are non-nil ([] never null), the existing invariant.
	if out["flags"] == nil {
		t.Fatalf("flags must never be nil on a read, got nil")
	}
}

// TestPrincipalSeamSemantics pins the Principal seam's binding/matching contract
// directly: attested → Subject() is the bound/match key; unattested or empty → unbound.
func TestPrincipalSeamSemantics(t *testing.T) {
	att := principalFromMap(attestedIdentity(idA))
	if !att.Attested() || att.Subject() != idA {
		t.Fatalf("attested principal: want (%q, true), got (%q, %v)", idA, att.Subject(), att.Attested())
	}
	if boundKeyFor(att) != idA {
		t.Fatalf("attested write binds Subject(), got %q", boundKeyFor(att))
	}

	unatt := principalFromMap(map[string]any{"spiffe_id": idA, "trust_tier": "unattested"})
	if unatt.Attested() {
		t.Fatal("unattested principal must report Attested()==false")
	}
	if boundKeyFor(unatt) != unboundKey {
		t.Fatalf("unattested write binds the unbound marker, got %q", boundKeyFor(unatt))
	}

	none := principalFromMap(nil)
	if none.Subject() != "" || none.Attested() {
		t.Fatalf("nil identity → empty unattested principal, got (%q, %v)", none.Subject(), none.Attested())
	}
	if k, enforced := readerVisibilityKey(none); k != unboundKey || enforced {
		t.Fatalf("no-identity reader → (unbound, not-enforced), got (%q, %v)", k, enforced)
	}
}
