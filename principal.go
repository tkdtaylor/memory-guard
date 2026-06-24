// SPDX-License-Identifier: Apache-2.0
package main

import "strings"

// principal.go is the Principal seam (ADR-004) — the identity analogue of the
// Detector seam (detector.go) and the MemoryStore seam (store.go). It isolates
// "how an identity is obtained / verified" from "how it is bound at write and
// matched at read". The guard talks to an identity ONLY through this interface;
// no SPIFFE/X.509/Ed25519 specifics cross the seam into guard.go or ipc.go.
//
// ADR-004 decision: memory-guard receives a PRE-VERIFIED principal — agent-mesh
// owns SVID issuance + the fail-closed verification path and emits a trust_tier;
// the guard trusts the caller-supplied claim across the 0600 UID-gated socket
// (the trust boundary). Per-call X.509 verification is ruled out by the < 1 ms
// hot-path budget and would drag backend specifics into the substrate. The
// zero-trust variant (SvidVerifyingPrincipal — parse + verify an SVID + bundle
// in-process) is DEFERRED behind this same seam, additive, no guard change.

// Principal is the verified identity the guard binds at write and matches at read.
// It exposes exactly what the guard needs and nothing about how identity is carried
// or verified — the SPIFFE ID is the only thing that crosses into the guard.
type Principal interface {
	// Subject is the normalized identity key (the SPIFFE ID) the read path matches
	// EXACTLY against an entry's bound key. "" means no identity (the unbound case).
	Subject() string
	// Attested reports whether the principal was attested upstream (trust_tier ==
	// "attested"). Isolation is enforced ONLY when Attested() is true; an unattested
	// or absent principal hits the documented unbound-only fallback (REQ-005), never
	// a silent return-everything — fail-closed w.r.t. bound entries.
	Attested() bool
}

// attestedTier is the exact trust_tier value agent-mesh emits on a successful
// SVID chain → trust-bundle → URI-SAN → signature → replay verification. Any
// other value (""/"unattested"/unknown) is treated as NOT attested (fail-closed).
const attestedTier = "attested"

// PreVerifiedPrincipal is the v1-default Principal (ADR-004 option 1): it TRUSTS
// the caller-supplied, already-verified claim {spiffe_id, trust_tier}. It does NOT
// parse certificates — verification stays agent-mesh's job upstream of the socket.
type PreVerifiedPrincipal struct {
	spiffeID  string // the normalized SPIFFE ID; the match key
	trustTier string // "attested" when verified upstream; "" / "unattested" otherwise
}

// Subject returns the normalized SPIFFE ID (the match key).
func (p PreVerifiedPrincipal) Subject() string { return p.spiffeID }

// Attested reports trust_tier == "attested".
func (p PreVerifiedPrincipal) Attested() bool { return p.trustTier == attestedTier }

// principalFromMap parses the typed identity wire shape — {spiffe_id, trust_tier}
// (ADR-004) — out of the free-form map carried on validate_*. A nil/empty map, or a
// map with no spiffe_id, yields an unbound, unattested principal (Subject() == "",
// Attested() == false) — the REQ-005 fallback input. The SPIFFE ID is normalized
// (trimmed) so the match key is canonical; matching downstream is EXACT on this key.
//
// This is the ONLY place the typed identity shape is decoded; the guard sees only a
// Principal, so no wire/SPIFFE detail leaks past the seam.
func principalFromMap(identity map[string]any) Principal {
	spiffeID, _ := identity["spiffe_id"].(string)
	trustTier, _ := identity["trust_tier"].(string)
	return PreVerifiedPrincipal{
		spiffeID:  normalizeSubject(spiffeID),
		trustTier: strings.TrimSpace(trustTier),
	}
}

// normalizeSubject canonicalizes a SPIFFE ID into the stored/matched key. v1 trims
// surrounding whitespace only; matching is EXACT on the result (no substring/fuzzy,
// so "tenant-1" never matches "tenant-12"). A richer normalization (case folding of
// the host, default-port stripping) is a future concern kept local to this seam.
func normalizeSubject(spiffeID string) string {
	return strings.TrimSpace(spiffeID)
}

// unboundKey is the bound-identity key recorded for an entry written WITHOUT an
// attested identity (Subject() == "" or !Attested()). It is the marker the
// unbound-only read fallback (REQ-005) matches on — NOT a wildcard that matches
// every reader. An empty Subject() normalizes to this key, so the v0 demo
// (go run . write/read, which carries no identity) stays readable by identity-less
// reads while NEVER exposing an identity-bound entry to an unattested reader.
const unboundKey = ""

// boundKeyFor maps a principal to the identity key an entry written under it carries.
// An attested principal binds its Subject(); anything else binds the unbound marker.
// This is the producer half of the producer→consumer identity contract (the write
// site); scopedMatch is the consumer half (the read site) — both go through this
// single derivation so the key bound at write is exactly the key matched at read.
func boundKeyFor(p Principal) string {
	if p != nil && p.Attested() && p.Subject() != "" {
		return p.Subject()
	}
	return unboundKey
}

// readerVisibilityKey maps a reading principal to the single bound-identity key whose
// entries it may see, plus whether it is an attested (isolation-enforced) reader.
//   - attested reader  → (its Subject(), true): sees ONLY entries bound to that exact
//     subject (identity-scoped isolation, REQ-002/003).
//   - unattested/absent → (unboundKey, false): sees ONLY unbound (public/system)
//     entries (REQ-005 unbound-only fallback) — never an identity-bound entry,
//     never the whole store.
func readerVisibilityKey(p Principal) (key string, enforced bool) {
	if p != nil && p.Attested() && p.Subject() != "" {
		return p.Subject(), true
	}
	return unboundKey, false
}
