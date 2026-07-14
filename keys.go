// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// keys.go — the named-key write-time policy (task 021 / ADR-017).
//
// validate_write gains an OPTIONAL logical `key` (a caller-supplied slot name such as
// "memguard:detector-config" or "persona:system-prompt"). The key is used ONLY to run two
// composable write-time checks; it is NOT persisted on entry, not part of MemoryStore, and
// not readable back by key (no ValidateReadByKey). Everything here is guard-side orchestration,
// stdlib-only (path.Match, crypto/sha256): it introduces no detector/store/identity backend
// specifics, so the Detector / MemoryStore / Principal seams stay clean.
//
// Two-tier ownership (ADR-017):
//
//   - Reserved system keys — the hard-coded, non-configurable prefix "memguard:" — are the
//     guard's OWN state and are enforced FAIL-CLOSED: an unattested/absent writer to a reserved
//     key is REJECTED (protected_key_violation), and a later write whose redacted content drifts
//     from the established baseline is REJECTED (immutable_mismatch). Nothing is stored on either
//     rejection. This is the same posture the write-gate already takes on suspected injection.
//   - Operator-configured keys — KeyPolicy.Protected / KeyPolicy.Immutable glob patterns sourced
//     from MEMGUARD_PROTECTED_KEYS / MEMGUARD_IMMUTABLE_KEYS — are FLAG-ONLY: the same violations
//     add the flag but ALLOW the write through (allow:true, stored_id set). The broader
//     allow/redact/block policy for the general case stays policy-engine's job; memory-guard's
//     contribution is detection plus a stable flag, not enforcement.
//
// Reserved-key status takes precedence: a key matching both the reserved prefix and an operator
// pattern uses reserved (fail-closed) semantics only, never both a reject and a flag.

// reservedKeyPrefix is the hard-coded, non-configurable prefix that marks a key as the guard's
// OWN reserved system slot. It cannot be disabled or reconfigured via env. Matching is a PREFIX
// match, not a substring match: "user-memguard:note" is NOT reserved.
const reservedKeyPrefix = "memguard:"

// The two additive flag values this task introduces. They are new VALUES inside the existing
// validate_write flags array (exactly like injection_suspected / pii:<LABEL>), never new
// top-level response fields — the {allow, stored_id, flags} shape is unchanged.
const (
	protectedKeyViolationFlag = "protected_key_violation"
	immutableMismatchFlag     = "immutable_mismatch"
)

// KeyPolicy holds the operator-configured glob-pattern lists for the two flag-only checks. The
// reserved namespace is always active independently of this policy, so a zero-value KeyPolicy
// (empty lists) still enforces the reserved "memguard:" prefix fail-closed.
type KeyPolicy struct {
	// Protected patterns mark keys whose write requires an attested writer; an unattested/absent
	// writer to a matching key is flagged protected_key_violation (allowed through).
	Protected []string
	// Immutable patterns mark keys whose first-written value is baselined; a later write under a
	// matching key whose redacted content hashes differently is flagged immutable_mismatch
	// (allowed through, baseline pinned to the first value).
	Immutable []string
}

// firstKey extracts the caller-supplied logical key from ValidateWrite's variadic key parameter,
// returning "" when no key was passed (the pre-021 2-arg call). Only the first element is honored;
// the variadic form exists purely to keep the 2-arg call sites source-compatible.
func firstKey(key []string) string {
	if len(key) == 0 {
		return ""
	}
	return key[0]
}

// isReservedSystemKey reports whether key is one of the guard's reserved system slots (a PREFIX
// match on reservedKeyPrefix). Reserved keys are enforced fail-closed and take precedence over
// any operator pattern.
func isReservedSystemKey(key string) bool {
	return strings.HasPrefix(key, reservedKeyPrefix)
}

// matchesAnyPattern reports whether key matches at least one path.Match glob in patterns. Patterns
// are validated at construction (NewKeyPolicyFromConfig), so a malformed pattern never reaches here
// silently; the err guard is defensive only. path.Match's separator is '/', which none of these
// namespaced keys ("config:threshold", "baseline:limit") contain, so "config:*" matches
// "config:threshold" as intended.
func matchesAnyPattern(patterns []string, key string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, key); err == nil && ok {
			return true
		}
	}
	return false
}

// immutableBaselineHash is a deterministic, namespaced SHA-256 hex digest over the REDACTED write
// content — the immutable-key baseline. It reuses residue.go::deletionHash's idiom (a namespaced
// SHA-256 over canonical bytes) for a different purpose: detecting value drift, not linking a
// deletion. The "immutable\x00" namespace prefix keeps its digest space disjoint from the deletion
// hash. It hashes the content VERBATIM (no normalization), so a single-byte change yields a
// different digest — that mutation-sensitivity is the whole point of the drift check (REQ-007).
func immutableBaselineHash(content string) string {
	h := sha256.Sum256([]byte("immutable\x00" + content))
	return hex.EncodeToString(h[:])
}

// evaluateKeyPolicy runs the protected + immutable checks for a keyed write and returns the
// policy flags to add plus whether the write must be REJECTED (a reserved-tier violation). It is
// called ONLY on the accepted path, AFTER the injection gate (REQ-009), so a write that trips
// injection never reaches it. redacted is the already-redacted content (the same value that would
// be stored), so the baseline is computed over exactly what persists.
//
// Baseline registry side effect: on the FIRST accepted write under an immutable-checked key, the
// baseline is established. It is NEVER overwritten by a later mismatching value (the baseline stays
// pinned to the first-seen hash so drift is detectable on every subsequent write). No baseline is
// established when the write is rejected by the protected check (so a rejected reserved write
// leaves no baseline — REQ-009 / TC-013). The registry lives in the guard (in-process only; the
// durability limitation is documented in ADR-017).
func (g *MemoryGuard) evaluateKeyPolicy(key, redacted string, attested bool) (flags []string, reject bool) {
	reserved := isReservedSystemKey(key)
	protectedMatch := reserved || matchesAnyPattern(g.keyPolicy.Protected, key)
	immutableMatch := reserved || matchesAnyPattern(g.keyPolicy.Immutable, key)

	// Protected (write-authorization) check. Reserved keys reject fail-closed; configured keys
	// flag-only. An attested writer clears both. Reserved rejection returns BEFORE the immutable
	// block, so a rejected reserved write establishes no baseline.
	if protectedMatch && !attested {
		if reserved {
			return []string{protectedKeyViolationFlag}, true
		}
		flags = append(flags, protectedKeyViolationFlag)
	}

	// Immutable (value-change) check. The baseline is established on the first accepted write and
	// pinned thereafter; a later mismatch rejects (reserved) or flags (configured).
	if immutableMatch {
		h := immutableBaselineHash(redacted)
		g.mu.Lock()
		baseline, exists := g.baselines[key]
		if !exists {
			g.baselines[key] = h
			g.mu.Unlock()
		} else {
			g.mu.Unlock()
			if h != baseline {
				if reserved {
					return []string{immutableMismatchFlag}, true
				}
				flags = append(flags, immutableMismatchFlag)
			}
		}
	}

	return flags, false
}
