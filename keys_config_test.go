// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"path"
	"reflect"
	"testing"
)

// keys_config_test.go — task 021, TC-009: the KeyPolicy config factory + builder composition.
//
//   - NewKeyPolicyFromConfig parses valid CSV glob lists (whitespace trimmed, empty entries dropped),
//     returns an empty policy for empty input, and fails closed (path.ErrBadPattern) on a malformed
//     pattern (REQ-006).
//   - WithKeyPolicy, WithAudit, and WithWriteInspector (task 018) compose in ANY call order, each
//     preserving the others' already-set fields when it copies the guard.

// --- TC-009a: NewKeyPolicyFromConfig parsing / validation / defaults --------------------

func TestKeysTC009_ConfigFactoryParse(t *testing.T) {
	// Valid CSV with surrounding whitespace: trimmed, both knobs populated.
	got, err := NewKeyPolicyFromConfig("config:*, secrets:*", "baseline:*")
	if err != nil {
		t.Fatalf("valid CSV must not error, got %v", err)
	}
	want := KeyPolicy{Protected: []string{"config:*", "secrets:*"}, Immutable: []string{"baseline:*"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed policy mismatch:\n got %#v\nwant %#v", got, want)
	}

	// Empty input on both knobs: empty (reserved-only) policy, no error.
	empty, err := NewKeyPolicyFromConfig("", "")
	if err != nil {
		t.Fatalf("empty input must not error, got %v", err)
	}
	if len(empty.Protected) != 0 || len(empty.Immutable) != 0 {
		t.Fatalf("empty input must yield an empty policy, got %#v", empty)
	}

	// Malformed pattern: construction error wrapping path.ErrBadPattern (fail-closed).
	_, err = NewKeyPolicyFromConfig("[unclosed", "")
	if err == nil {
		t.Fatalf("malformed pattern must be a construction error, got nil")
	}
	if !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("malformed-pattern error must wrap path.ErrBadPattern, got %v", err)
	}

	// Edge: a trailing empty element ("config:*,") drops the empty entry, not a match-everything.
	trailing, err := NewKeyPolicyFromConfig("config:*,", "")
	if err != nil {
		t.Fatalf("trailing comma must not error, got %v", err)
	}
	if !reflect.DeepEqual(trailing.Protected, []string{"config:*"}) {
		t.Fatalf("trailing empty element must be dropped, got %#v", trailing.Protected)
	}
}

// --- TC-009b: builder composition in any order (WithKeyPolicy / WithAudit / WithWriteInspector) ---

// tapInspector is a trivial WriteInspector that always emits one flag, so a guard that HAS the
// inspector wired can be distinguished from one that does not, independent of the key policy.
type tapInspector struct{ flag string }

func (ti tapInspector) Inspect(content string, ctx WriteContext) []string { return []string{ti.flag} }

func TestKeysTC009_BuilderComposeAnyOrder(t *testing.T) {
	policy := KeyPolicy{Protected: []string{"config:*"}}
	cfg := AuditConfig{Enabled: true, Sink: &CollectingSink{}}
	insp := tapInspector{flag: "tap"}
	id := attestedIdentity("spiffe://secure-agents/agent/ops")

	// assertAllThree exercises each seam through the composed guard: the key policy (a protected
	// flag on an unattested keyed write), the audit sink (an emitted event on a PII write), and the
	// inspector (its tap flag on any accepted write). If any builder dropped another's field, one of
	// these observable effects disappears.
	assertAllThree := func(t *testing.T, g *MemoryGuard, label string) {
		t.Helper()

		// Key policy present: unattested write to config:* carries protected_key_violation.
		kp := g.ValidateWrite("benign note", nil, "config:threshold")
		if !hasFlag(kp["flags"], protectedKeyViolationFlag) {
			t.Fatalf("%s: key policy dropped — no protected_key_violation on config:* write: %v", label, kp["flags"])
		}

		// Inspector present: its tap flag rides every accepted write.
		if !hasFlag(kp["flags"], "tap") {
			t.Fatalf("%s: inspector dropped — no tap flag: %v", label, kp["flags"])
		}

		// Audit present: a PII write emits at least one event into the collecting sink.
		sink := cfg.Sink.(*CollectingSink)
		before := len(sink.Events())
		g.ValidateWrite("contact alice@example.com", id)
		if len(sink.Events()) == before {
			t.Fatalf("%s: audit dropped — no event emitted on a PII write", label)
		}
	}

	// Order 1: audit -> key policy -> inspector.
	g1 := NewMemoryGuard(NewRegexDetector()).WithAudit(cfg).WithKeyPolicy(policy).WithWriteInspector(insp)
	assertAllThree(t, g1, "audit,keypolicy,inspector")

	// Order 2: inspector -> key policy -> audit (fresh sink state via a fresh guard on the same cfg).
	cfg.Sink = &CollectingSink{}
	g2 := NewMemoryGuard(NewRegexDetector()).WithWriteInspector(insp).WithKeyPolicy(policy).WithAudit(cfg)
	assertAllThree(t, g2, "inspector,keypolicy,audit")

	// Order 3: key policy -> audit -> inspector.
	cfg.Sink = &CollectingSink{}
	g3 := NewMemoryGuard(NewRegexDetector()).WithKeyPolicy(policy).WithAudit(cfg).WithWriteInspector(insp)
	assertAllThree(t, g3, "keypolicy,audit,inspector")
}
