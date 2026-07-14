// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"strings"
	"testing"
)

// keys_docs_test.go — task 021, TC-012 (REQ-008 / REQ-009): ADR + spec propagation.
//
// This guards that the code change did not ship without the paired documentation: ADR-017 must record
// the two-tier ownership boundary and the durability limitation, and each of the five spec files must
// carry the new flag vocabulary / config / behavior. It mirrors contract_tracer_test.go's TC-008
// pattern (asserting the ADR exists and records the decision), so a future edit that drops the docs is
// caught as a test failure, not discovered later.

func TestKeysTC012_ADRAndSpecPropagation(t *testing.T) {
	mustContain := func(t *testing.T, path string, needles ...string) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("TC-012: reading %s: %v", path, err)
		}
		body := string(b)
		for _, n := range needles {
			if !strings.Contains(body, n) {
				t.Fatalf("TC-012: %s must contain %q", path, n)
			}
		}
	}

	// ADR-017 records the two-tier ownership boundary, the policy-engine deferral, and the durability limit.
	mustContain(t, "docs/architecture/decisions/017-protected-immutable-keys.md",
		"reserved", "policy-engine", "in-process", "Durability limitation", "protected_key_violation", "immutable_mismatch")

	// Five spec files updated in the same change.
	mustContain(t, "docs/CONTRACT.md", "protected_key_violation", "immutable_mismatch")
	mustContain(t, "docs/spec/interfaces.md", "KeyPolicy", "protected_key_violation", "immutable_mismatch")
	mustContain(t, "docs/spec/data-model.md", "baselines", "immutable_mismatch", "protected_key_violation")
	mustContain(t, "docs/spec/behaviors.md", "B-011", "protected_key_violation", "immutable_mismatch")
	mustContain(t, "docs/spec/configuration.md", "MEMGUARD_PROTECTED_KEYS", "MEMGUARD_IMMUTABLE_KEYS")
}
