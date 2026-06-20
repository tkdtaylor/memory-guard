// SPDX-License-Identifier: Apache-2.0
package main

// PII corpus tests for task 004: recall/precision harness over the labelled corpus.
//
// All fixtures use SYNTHETIC PII — no real personal data.
// Hard negatives are labelled "none" and must NOT be redacted; a match on them fails
// the precision assertion (TC-003).

import (
	"fmt"
	"strings"
	"testing"
)

// corpusSample is a single labelled entry in the PII corpus.
type corpusSample struct {
	text          string // input text (synthetic PII only)
	category      string // expected PII category label, or "none" for hard negatives
	expectRedact  bool   // true = the text should be redacted (positive), false = hard negative
	allowedOver   string // non-empty = over-match is deliberately accepted with this rationale
}

// piiCorpus is the full labelled corpus: positives per category + hard negatives.
// Every category introduced in task 004 must have at least one positive sample and at least one
// hard negative (or share a structural one).
var piiCorpus = []corpusSample{
	// ---- v0 categories (regression: must still redact) ----
	{text: "contact alice@example.com", category: "EMAIL", expectRedact: true},
	{text: "email: bob.smith+filter@sub.example.co.uk", category: "EMAIL", expectRedact: true},
	{text: "ssn 123-45-6789", category: "US_SSN", expectRedact: true},
	{text: "social security number: 987-65-4321", category: "US_SSN", expectRedact: true},
	{text: "card 4111 1111 1111 1111", category: "CREDIT_CARD", expectRedact: true},
	{text: "visa 4111-1111-1111-1111", category: "CREDIT_CARD", expectRedact: true},
	{text: "key sk-ABCDEFGH12345678", category: "API_KEY", expectRedact: true},
	{text: "aws AKIAIOSFODNN7EXAMPLE", category: "API_KEY", expectRedact: true},
	{text: "github ghp-abcdef1234567890", category: "API_KEY", expectRedact: true},
	{text: "slack xoxb-abc123def456ghi", category: "API_KEY", expectRedact: true},

	// ---- PHONE positives ----
	{text: "call me at 555-867-5309", category: "PHONE", expectRedact: true},
	{text: "phone: (800) 555-0199", category: "PHONE", expectRedact: true},
	{text: "reach me at +1 415.555.0101", category: "PHONE", expectRedact: true},
	{text: "fax 212-555-0142", category: "PHONE", expectRedact: true},

	// ---- IBAN positives ----
	{text: "bank transfer to DE89370400440532013000", category: "IBAN", expectRedact: true},
	{text: "IBAN: GB29NWBK60161331926819", category: "IBAN", expectRedact: true},
	{text: "account FR7630006000011234567890189", category: "IBAN", expectRedact: true},

	// ---- IP_ADDRESS positives (IPv4) ----
	{text: "server at 192.168.1.100", category: "IP_ADDRESS", expectRedact: true},
	{text: "origin ip 203.0.113.42", category: "IP_ADDRESS", expectRedact: true},
	{text: "banned: 10.0.0.1", category: "IP_ADDRESS", expectRedact: true},
	{text: "255.255.255.0", category: "IP_ADDRESS", expectRedact: true},

	// ---- IP_ADDRESS positives (IPv6) ----
	{text: "ipv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334", category: "IP_ADDRESS", expectRedact: true},
	{text: "loopback ::1", category: "IP_ADDRESS", expectRedact: true},
	{text: "fe80::1", category: "IP_ADDRESS", expectRedact: true},

	// ---- DOB positives ----
	{text: "date of birth 01/15/1990", category: "DOB", expectRedact: true},
	{text: "born: 12/31/2001", category: "DOB", expectRedact: true},
	{text: "dob 1985-07-04", category: "DOB", expectRedact: true},
	{text: "birthday 1999-11-30", category: "DOB", expectRedact: true},
	{text: "born 15 Jan 1990", category: "DOB", expectRedact: true},
	{text: "born 3 Mar 2000", category: "DOB", expectRedact: true},

	// ---- API_KEY (v1 broader prefixes: sk-ant, hf_, npm_, pat_) ----
	// These use prefixes not present in the v0 recognizer but consolidated under the API_KEY label.
	{text: "token sk-ant-api03-ABCDEFGH1234567890", category: "API_KEY", expectRedact: true},
	{text: "huggingface hf_aBcDeFgHiJkLmNoPq", category: "API_KEY", expectRedact: true},
	{text: "npm token npm_1234abcd5678efgh90ij", category: "API_KEY", expectRedact: true},
	{text: "personal pat_XyZ1234567890abcdef", category: "API_KEY", expectRedact: true},

	// ---- CREDENTIAL positives (long hex secret strings) ----
	{text: "secret 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", category: "CREDENTIAL", expectRedact: true},
	{text: "token 1234567890abcdef1234567890abcdef12345678", category: "CREDENTIAL", expectRedact: true},

	// ==== HARD NEGATIVES (must NOT be redacted) ====

	// 9-digit order number — NOT an SSN (SSN requires \d{3}-\d{2}-\d{4} format with hyphens)
	{text: "order 123456789", category: "none", expectRedact: false},
	// SSN-like but wrong segment lengths — NOT an SSN
	{text: "id 12-345-6789", category: "none", expectRedact: false},

	// 3-part semver — NOT an IP address (IP requires 4 octets)
	{text: "version v1.2.3", category: "none", expectRedact: false},
	// Another 3-part version — NOT an IP
	{text: "node 14.17.6", category: "none", expectRedact: false},

	// UUID — NOT an API key (no matching prefix; hex runs are under 32 chars each segment)
	{text: "id 550e8400-e29b-41d4-a716-446655440000", category: "none", expectRedact: false},

	// Benign short hex — NOT a CREDENTIAL (under 32 hex chars)
	{text: "color #1a2b3c", category: "none", expectRedact: false},

	// 6-digit order code — NOT a phone (requires separator between groups)
	{text: "code 867530", category: "none", expectRedact: false},

	// Benign text
	{text: "the quick brown fox jumps over the lazy dog", category: "none", expectRedact: false},
	{text: "meeting at noon about the roadmap", category: "none", expectRedact: false},
}

// TC-001: each positive sample is redacted and flagged with the correct pii:<LABEL>.
// Also confirms v0 categories still redact (regression).
func TestCorpusPositivesRedactAndFlag(t *testing.T) {
	for _, det := range []struct {
		name string
		d    Detector
	}{
		{"RegexDetector", NewRegexDetector()},
		{"NativeDetector", NewNativeDetector()},
	} {
		det := det
		t.Run(det.name, func(t *testing.T) {
			for _, s := range piiCorpus {
				if !s.expectRedact {
					continue // hard negatives are covered in TC-003
				}
				red, flags := det.d.RedactPII(s.text)
				label := s.category
				placeholder := "<" + label + ">"
				flagWant := "pii:" + label
				if !strings.Contains(red, placeholder) {
					t.Errorf("[%s] category=%s: placeholder %q not found in redacted %q (input: %q)",
						det.name, label, placeholder, red, s.text)
				}
				if !hasFlag(flags, flagWant) {
					t.Errorf("[%s] category=%s: flag %q not in %v (input: %q)",
						det.name, label, flagWant, flags, s.text)
				}
			}
		})
	}
}

// TC-002: recall/precision harness — per-category recall must meet the threshold and be
// recorded. A category with zero detections (recall = 0) fails the suite.
func TestCorpusRecallPrecision(t *testing.T) {
	const recallThreshold = 0.80  // per-category: at least 80% of positives detected
	const precisionThreshold = 0.80 // overall: at most 20% of hard-negative matches are FPs

	for _, det := range []struct {
		name string
		d    Detector
	}{
		{"RegexDetector", NewRegexDetector()},
		{"NativeDetector", NewNativeDetector()},
	} {
		det := det
		t.Run(det.name, func(t *testing.T) {
			// Per-category tallies: true positives and false negatives.
			type catStats struct {
				tp, fn int
			}
			byCategory := map[string]*catStats{}
			// False-positive count over hard negatives.
			fpCount := 0
			tnCount := 0

			for _, s := range piiCorpus {
				red, _ := det.d.RedactPII(s.text)

				if s.expectRedact {
					// Positive sample: was the placeholder injected?
					placeholder := "<" + s.category + ">"
					if _, ok := byCategory[s.category]; !ok {
						byCategory[s.category] = &catStats{}
					}
					if strings.Contains(red, placeholder) {
						byCategory[s.category].tp++
					} else {
						byCategory[s.category].fn++
					}
				} else {
					// Hard negative: was anything redacted? (any <LABEL> present = FP)
					if s.allowedOver != "" {
						// Deliberately accepted over-match; skip FP count.
						continue
					}
					if strings.Contains(red, "<") {
						fpCount++
						t.Logf("[%s] FALSE POSITIVE on hard negative %q → %q", det.name, s.text, red)
					} else {
						tnCount++
					}
				}
			}

			// Per-category recall check.
			for cat, st := range byCategory {
				total := st.tp + st.fn
				if total == 0 {
					t.Errorf("[%s] category %s: no positive samples found in corpus", det.name, cat)
					continue
				}
				recall := float64(st.tp) / float64(total)
				t.Logf("[%s] %s: recall=%.2f (%d/%d)", det.name, cat, recall, st.tp, total)
				if recall < recallThreshold {
					t.Errorf("[%s] %s: recall %.2f < threshold %.2f (%d/%d positives detected)",
						det.name, cat, recall, recallThreshold, st.tp, total)
				}
				if st.tp == 0 {
					t.Errorf("[%s] %s: ZERO detections — recognizer is silent or broken", det.name, cat)
				}
			}

			// Overall precision: FP / (FP + TN).
			hardNegTotal := fpCount + tnCount
			if hardNegTotal > 0 {
				fpr := float64(fpCount) / float64(hardNegTotal)
				precision := 1.0 - fpr
				t.Logf("[%s] overall precision=%.2f (%d FP, %d TN, %d hard-neg total)",
					det.name, precision, fpCount, tnCount, hardNegTotal)
				if precision < precisionThreshold {
					t.Errorf("[%s] precision %.2f < threshold %.2f (%d FPs over %d hard negatives)",
						det.name, precision, precisionThreshold, fpCount, hardNegTotal)
				}
			}

			// Print a summary line for the verification ladder.
			t.Logf("[%s] corpus summary: %d categories evaluated, %d FP on %d hard negatives",
				det.name, len(byCategory), fpCount, hardNegTotal)
		})
	}
}

// TC-003: hard negatives are not redacted; over-match on a hard negative fails the assertion
// unless explicitly recorded with rationale in allowedOver.
func TestCorpusHardNegatives(t *testing.T) {
	for _, det := range []struct {
		name string
		d    Detector
	}{
		{"RegexDetector", NewRegexDetector()},
		{"NativeDetector", NewNativeDetector()},
	} {
		det := det
		t.Run(det.name, func(t *testing.T) {
			for _, s := range piiCorpus {
				if s.expectRedact {
					continue // positives are covered in TC-001
				}
				red, flags := det.d.RedactPII(s.text)
				// Any <LABEL> in the output = an over-match (false positive).
				if strings.Contains(red, "<") {
					if s.allowedOver != "" {
						t.Logf("[%s] DELIBERATE over-match on %q → %q (rationale: %s)",
							det.name, s.text, red, s.allowedOver)
					} else {
						t.Errorf("[%s] UNEXPECTED false-positive on hard-negative %q → redacted=%q flags=%v",
							det.name, s.text, red, flags)
					}
				}
			}
		})
	}
}

// TC-004 (structural): only detector.go (+ tests + data-model.md) changed.
// This test asserts the seam invariant behaviorally: NewMemoryGuard(nil) still wires the
// (now broader) RegexDetector and the v0 PII categories still work end-to-end.
func TestSeamInvariantAfterTask004(t *testing.T) {
	// nil falls back to RegexDetector (the now-broader one).
	g := NewMemoryGuard(nil)
	if _, ok := g.det.(*RegexDetector); !ok {
		t.Fatalf("expected nil to fall back to *RegexDetector, got %T", g.det)
	}

	// v0 EMAIL still works through the broader detector.
	out := g.ValidateWrite("contact alice@example.com", nil)
	if out["allow"] != true || out["stored_id"] == nil {
		t.Fatalf("expected stored write, got %v", out)
	}
	if !hasFlag(out["flags"], "pii:EMAIL") {
		t.Fatalf("expected pii:EMAIL, got %v", out["flags"])
	}

	// New PHONE category also works through the same guard/IPC path.
	gPhone := NewMemoryGuard(nil)
	pOut := gPhone.ValidateWrite("call me at 555-867-5309", nil)
	if pOut["allow"] != true || pOut["stored_id"] == nil {
		t.Fatalf("expected phone PII write to be stored, got %v", pOut)
	}
	if !hasFlag(pOut["flags"], "pii:PHONE") {
		t.Fatalf("expected pii:PHONE flag, got %v", pOut["flags"])
	}
	// Confirm the raw phone number is not stored.
	read := gPhone.ValidateRead("call", nil)
	content := read["content_redacted"].(string)
	if strings.Contains(content, "555-867-5309") {
		t.Fatalf("raw phone number leaked into store: %q", content)
	}
	if !strings.Contains(content, "<PHONE>") {
		t.Fatalf("expected <PHONE> placeholder in stored content: %q", content)
	}
}

// TC-002 (extended): multi-category string — each category redacts independently.
func TestMultiCategoryRedaction(t *testing.T) {
	input := "contact alice@example.com dob 1990-07-04 ip 10.0.0.1"
	for _, det := range []struct {
		name string
		d    Detector
	}{
		{"RegexDetector", NewRegexDetector()},
		{"NativeDetector", NewNativeDetector()},
	} {
		det := det
		t.Run(det.name, func(t *testing.T) {
			red, flags := det.d.RedactPII(input)
			// Each category should produce its placeholder.
			for _, want := range []struct {
				placeholder string
				flag        string
			}{
				{"<EMAIL>", "pii:EMAIL"},
				{"<DOB>", "pii:DOB"},
				{"<IP_ADDRESS>", "pii:IP_ADDRESS"},
			} {
				if !strings.Contains(red, want.placeholder) {
					t.Errorf("[%s] missing %s in %q", det.name, want.placeholder, red)
				}
				if !hasFlag(flags, want.flag) {
					t.Errorf("[%s] missing flag %s in %v", det.name, want.flag, flags)
				}
			}
			// The raw PII must not appear in the redacted output.
			for _, raw := range []string{"alice@example.com", "1990-07-04", "10.0.0.1"} {
				if strings.Contains(red, raw) {
					t.Errorf("[%s] raw PII %q still present in %q", det.name, raw, red)
				}
			}
			t.Logf("[%s] multi-category input=%q → redacted=%q flags=%v", det.name, input, red, flags)
		})
	}
}

// corpusSummaryReport produces a human-readable recall/precision summary for the spec table.
// This is only invoked during TestMain or a dedicated benchmark; it does not fail the suite.
func corpusSummaryReport(t *testing.T, detName string, d Detector) string {
	type catRow struct {
		tp, fn int
	}
	rows := map[string]*catRow{}
	fpCount := 0
	tnCount := 0

	for _, s := range piiCorpus {
		red, _ := d.RedactPII(s.text)
		if s.expectRedact {
			if _, ok := rows[s.category]; !ok {
				rows[s.category] = &catRow{}
			}
			ph := "<" + s.category + ">"
			if strings.Contains(red, ph) {
				rows[s.category].tp++
			} else {
				rows[s.category].fn++
			}
		} else {
			if s.allowedOver == "" {
				if strings.Contains(red, "<") {
					fpCount++
				} else {
					tnCount++
				}
			}
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== Corpus summary: %s ===\n", detName)
	for cat, r := range rows {
		total := r.tp + r.fn
		recall := 0.0
		if total > 0 {
			recall = float64(r.tp) / float64(total)
		}
		fmt.Fprintf(&sb, "  %-15s recall=%.2f (%d/%d)\n", cat, recall, r.tp, total)
	}
	hnTotal := fpCount + tnCount
	precision := 1.0
	if hnTotal > 0 {
		precision = float64(hnTotal-fpCount) / float64(hnTotal)
	}
	fmt.Fprintf(&sb, "  overall precision=%.2f (%d FP / %d hard-neg)\n", precision, fpCount, hnTotal)
	return sb.String()
}

// TestCorpusSummary logs the recall/precision summary for the verification ladder record.
func TestCorpusSummary(t *testing.T) {
	for _, det := range []struct {
		name string
		d    Detector
	}{
		{"RegexDetector", NewRegexDetector()},
		{"NativeDetector", NewNativeDetector()},
	} {
		t.Log("\n" + corpusSummaryReport(t, det.name, det.d))
	}
}
