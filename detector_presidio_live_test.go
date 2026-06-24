// SPDX-License-Identifier: Apache-2.0

//go:build presidio_live

package main

// Live Presidio-backend tests (task 007). Gated behind the `presidio_live` build tag because
// they require the Presidio sidecar to be provisioned (pinned presidio-analyzer/anonymizer +
// the spaCy en_core_web_lg model — see presidio/requirements.txt). The default `go test ./...`
// run does NOT include these, so CI without the model stays green; they are run explicitly via:
//
//	go test -tags presidio_live -run TestPresidio ./...
//
// These cover the live halves the test-spec marks "needs Presidio backend wired":
//   TC-002 (recall lift), TC-003 (latency), and the live half of TC-001 (real redaction).

import (
	"fmt"
	"testing"
	"time"
)

// newLivePresidio constructs and STARTS the Presidio sidecar, skipping the test with a
// recorded reason if the sidecar cannot be provisioned (per the test-spec: skip-with-reason,
// never a silent pass).
func newLivePresidio(t *testing.T) *PresidioDetector {
	t.Helper()
	d := NewPresidioDetector(presidioConfig{})
	if err := d.Start(); err != nil {
		t.Skipf("Presidio sidecar unavailable (provision via presidio/requirements.txt): %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TC-001 (live): the Presidio backend redacts structured PII (native) AND NER entities
// (PERSON) through the unchanged Detector interface.
func TestPresidioLiveRedactsStructuredAndNER(t *testing.T) {
	var d Detector = newLivePresidio(t)

	// Structured PII the native composite owns — must still redact.
	red, flags := d.RedactPII("contact alice@example.com ssn 123-45-6789")
	if !contains(flags, "pii:EMAIL") {
		t.Errorf("expected pii:EMAIL, got %v (redacted=%q)", flags, red)
	}
	if !contains(flags, "pii:US_SSN") {
		t.Errorf("expected pii:US_SSN, got %v (redacted=%q)", flags, red)
	}

	// NER entity the regex backend has NO recognizer for — the recall lift.
	red2, flags2 := d.RedactPII("the new CFO is John Smith from Seattle")
	if !contains(flags2, "pii:PERSON") {
		t.Errorf("expected pii:PERSON from NER, got %v (redacted=%q)", flags2, red2)
	}
	t.Logf("NER redaction: %q -> %q flags=%v", "the new CFO is John Smith from Seattle", red2, flags2)

	// Empty input: no panic, no flags.
	if r, f := d.RedactPII(""); r != "" || len(f) != 0 {
		t.Errorf("empty input should yield no redaction/flags, got %q %v", r, f)
	}
}

// TC-002 (live): PII recall lift on the PII corpus (Presidio's real domain) + injection
// UNCHANGED on the adversarial corpus (honest conflation finding from ADR-009). REQ-002's
// literal "recall > 0.69 on adversarialCorpus" is an INJECTION number a PII engine cannot
// lift; this test records that explicitly and instead proves (a) PII recall lifts on the PII
// corpus, and (b) injection recall is UNCHANGED vs the native baseline.
func TestPresidioLiveRecallLiftPIIAndInjectionUnchanged(t *testing.T) {
	pres := newLivePresidio(t)
	native := NewNativeDetector()

	// (a) PII recall: count NER-only entities the native backend misses but Presidio catches.
	// We measure the LIFT as additional PII categories detected on NER-bearing inputs.
	nerInputs := []struct{ text, wantLabel string }{
		{"the new CFO is John Smith from Seattle", "pii:PERSON"},
		{"send the report to Maria Garcia in London", "pii:PERSON"},
		{"escalate to Dr. Robert Chen immediately", "pii:PERSON"},
	}
	nativeHits, presidioHits := 0, 0
	for _, in := range nerInputs {
		_, nf := native.RedactPII(in.text)
		_, pf := pres.RedactPII(in.text)
		if contains(nf, in.wantLabel) {
			nativeHits++
		}
		if contains(pf, in.wantLabel) {
			presidioHits++
		}
	}
	t.Logf("PII NER recall: native caught %d/%d PERSON spans, Presidio caught %d/%d — LIFT=%d",
		nativeHits, len(nerInputs), presidioHits, len(nerInputs), presidioHits-nativeHits)
	if presidioHits <= nativeHits {
		t.Errorf("expected a PII/NER recall LIFT over native (native=%d, presidio=%d)",
			nativeHits, presidioHits)
	}

	// (b) Injection recall on the UNCHANGED adversarial corpus — must be UNCHANGED vs native
	// (Presidio does not classify injection; it delegates to the native heuristic).
	poisoning, _ := splitCorpus()
	gNative := NewMemoryGuard(native)
	gPres := NewMemoryGuard(pres)
	nativeRej, presRej := 0, 0
	for _, s := range poisoning {
		if gNative.ValidateWrite(s.content, nil)["allow"] == false {
			nativeRej++
		}
		if gPres.ValidateWrite(s.content, nil)["allow"] == false {
			presRej++
		}
	}
	nativeRecall := float64(nativeRej) / float64(len(poisoning))
	presRecall := float64(presRej) / float64(len(poisoning))
	t.Logf("injection recall: native=%.4f (%d/%d), presidio=%.4f (%d/%d) — UNCHANGED (orthogonal)",
		nativeRecall, nativeRej, len(poisoning), presRecall, presRej, len(poisoning))
	if presRej != nativeRej {
		t.Errorf("injection recall changed (native=%d, presidio=%d) — DetectInjection must delegate UNCHANGED",
			nativeRej, presRej)
	}
}

// TC-003 (live): measure the REAL per-op detection cost with the warm sidecar wired. A
// sidecar round-trip is MILLISECONDS, NOT microseconds — it will EXCEED the native < 1 ms
// budget. Per REQ-003 (which explicitly allows a REVISED budget with rationale), this test
// asserts the REVISED rich-backend budget recorded in ADR-009, and logs the measured figure.
// It does NOT assert the native < 1 ms against Presidio (that would be dishonest).
func TestPresidioLiveLatency(t *testing.T) {
	d := newLivePresidio(t)
	const input = "contact alice@example.com ssn 123-45-6789, the CFO is John Smith"
	const iters = 200

	// Warm-up (exclude cold-start / first-call JIT from steady-state).
	for i := 0; i < 20; i++ {
		d.DetectInjection(input)
		d.RedactPII(input)
	}

	start := time.Now()
	for i := 0; i < iters; i++ {
		d.DetectInjection(input)
		d.RedactPII(input)
	}
	perOp := time.Since(start) / iters

	// Revised "rich-backend" budget (ADR-009): a warm sidecar round-trip is expected in the
	// single-digit-to-low-tens-of-milliseconds range. The budget is generous (50 ms) because
	// the rationale is "rich NER off the hot path", not "microsecond gate". The native backend
	// remains the < 1 ms hot-path default; Presidio is the opt-in rich backend.
	const richBackendBudget = 50 * time.Millisecond
	t.Logf("Presidio sidecar per-op detection cost ~%v (revised rich-backend budget: %v; native default stays <1ms)",
		perOp, richBackendBudget)
	if perOp > richBackendBudget {
		t.Errorf("Presidio per-op %v exceeds the REVISED rich-backend budget %v — record a higher budget + rationale in ADR-009",
			perOp, richBackendBudget)
	}
	fmt.Printf("MEASURED Presidio per-op latency: %v\n", perOp)
}
