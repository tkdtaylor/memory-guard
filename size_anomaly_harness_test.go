// SPDX-License-Identifier: Apache-2.0
package main

// size_anomaly_harness_test.go: L5 validation-harness evidence for task 019 (ADR-018). It drives
// the SizeAnomalyDetector through the REAL MemoryGuard.ValidateWrite path (opted in via
// WithWriteInspector), not a hand-constructed Inspect call, so the flag is proven reachable on the
// live write path. Establishes ~20 normal writes for one key, then asserts the outlier flags, a
// control does not, cold-start never flags, and CombineInspectors surfaces both detectors' flags.

import (
	"testing"
)

// normalSizes returns n benign sizes clustered around ~100 bytes with small nonzero variance, so
// the baseline has a real (small) standard deviation rather than a degenerate zero.
func normalSizes(n int) []int {
	pattern := []int{100, 102, 98, 101, 99}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		out[i] = pattern[i%len(pattern)]
	}
	return out
}

func TestSizeAnomalyHarnessL5(t *testing.T) {
	idA := attestedIdentity("spiffe://secure-agents/agent/alpha")

	// Default config (WindowSize=20, SigmaThreshold=3.0, MinSamples=5), opted in on the live guard.
	g := NewMemoryGuard(NewNativeDetector()).WithWriteInspector(NewSizeAnomalyDetector(SizeAnomalyConfig{}))

	// Establish ~20 normal-sized writes for one key through the live ValidateWrite path.
	for i, s := range normalSizes(20) {
		out := g.ValidateWrite(szText(s), idA)
		assertAllowStored(t, out)
		if hasFlag(out["flags"], sizeAnomalyFlag) {
			t.Fatalf("baseline write %d (size %d) must NOT flag size anomaly, flags=%v", i+1, s, out["flags"])
		}
	}

	// One outsized write: flags size_anomaly_suspected, allow:true, real stored_id.
	outlier := g.ValidateWrite(szText(5000), idA)
	if outlier["allow"] != true {
		t.Fatalf("L5 outlier: allow must be true, got %v", outlier["allow"])
	}
	if id, ok := outlier["stored_id"].(string); !ok || id == "" {
		t.Fatalf("L5 outlier: stored_id must be a non-empty string, got %v", outlier["stored_id"])
	}
	if !hasFlag(outlier["flags"], sizeAnomalyFlag) {
		t.Fatalf("L5 outlier: flags must contain %q, got %v", sizeAnomalyFlag, outlier["flags"])
	}
	t.Logf("L5 outlier PASS: allow=%v stored_id=%v flags=%v", outlier["allow"], outlier["stored_id"], outlier["flags"])

	// A normal-sized control in the same run: flag ABSENT (the 5000 outlier did not make ~100 anomalous).
	control := g.ValidateWrite(szText(100), idA)
	assertAllowStored(t, control)
	if hasFlag(control["flags"], sizeAnomalyFlag) {
		t.Fatalf("L5 control: normal-sized write must NOT flag, flags=%v", control["flags"])
	}
	t.Logf("L5 control PASS: normal write flags=%v (no size_anomaly_suspected)", control["flags"])

	// Cold-start in a fresh run: the first MinSamples-1 (=4) writes never flag regardless of spread.
	gCold := NewMemoryGuard(NewNativeDetector()).WithWriteInspector(NewSizeAnomalyDetector(SizeAnomalyConfig{}))
	for i, s := range []int{1, 90000, 3, 700000} {
		out := gCold.ValidateWrite(szText(s), idA)
		assertAllowStored(t, out)
		if hasFlag(out["flags"], sizeAnomalyFlag) {
			t.Fatalf("L5 cold-start write %d (size %d) must NOT flag before MinSamples, flags=%v", i+1, s, out["flags"])
		}
	}
	t.Logf("L5 cold-start PASS: first 4 writes never flagged despite huge spread")

	// CombineInspectors: a write that trips BOTH the size detector and a forced second inspector
	// surfaces both flags together, through the live ValidateWrite path.
	spy := &spyInspector{forced: []string{selfReinforcementFlag}}
	gBoth := NewMemoryGuard(NewNativeDetector()).WithWriteInspector(
		CombineInspectors(NewSizeAnomalyDetector(SizeAnomalyConfig{}), spy))
	for _, s := range normalSizes(20) {
		gBoth.ValidateWrite(szText(s), idA)
	}
	both := gBoth.ValidateWrite(szText(5000), idA)
	assertAllowStored(t, both)
	fs := flagSet(both["flags"])
	if !fs[sizeAnomalyFlag] || !fs[selfReinforcementFlag] {
		t.Fatalf("L5 combine: flags must contain BOTH %q and %q, got %v", sizeAnomalyFlag, selfReinforcementFlag, both["flags"])
	}
	t.Logf("L5 combine PASS: both detectors' flags present together = %v", both["flags"])
}
