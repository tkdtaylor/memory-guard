// SPDX-License-Identifier: Apache-2.0
package main

// size_anomaly_socket_test.go: L6 evidence for task 019 (ADR-018). It drives the
// size_anomaly_suspected flag over the LIVE serve() Unix socket, decoding the flags array off the
// wire, so the additive flag is observed on the real transport and not merely in-process. The
// daemon is wired through the SAME buildWriteInspector() production factory main.go's serve/write
// path uses. Self-reinforcement is toggled off for this run (MEMGUARD_SELF_REINFORCEMENT=off) so
// the size flag is isolated on the wire; the size-anomaly detector is still wired by the real
// factory with its default config (WindowSize=20, SigmaThreshold=3.0, MinSamples=5).

import "testing"

func TestSizeAnomalyOverSocket(t *testing.T) {
	t.Setenv("MEMGUARD_SELF_REINFORCEMENT", "off")
	t.Setenv("MEMGUARD_SIZE_ANOMALY", "on")
	d := startSelfReinforcementDaemon(t) // production buildWriteInspector() wiring, size-anomaly only

	idAlpha := map[string]any{
		"spiffe_id": "spiffe://secure-agents/agent/alpha", "trust_tier": "attested", "source_class": "agent_authored",
	}

	// ~20 similarly-sized benign writes under one identity: establish the size baseline over the wire.
	for i := 0; i < 20; i++ {
		out := d.call(map[string]any{"op": "validate_write", "entry": szText(100), "identity": idAlpha})
		if out["allow"] != true {
			t.Fatalf("baseline write %d: expected allow:true over the wire, got %v", i+1, out)
		}
		if wireHasFlag(wireFlags(t, out), sizeAnomalyFlag) {
			t.Fatalf("baseline write %d (100 bytes) must NOT flag size anomaly over the wire", i+1)
		}
	}

	// One large outlier: size_anomaly_suspected appears on the wire, allow still true, real stored_id.
	outlier := d.call(map[string]any{"op": "validate_write", "entry": szText(5000), "identity": idAlpha})
	flags := wireFlags(t, outlier)
	if outlier["allow"] != true {
		t.Fatalf("outlier: expected allow:true over the wire, got %v", outlier)
	}
	if id, ok := outlier["stored_id"].(string); !ok || id == "" {
		t.Fatalf("outlier: expected non-empty stored_id over the wire, got %v", outlier["stored_id"])
	}
	if !wireHasFlag(flags, sizeAnomalyFlag) {
		t.Fatalf("outlier: wire flags must contain %q, got %v", sizeAnomalyFlag, flags)
	}
	t.Logf("WIRE outlier: allow=%v stored_id=%v flags=%v", outlier["allow"], outlier["stored_id"], flags)

	// A normal-sized control over the wire: no size flag.
	control := d.call(map[string]any{"op": "validate_write", "entry": szText(100), "identity": idAlpha})
	if wireHasFlag(wireFlags(t, control), sizeAnomalyFlag) {
		t.Fatalf("control: normal-sized write must NOT flag over the wire, got %v", wireFlags(t, control))
	}
	t.Logf("WIRE control: flags=%v (no size_anomaly_suspected)", wireFlags(t, control))
}
