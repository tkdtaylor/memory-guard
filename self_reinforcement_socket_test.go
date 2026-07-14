// SPDX-License-Identifier: Apache-2.0
package main

// self_reinforcement_socket_test.go: L6 evidence for task 018. It drives the self-reinforcement
// flag over the LIVE serve() Unix socket, decoding the flags arrays off the wire, so the additive
// flag is observed on the real transport and not merely in-process. The daemon is wired through
// the SAME buildWriteInspector() factory main.go's serve/write path uses (the ADR-016 default
// config: similarity 0.85, cooldown 5m, max self-writes 3), so this exercises the production
// construction path, not a hand-tuned test guard.

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// srSocketDaemon is a serve()-equivalent daemon wired with the production behavioral inspector.
type srSocketDaemon struct {
	socket string
	t      *testing.T
}

// startSelfReinforcementDaemon brings up serve() against a real store and the production
// buildWriteInspector() wiring, on a listener the test owns so teardown is deterministic.
func startSelfReinforcementDaemon(t *testing.T) *srSocketDaemon {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "memguard-selfreinf.sock")
	guard := NewMemoryGuard(NewNativeDetector(), NewInMemoryStore()).
		WithWriteInspector(buildWriteInspector()) // the LIVE serve/write wiring factory
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	_ = os.Chmod(sock, 0o600)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, guard)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); _ = os.Remove(sock) })
	return &srSocketDaemon{socket: sock, t: t}
}

// call dials the live socket, sends one newline-delimited request, and decodes the wire response.
func (d *srSocketDaemon) call(req map[string]any) map[string]any {
	d.t.Helper()
	conn, err := net.DialTimeout("unix", d.socket, 2*time.Second)
	if err != nil {
		d.t.Fatalf("dial %s: %v", d.socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, _ := json.Marshal(req)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		d.t.Fatalf("write request: %v", err)
	}
	respLine, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(respLine) == 0 {
		d.t.Fatalf("read response: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(respLine, &resp); err != nil {
		d.t.Fatalf("decode response %q: %v", string(respLine), err)
	}
	return resp
}

// wireFlags extracts the flags array from a decoded socket response as []string. Off the wire the
// JSON array decodes to []any; this normalizes it so assertions are exact string comparisons.
func wireFlags(t *testing.T, out map[string]any) []string {
	t.Helper()
	raw, ok := out["flags"].([]any)
	if !ok {
		if out["flags"] == nil {
			return nil
		}
		t.Fatalf("flags not a JSON array: %T (%v)", out["flags"], out["flags"])
	}
	flags := make([]string, 0, len(raw))
	for _, f := range raw {
		s, ok := f.(string)
		if !ok {
			t.Fatalf("flag element not a string: %T", f)
		}
		flags = append(flags, s)
	}
	return flags
}

func wireHasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// TestSelfReinforcementOverSocket replays a near-identical agent-authored burst and a varied-benign
// burst over the live socket, quoting the wire flags for both. The near-identical corpus is tuned
// to exceed the PRODUCTION default similarity threshold (0.85) so the default wiring itself flags,
// not a lowered test threshold.
func TestSelfReinforcementOverSocket(t *testing.T) {
	d := startSelfReinforcementDaemon(t)

	// Near-identical agent-authored writes: pairwise overlap coefficient >= 0.85 (each shares 6 of
	// its 7 tokens with the others), so the 4th trips the default max_self_writes=3 cap.
	burst := []string{
		"nightly deployment finished cleanly without errors tonight",
		"nightly deployment finished cleanly without errors again",
		"nightly deployment finished cleanly without errors overnight",
		"nightly deployment finished cleanly without errors now",
	}
	idAlpha := map[string]any{
		"spiffe_id": "spiffe://secure-agents/agent/alpha", "trust_tier": "attested", "source_class": "agent_authored",
	}

	var lastFlags []string
	firstFlaggedAt := -1
	for i, c := range burst {
		out := d.call(map[string]any{"op": "validate_write", "entry": c, "identity": idAlpha})
		flags := wireFlags(t, out)
		if out["allow"] != true {
			t.Fatalf("burst write %d: expected allow:true over the wire, got %v", i+1, out)
		}
		if wireHasFlag(flags, selfReinforcementFlag) && firstFlaggedAt < 0 {
			firstFlaggedAt = i + 1
		}
		if i == len(burst)-1 {
			lastFlags = flags
		}
		t.Logf("WIRE recall write %d flags=%v", i+1, flags)
	}
	if firstFlaggedAt != 4 {
		t.Fatalf("recall over socket: expected first self_reinforcement_suspected at write 4, got %d", firstFlaggedAt)
	}
	if !wireHasFlag(lastFlags, selfReinforcementFlag) {
		t.Fatalf("recall over socket: 4th write's wire flags must contain self_reinforcement_suspected, got %v", lastFlags)
	}

	// Varied-benign burst from a distinct agent identity: never flags over the wire (precision).
	idBeta := map[string]any{
		"spiffe_id": "spiffe://secure-agents/agent/beta", "trust_tier": "attested", "source_class": "agent_authored",
	}
	varied := []string{
		"quarterly budget review moved to Thursday",
		"new intern starts onboarding Monday",
		"database backup job failed at 2am, retried successfully",
		"office wifi password rotated",
		"lunch order deadline is noon",
	}
	for i, c := range varied {
		out := d.call(map[string]any{"op": "validate_write", "entry": c, "identity": idBeta})
		flags := wireFlags(t, out)
		if wireHasFlag(flags, selfReinforcementFlag) {
			t.Fatalf("precision over socket: varied write %d (%q) flagged, wire flags=%v", i+1, c, flags)
		}
		t.Logf("WIRE precision write %d flags=%v", i+1, flags)
	}

	// A bare benign write with no repetition behaves exactly as on main today: {allow, stored_id,
	// flags} with no self-reinforcement flag, keys unchanged.
	bare := d.call(map[string]any{"op": "validate_write", "entry": "a single unremarkable note", "identity": idBeta})
	if bare["allow"] != true {
		t.Fatalf("bare write: expected allow:true, got %v", bare)
	}
	if _, ok := bare["stored_id"].(string); !ok {
		t.Fatalf("bare write: expected string stored_id, got %v", bare["stored_id"])
	}
	if wireHasFlag(wireFlags(t, bare), selfReinforcementFlag) {
		t.Fatal("bare write must not carry self_reinforcement_suspected")
	}
	wantKeys := map[string]bool{"allow": true, "stored_id": true, "flags": true}
	got := keySet(bare)
	for k := range wantKeys {
		if !got[k] {
			t.Fatalf("bare write missing key %q; keys=%v", k, keysOf(bare))
		}
	}
	if len(got) != len(wantKeys) {
		t.Fatalf("bare write has extra keys: %v", keysOf(bare))
	}
	t.Logf("WIRE bare write flags=%v keys=%v", wireFlags(t, bare), keysOf(bare))
}
