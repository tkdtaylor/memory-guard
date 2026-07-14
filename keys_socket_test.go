// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// keys_socket_test.go — task 021, TC-011 (L5): contract-shape parity for the key-policy branches
// over a LIVE serve socket.
//
// This mirrors contract_tracer_test.go's dial-and-decode pattern, but the guard is wired with the
// task's KeyPolicy (config:* protected, baseline:* immutable) and the reserved "memguard:" namespace
// is always active. It drives every key-policy branch — reserved-reject, reserved-immutable-reject,
// configured-flag, configured-immutable-flag — over the real Unix socket, JSON-decodes each response
// off the wire, and asserts the EXACT key set {allow, stored_id, flags} plus the flag values
// field-by-field. This is a socket-level assertion of the decoded JSON, not an in-process return
// value and not a smoke check.

// keyDaemon is a serve()-style daemon on a real Unix socket, backed by a key-policy guard.
type keyDaemon struct {
	socket string
	t      *testing.T
}

// startKeyDaemon brings up a handleConn serve loop over a real socket with a key-policy guard
// (RegexDetector, InMemoryStore, config:* protected + baseline:* immutable, no inspector so the
// key-policy flags are the only additive flags in play). It returns once the socket is listening.
func startKeyDaemon(t *testing.T) *keyDaemon {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "memguard-keys.sock")

	guard := NewMemoryGuard(NewRegexDetector(), NewInMemoryStore()).
		WithKeyPolicy(KeyPolicy{Protected: []string{"config:*"}, Immutable: []string{"baseline:*"}})

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
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	return &keyDaemon{socket: sock, t: t}
}

// call dials the live socket, writes one newline-delimited request, and decodes the single JSON
// response off the wire — the REAL IPC consumer path.
func (d *keyDaemon) call(req map[string]any) map[string]any {
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

// TestKeysTC011_SocketShapeParity drives every key-policy branch over the live socket and asserts
// the decoded response carries EXACTLY {allow, stored_id, flags} with the correct flag values.
func TestKeysTC011_SocketShapeParity(t *testing.T) {
	d := startKeyDaemon(t)
	attested := attestedIdentity("spiffe://secure-agents/agent/ops")

	writeKeys := []string{"allow", "stored_id", "flags"}

	// Branch 1 — reserved key, no identity: rejected, protected_key_violation, stored_id null.
	r1 := d.call(map[string]any{"op": "validate_write", "entry": contentA, "key": "memguard:policy"})
	mustKeys(t, "validate_write(reserved-reject)", r1, writeKeys)
	if r1["allow"] != false {
		t.Fatalf("branch 1: reserved no-identity must be rejected, got %v", r1)
	}
	if r1["stored_id"] != nil {
		t.Fatalf("branch 1: rejected write must have null stored_id, got %#v", r1["stored_id"])
	}
	if !flagsContain(r1["flags"], protectedKeyViolationFlag) {
		t.Fatalf("branch 1: expected protected_key_violation, got %v", r1["flags"])
	}

	// Branch 2 — reserved key, attested: allowed, establishes the baseline, no flag.
	r2 := d.call(map[string]any{"op": "validate_write", "entry": contentA, "key": "memguard:policy", "identity": attested})
	mustKeys(t, "validate_write(reserved-allow)", r2, writeKeys)
	if r2["allow"] != true {
		t.Fatalf("branch 2: reserved attested must be allowed, got %v", r2)
	}
	if sid, ok := r2["stored_id"].(string); !ok || sid == "" {
		t.Fatalf("branch 2: expected non-empty stored_id, got %#v", r2["stored_id"])
	}
	if arr, ok := r2["flags"].([]any); !ok || len(arr) != 0 {
		t.Fatalf("branch 2: expected empty flags array, got %#v", r2["flags"])
	}

	// Branch 3 — reserved key, attested, DIFFERENT content: rejected, immutable_mismatch, null id.
	r3 := d.call(map[string]any{"op": "validate_write", "entry": contentB, "key": "memguard:policy", "identity": attested})
	mustKeys(t, "validate_write(reserved-immutable-reject)", r3, writeKeys)
	if r3["allow"] != false || r3["stored_id"] != nil {
		t.Fatalf("branch 3: reserved drift must be rejected with null stored_id, got %v", r3)
	}
	if !flagsContain(r3["flags"], immutableMismatchFlag) {
		t.Fatalf("branch 3: expected immutable_mismatch, got %v", r3["flags"])
	}

	// Branch 4 — configured protected key, no identity: allowed + flagged (flag-only).
	r4 := d.call(map[string]any{"op": "validate_write", "entry": contentA, "key": "config:threshold"})
	mustKeys(t, "validate_write(configured-flag)", r4, writeKeys)
	if r4["allow"] != true {
		t.Fatalf("branch 4: configured protected no-identity must be allowed, got %v", r4)
	}
	if sid, ok := r4["stored_id"].(string); !ok || sid == "" {
		t.Fatalf("branch 4: expected non-empty stored_id, got %#v", r4["stored_id"])
	}
	if !flagsContain(r4["flags"], protectedKeyViolationFlag) {
		t.Fatalf("branch 4: expected protected_key_violation, got %v", r4["flags"])
	}

	// Branch 5 — configured immutable key twice, different content, attested: both allowed, second
	// flags immutable_mismatch, two distinct stored_ids.
	c1 := d.call(map[string]any{"op": "validate_write", "entry": contentA, "key": "baseline:limit", "identity": attested})
	mustKeys(t, "validate_write(configured-immutable-first)", c1, writeKeys)
	c2 := d.call(map[string]any{"op": "validate_write", "entry": contentB, "key": "baseline:limit", "identity": attested})
	mustKeys(t, "validate_write(configured-immutable-flag)", c2, writeKeys)
	if c1["allow"] != true || c2["allow"] != true {
		t.Fatalf("branch 5: both configured-immutable writes must be allowed, got %v / %v", c1, c2)
	}
	sid1, _ := c1["stored_id"].(string)
	sid2, _ := c2["stored_id"].(string)
	if sid1 == "" || sid2 == "" || sid1 == sid2 {
		t.Fatalf("branch 5: expected two distinct non-empty stored_ids, got %q / %q", sid1, sid2)
	}
	if flagsContain(c1["flags"], immutableMismatchFlag) {
		t.Fatalf("branch 5: first configured-immutable write must not flag, got %v", c1["flags"])
	}
	if !flagsContain(c2["flags"], immutableMismatchFlag) {
		t.Fatalf("branch 5: second configured-immutable write must flag immutable_mismatch, got %v", c2["flags"])
	}

	t.Log("TC-011 PASS: all key-policy branches decode to exactly {allow, stored_id, flags} with correct flag values over the live socket")
}
