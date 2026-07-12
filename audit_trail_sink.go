// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// audit_trail_sink.go is the REAL audit transport (task 017 / ADR-014): an AuditSink
// (audit.go) that speaks the sibling audit-trail block's confirmed wire contract over a
// Unix socket. It is the piece ADR-007 deferred ("emission stays disabled until the
// audit-trail emit endpoint is confirmed live"); that endpoint now exists and its contract
// is the PLAIN hash-chained event {ts, actor, action, target, decision?, refs[], context?},
// NOT OCSF. The internal OCSFEvent builders (audit.go) are kept unchanged and translated to
// the plain event HERE, at the transport boundary, so guard.go / ipc.go / the event builders
// / the memory-guard contract are untouched (exactly the swap ADR-007 §1 anticipated).
//
// ALL transport specifics (dialing, deadlines, socket paths, the wire mapping) live in this
// file. guard.go and ipc.go never dial; main.go names only the flag/env strings and
// buildAuditConfig. emitSafe (audit.go) stays the only guard-side emission call site, so a
// down/slow/absent/erroring audit-trail NEVER blocks the hot path or changes a verdict.

// auditActor is the honest actor value: OCSFEvent does not carry the calling principal today,
// so the emitting block is the actor. Threading the task-009/016 caller SPIFFE ID in is a
// noted follow-on (ADR-014), not scope here.
const auditActor = "memory-guard"

// defaultAuditTimeout bounds every dial/read/write so a hanging audit-trail cannot leak a
// goroutine per event forever (the drain goroutine eventually errors out).
const defaultAuditTimeout = 2 * time.Second

// mapToAuditTrailEvent translates an internal OCSFEvent into audit-trail's plain event
// (ADR-014 field table). It is a PURE function (unit-testable without a socket). Every
// value is a string or an int64/int — audit-trail rejects float-bearing events
// (validateEmitEventNoFloats in its chain.go). No raw content or PII ever enters the event:
// only flag LABELS, ids, the deletion hash, and envelope fields cross the wire.
func mapToAuditTrailEvent(e OCSFEvent) map[string]any {
	f := e.Finding

	target := f.StoredID
	if target == "" {
		target = "memory-store"
	}

	refs := []map[string]any{}
	if f.DeletionHash != "" {
		refs = append(refs, map[string]any{"type": "deletion_hash", "id": f.DeletionHash})
	}

	ctx := map[string]any{
		"finding_type":   f.Type,
		"flags":          strings.Join(f.Flags, ","),
		"flag_count":     f.FlagCount,
		"severity_id":    e.SeverityID,
		"ocsf_class_uid": e.ClassUID,
	}

	ev := map[string]any{
		"ts":      e.Time,
		"actor":   auditActor,
		"action":  f.Operation,
		"target":  target,
		"refs":    refs,
		"context": ctx,
	}

	// decision is a GATE verdict — set only for write-gate outcomes, omitted for deletions
	// (a deletion outcome is not an allow/deny; the signal rides in context/refs).
	switch f.Type {
	case "injection_rejected":
		ev["decision"] = "deny"
	case "pii_redaction":
		ev["decision"] = "allow"
	}

	// residue_detected (0|1) rides in context on verify_delete events.
	if f.Operation == "verify_delete" {
		rd := 0
		if f.ResidueDetected != nil && *f.ResidueDetected {
			rd = 1
		}
		ctx["residue_detected"] = rd
	}

	return ev
}

// AuditTrailSink implements AuditSink over the audit-trail Unix-socket emit contract:
// per event, dial → write one newline-terminated {"op":"emit","event":…} → read one
// response line → close. Any dial/write/read/decode failure or {error:…} response returns a
// non-nil error, which emitSafe / AsyncSink swallow upstream (fail-open, ADR-007 §3).
type AuditTrailSink struct {
	socketPath string
	timeout    time.Duration
}

// NewAuditTrailSink builds a sink dialing socketPath with an I/O deadline. A non-positive
// timeout falls back to defaultAuditTimeout.
func NewAuditTrailSink(socketPath string, timeout time.Duration) *AuditTrailSink {
	if timeout <= 0 {
		timeout = defaultAuditTimeout
	}
	return &AuditTrailSink{socketPath: socketPath, timeout: timeout}
}

// Emit sends one event over the socket and validates the response. It NEVER blocks
// unbounded: dial and the read/write both carry the deadline.
func (s *AuditTrailSink) Emit(event OCSFEvent) error {
	conn, err := net.DialTimeout("unix", s.socketPath, s.timeout)
	if err != nil {
		return fmt.Errorf("audit-trail dial %s: %w", s.socketPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return fmt.Errorf("audit-trail set deadline: %w", err)
	}

	req := map[string]any{"op": "emit", "event": mapToAuditTrailEvent(event)}
	line, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("audit-trail marshal: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit-trail write: %w", err)
	}

	respLine, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(respLine) == 0 {
		return fmt.Errorf("audit-trail read: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return fmt.Errorf("audit-trail decode %q: %w", respLine, err)
	}
	if e, isErr := resp["error"]; isErr {
		return fmt.Errorf("audit-trail emit rejected: %v", e)
	}
	if _, ok := resp["hash"]; !ok {
		return fmt.Errorf("audit-trail response missing hash: %v", resp)
	}
	return nil
}

// resolveAuditSocket applies the documented precedence for the audit-trail socket path:
// the --audit-socket FLAG wins over the MEMGUARD_AUDIT_SOCKET env fallback; empty means
// disabled. Kept here (not inlined in main.go) so the precedence is unit-testable.
func resolveAuditSocket(flagVal, envVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return envVal
}

// buildAuditConfig returns the AuditConfig for a serve invocation. An empty path yields a
// DISABLED config (zero connections attempted — the default). A non-empty path yields an
// enabled config whose sink is the AuditTrailSink wrapped in AsyncSink (ADR-007 §6 mandates
// non-blocking dispatch for a real transport, so a stalled endpoint degrades to dropped
// events, not a stalled guard). Reachability is NOT checked here: emission is a soft
// dependency (fail-open at runtime), unlike the store/detector factories which fail closed.
func buildAuditConfig(socketPath string) AuditConfig {
	if socketPath == "" {
		return AuditConfig{} // disabled (zero value)
	}
	return AuditConfig{
		Enabled: true,
		Sink:    NewAsyncSink(NewAuditTrailSink(socketPath, defaultAuditTimeout), 256),
	}
}
