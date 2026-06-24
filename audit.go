// SPDX-License-Identifier: Apache-2.0
package main

// audit.go — the AuditSink seam (task 010 / ADR-007).
//
// Emission contract:
//   - Every detection memory-guard already computes (PII redaction, injection rejection,
//     residue found, deletion) is ALSO emitted as an OCSF-shaped event through this seam.
//   - Emission is BEST-EFFORT and FAIL-OPEN: a slow, failing, or absent sink NEVER blocks
//     the hot path, NEVER surfaces an error to the caller, and NEVER changes a validate_* /
//     verify_delete verdict. A panicking sink is recovered.
//   - Emission is CONFIG-GATED, defaulting to DISABLED until the audit-trail emit endpoint
//     is confirmed live (ADR-007). An invalid or missing config fails to DISABLED (no emission).
//   - NO raw PII or raw deleted content ever appears in an emitted event. The event carries
//     the redacted/flagged metadata (flag categories, counts, deletion_hash) only.
//
// The AuditSink interface is the ONLY coupling point — guard.go and ipc.go know nothing
// about transports (socket/HTTP/file). Swapping the transport means swapping the AuditSink
// implementation, with zero guard/IPC/contract impact.
//
// OCSF event shape (ADR-007): modelled on the PUBLIC OCSF standard (Security Finding /
// Detection Finding class). Required envelope fields:
//   class_uid, category_uid, activity_id, severity_id, time,
//   metadata.product, finding.{type, related_events}
// Detection detail is in STRUCTURED fields (operation, flags, flag_count, stored_id,
// deletion_hash) — NOT a free-text blob (REQ-002). The exact audit-trail wire contract
// is deferred pending live endpoint confirmation; the shape is intentionally close to
// OCSF so it arrives already aligned when that confirmation comes.

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ─── OCSF event shape ────────────────────────────────────────────────────────

// OCSFProduct identifies the originating component in the event envelope.
type OCSFProduct struct {
	Name    string `json:"name"`              // "memory-guard"
	Version string `json:"version,omitempty"` // semver or commit ref
}

// OCSFMetadata is the OCSF metadata block.
type OCSFMetadata struct {
	Product   OCSFProduct `json:"product"`
	Version   string      `json:"version"` // OCSF schema version, e.g. "1.1.0"
	EventCode string      `json:"event_code,omitempty"`
}

// OCSFFinding carries detection-specific structured data. Raw PII is NEVER placed here —
// only redacted/flagged metadata (categories, counts, the deletion_hash audit link).
type OCSFFinding struct {
	// Type names the detection class: "pii_redaction", "injection_rejected",
	// "residue_found", "deletion_verified". Required.
	Type string `json:"type"`

	// Operation is the guard verb that triggered the detection: "validate_write",
	// "validate_read", or "verify_delete".
	Operation string `json:"operation"`

	// Flags is the set of guard-computed flag strings (e.g. "pii:EMAIL", "injection_suspected",
	// "residue_detected"). These are METADATA flags — no raw value.
	Flags []string `json:"flags"`

	// FlagCount is len(Flags) — for quick counting without deserializing the full slice.
	FlagCount int `json:"flag_count"`

	// StoredID is the opaque mem-<hex> id returned by a successful validate_write, or ""
	// for rejected writes and verify_delete operations. Never carries the stored value.
	StoredID string `json:"stored_id,omitempty"`

	// DeletionHash is the deterministic SHA-256 audit-linkage value from verify_delete
	// (defined in residue.go). Present on deletion and residue events; "" otherwise.
	DeletionHash string `json:"deletion_hash,omitempty"`

	// ResidueDetected is true when a residue scan found surviving content.
	// Only set on verify_delete events.
	ResidueDetected *bool `json:"residue_detected,omitempty"`

	// RelatedEvents is the OCSF "related events" placeholder for future chaining; empty in v0.
	RelatedEvents []string `json:"related_events"`
}

// OCSFEvent is the full audit event emitted for each detection (ADR-007 / OCSF public spec).
// Required envelope fields (OCSF Security Finding class):
//
//	class_uid    — OCSF class identifier (2001 = Security Finding)
//	category_uid — OCSF category (2 = Findings)
//	activity_id  — activity within the class (1 = Create/Find)
//	severity_id  — severity level (2 = Low, 4 = High for injection; see below)
//	time         — UTC Unix-timestamp (int64) of the detection instant
//	metadata     — product/schema block
//	finding      — structured detection detail (NEVER raw PII)
//
// All fields use the OCSF wire names (snake_case) via json tags.
type OCSFEvent struct {
	ClassUID    int          `json:"class_uid"`    // 2001 = Security Finding
	CategoryUID int          `json:"category_uid"` // 2 = Findings
	ActivityID  int          `json:"activity_id"`  // 1 = Create
	SeverityID  int          `json:"severity_id"`  // 1=Info 2=Low 3=Medium 4=High 5=Critical
	Time        int64        `json:"time"`         // UTC Unix timestamp (seconds)
	Metadata    OCSFMetadata `json:"metadata"`
	Finding     OCSFFinding  `json:"finding"`
}

// OCSF class / category / activity constants (public OCSF 1.1 schema).
const (
	ocsfClassSecurityFinding = 2001
	ocsfCategoryFindings     = 2
	ocsfActivityCreate       = 1

	// Severity IDs (OCSF 1.1).
	ocsfSeverityInformational = 1
	ocsfSeverityLow           = 2
	ocsfSeverityMedium        = 3
	ocsfSeverityHigh          = 4
)

// OCSF schema version we model against.
const ocsfSchemaVersion = "1.1.0"

// ─── AuditSink seam ──────────────────────────────────────────────────────────

// AuditSink is the transport-agnostic emission seam. Implementors receive fully-formed
// OCSFEvent values; the underlying transport (Unix socket / HTTP / file) is an internal
// detail of the implementor, invisible to the guard. Emit MUST be safe for concurrent
// calls — the guard may call it from goroutines without holding its mutex.
//
// A nil AuditSink is treated as "emission disabled" — the guard never calls Emit on nil.
type AuditSink interface {
	// Emit sends the event to the sink. It MUST return quickly (or asynchronously)
	// so a slow/blocking sink does not stall the hot path. If Emit returns a non-nil
	// error, the guard SWALLOWS it (fail-open). A panicking Emit is recovered.
	Emit(event OCSFEvent) error
}

// ─── AuditConfig ─────────────────────────────────────────────────────────────

// AuditConfig controls whether and where events are emitted. The zero value is
// DISABLED — safe to embed in NewMemoryGuard call sites that do not need emission.
type AuditConfig struct {
	// Enabled must be true for any emission to occur. Default: false (disabled until
	// the audit-trail emit endpoint is confirmed live — ADR-007).
	Enabled bool

	// Sink is the AuditSink implementation to use. A nil sink with Enabled==true is
	// treated as disabled (invalid config fails closed to disabled — REQ-006).
	Sink AuditSink
}

// isActive returns true iff emission should occur (enabled AND a non-nil sink).
// An invalid config (Enabled without a Sink) fails closed to disabled (REQ-006).
func (c AuditConfig) isActive() bool {
	return c.Enabled && c.Sink != nil
}

// ─── NoOpSink (disabled transport) ───────────────────────────────────────────

// NoOpSink is the disabled-emission sentinel. It is the default when no sink is configured.
// It implements AuditSink so it can be wired anywhere a sink is required, but Emit is
// a zero-cost no-op that never allocates.
type NoOpSink struct{}

// Emit does nothing and returns nil. Used when emission is disabled (default).
func (NoOpSink) Emit(_ OCSFEvent) error { return nil }

// ─── AsyncSink (non-blocking dispatch wrapper) ───────────────────────────────

// AsyncSink wraps any (possibly SLOW or blocking) AuditSink in a non-blocking,
// fire-and-forget dispatch so a slow real transport can NEVER stall the hot path
// (REQ-005 / TC-006-d). The hot-path Emit only enqueues onto a bounded buffered
// channel and returns immediately; a single background goroutine drains the channel
// and forwards each event to the wrapped sink. When the buffer is full, the event is
// DROPPED (fail-open — availability over completeness), never blocking the caller.
//
// This is the dispatch real transports (Unix socket / HTTP / file) should use:
// wrap the blocking transport sink in NewAsyncSink so a stalled audit-trail endpoint
// degrades to dropped events, not a stalled memory hot path. The synchronous in-process
// sinks (CollectingSink, NoOpSink) stay synchronous so the existing deterministic tests
// observe every event without a drain race; AsyncSink is opt-in via the constructor.
//
// Lifecycle: NewAsyncSink starts the drain goroutine. Close stops it (idempotent).
// A panicking wrapped sink is RECOVERED inside the drain goroutine, so a misbehaving
// transport never crashes the process.
type AsyncSink struct {
	ch     chan OCSFEvent
	inner  AuditSink
	closed chan struct{}
	once   sync.Once
}

// NewAsyncSink wraps inner in a non-blocking dispatch with a buffer of n events and
// starts the background drain goroutine. A buffer of 0 is treated as 1 (a channel must
// have capacity to be non-blocking for at least one in-flight event). The wrapped sink
// is forwarded each event from the drain goroutine; the caller's Emit never blocks on it.
func NewAsyncSink(inner AuditSink, n int) *AsyncSink {
	if n < 1 {
		n = 1
	}
	s := &AsyncSink{
		ch:     make(chan OCSFEvent, n),
		inner:  inner,
		closed: make(chan struct{}),
	}
	go s.drain()
	return s
}

// Emit enqueues the event non-blocking and returns immediately. If the buffer is full,
// the event is dropped (returns an error the guard swallows). This is the call the guard's
// emitSafe invokes on the hot path — it MUST NOT block on the wrapped (possibly slow) sink.
func (s *AsyncSink) Emit(event OCSFEvent) error {
	select {
	case s.ch <- event:
		return nil
	case <-s.closed:
		return fmt.Errorf("AsyncSink: closed, event dropped")
	default:
		return fmt.Errorf("AsyncSink: buffer full, event dropped")
	}
}

// drain forwards buffered events to the wrapped sink one at a time, off the hot path.
// A panic in the wrapped sink is recovered per-event so one bad event cannot kill the
// drain goroutine or the process.
func (s *AsyncSink) drain() {
	for {
		select {
		case event := <-s.ch:
			s.forward(event)
		case <-s.closed:
			// Drain any remaining buffered events best-effort, then exit.
			for {
				select {
				case event := <-s.ch:
					s.forward(event)
				default:
					return
				}
			}
		}
	}
}

// forward calls the wrapped sink with panic recovery (fail-open inside the drain).
func (s *AsyncSink) forward(event OCSFEvent) {
	defer func() { _ = recover() }()
	if s.inner != nil {
		_ = s.inner.Emit(event)
	}
}

// Close stops the drain goroutine (idempotent). Safe to call multiple times.
func (s *AsyncSink) Close() {
	s.once.Do(func() { close(s.closed) })
}

// ─── ChannelSink (in-process test transport) ─────────────────────────────────

// ChannelSink is a non-blocking in-process sink suitable for tests and for future
// async background-flush designs. It drops events when the channel is full rather than
// blocking the caller (fail-open). Buffer the channel generously for test workloads.
type ChannelSink struct {
	ch chan OCSFEvent
}

// NewChannelSink creates a ChannelSink with a buffer of n events.
func NewChannelSink(n int) *ChannelSink { return &ChannelSink{ch: make(chan OCSFEvent, n)} }

// Emit sends the event to the channel non-blocking. Drops (and returns an error) if full.
func (s *ChannelSink) Emit(event OCSFEvent) error {
	select {
	case s.ch <- event:
		return nil
	default:
		return fmt.Errorf("ChannelSink: buffer full, event dropped")
	}
}

// Drain returns all events currently buffered in the channel (non-blocking).
func (s *ChannelSink) Drain() []OCSFEvent {
	var out []OCSFEvent
	for {
		select {
		case e := <-s.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// ─── CollectingSink (fake sink for tests) ────────────────────────────────────

// CollectingSink is the fake AuditSink used in test suites. It captures every emitted
// event into an append-only slice, recording both the event and the call count.
// Thread-safe (the guard may emit from concurrent goroutines in tests).
type CollectingSink struct {
	mu     sync.Mutex
	events []OCSFEvent
}

// Emit appends the event to the collection.
func (s *CollectingSink) Emit(event OCSFEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

// Events returns a snapshot of all captured events (safe for concurrent access).
func (s *CollectingSink) Events() []OCSFEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OCSFEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Count returns the number of events captured so far.
func (s *CollectingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// SerializedEvents returns every captured event serialized to its JSON wire form.
// Used by TC-005 to scan for raw PII leakage across the full serialized payload.
func (s *CollectingSink) SerializedEvents() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.events))
	for _, e := range s.events {
		b, _ := json.Marshal(e)
		out = append(out, b)
	}
	return out
}

// ─── FailingSink (error-returning fake for TC-006) ───────────────────────────

// FailingSink always returns an error from Emit, standing in for an audit-trail that
// is down or unreachable. Used by TC-006 to prove fail-open: the guard must continue
// normally even when every emission fails.
type FailingSink struct{}

// Emit always returns an error (simulates a down/unreachable audit-trail).
func (FailingSink) Emit(_ OCSFEvent) error {
	return fmt.Errorf("FailingSink: simulated emission failure")
}

// ─── PanicSink (panic-recovery fake for TC-006 edge case) ────────────────────

// PanicSink panics on every Emit call, used to verify the guard's recover() wrapper
// prevents a panicking sink from crashing the hot path (TC-006 edge case).
type PanicSink struct{}

// Emit always panics with a descriptive message.
func (PanicSink) Emit(_ OCSFEvent) error {
	panic("PanicSink: intentional panic to test recovery")
}

// ─── SlowSink (blocking fake for TC-006-d async dispatch test) ───────────────

// SlowSink blocks in Emit for a fixed delay, standing in for a slow/unresponsive
// audit-trail transport. Wrapped in an AsyncSink, it proves the hot path does NOT
// stall waiting for a slow sink (TC-006-d / REQ-005). The done channel records when
// the (delayed) Emit finally completes, so a test can confirm the slow work happened
// off the hot path rather than on it.
type SlowSink struct {
	delay time.Duration
	done  chan struct{}
}

// NewSlowSink builds a SlowSink that sleeps delay per Emit and signals done on the
// channel after the (first) sleep completes.
func NewSlowSink(delay time.Duration) *SlowSink {
	return &SlowSink{delay: delay, done: make(chan struct{}, 1)}
}

// Emit sleeps for the configured delay (simulating a slow transport) then signals done.
func (s *SlowSink) Emit(_ OCSFEvent) error {
	time.Sleep(s.delay)
	select {
	case s.done <- struct{}{}:
	default:
	}
	return nil
}

// Done returns the channel signalled after a (delayed) Emit completes.
func (s *SlowSink) Done() <-chan struct{} { return s.done }

// ─── Emission helpers ─────────────────────────────────────────────────────────

// emitSafe calls sink.Emit(event) in a way that is ALWAYS fail-open:
//   - If sink is nil, returns immediately (no emission).
//   - If Emit returns a non-nil error, the error is SWALLOWED (not propagated).
//   - If Emit panics, the panic is RECOVERED (the guard continues normally).
//
// This is the ONLY function that calls Emit from the guard — callers in guard.go use
// emitSafe and are therefore insulated from any sink failure mode.
func emitSafe(sink AuditSink, event OCSFEvent) {
	if sink == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// Panic recovered — swallow; the guard continues.
			_ = r
		}
	}()
	_ = sink.Emit(event) // error swallowed — fail-open
}

// ─── Event constructors ───────────────────────────────────────────────────────

// newEventEnvelope builds the common OCSF envelope fields that every event shares.
// The caller fills in the finding block and severity.
func newEventEnvelope(severityID int, finding OCSFFinding) OCSFEvent {
	return OCSFEvent{
		ClassUID:    ocsfClassSecurityFinding,
		CategoryUID: ocsfCategoryFindings,
		ActivityID:  ocsfActivityCreate,
		SeverityID:  severityID,
		Time:        time.Now().UTC().Unix(),
		Metadata: OCSFMetadata{
			Product: OCSFProduct{Name: "memory-guard"},
			Version: ocsfSchemaVersion,
		},
		Finding: finding,
	}
}

// boolPtr returns a pointer to a bool value (for nullable struct fields).
func boolPtr(b bool) *bool { return &b }

// BuildPIIRedactionEvent constructs the OCSF event for a PII-redaction detection on
// validate_write. flags is the full flag slice the guard already computed (pii:LABEL, …).
// storedID is the opaque mem-<hex> id (empty for a rejected write).
//
// REQ-004: the raw text is NEVER passed to this function — guard.go passes only flags
// and the already-assigned storedID.
func BuildPIIRedactionEvent(flags []string, storedID string) OCSFEvent {
	finding := OCSFFinding{
		Type:          "pii_redaction",
		Operation:     "validate_write",
		Flags:         flagsOrEmptySlice(flags),
		FlagCount:     len(flags),
		StoredID:      storedID,
		RelatedEvents: []string{},
	}
	return newEventEnvelope(ocsfSeverityLow, finding)
}

// BuildInjectionRejectedEvent constructs the OCSF event for an injection-rejected write.
// flags must contain "injection_suspected". storedID is always "" (fail-closed: no store).
//
// REQ-004: the raw text is NEVER passed to this function.
func BuildInjectionRejectedEvent(flags []string) OCSFEvent {
	finding := OCSFFinding{
		Type:          "injection_rejected",
		Operation:     "validate_write",
		Flags:         flagsOrEmptySlice(flags),
		FlagCount:     len(flags),
		StoredID:      "", // fail-closed: poisoned writes are never stored
		RelatedEvents: []string{},
	}
	return newEventEnvelope(ocsfSeverityHigh, finding)
}

// BuildDeletionEvent constructs the OCSF event for a verify_delete operation.
// deletionHash is the audit-linkage value from residue.go::deletionHash.
// residueDetected indicates whether the residue scan found surviving content.
//
// REQ-004: the raw deleted content is NEVER passed to this function — only the hash.
func BuildDeletionEvent(deletionHash string, residueDetected bool, residueFlags []string) OCSFEvent {
	detType := "deletion_verified"
	severity := ocsfSeverityInformational
	if residueDetected {
		detType = "residue_found"
		severity = ocsfSeverityMedium
	}
	finding := OCSFFinding{
		Type:            detType,
		Operation:       "verify_delete",
		Flags:           flagsOrEmptySlice(residueFlags),
		FlagCount:       len(residueFlags),
		DeletionHash:    deletionHash,
		ResidueDetected: boolPtr(residueDetected),
		RelatedEvents:   []string{},
	}
	return newEventEnvelope(severity, finding)
}

// flagsOrEmptySlice returns a non-nil slice so the JSON wire form is [] not null.
func flagsOrEmptySlice(flags []string) []string {
	if flags == nil {
		return []string{}
	}
	return flags
}
