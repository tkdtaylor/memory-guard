// SPDX-License-Identifier: Apache-2.0
package main

// write_inspector.go: the WriteInspector seam (task 018 / ADR-016).
//
// This is the block's SECOND detection seam, distinct from the stateless Detector
// (detector.go). Detector is a pure function of a single text (RedactPII / DetectInjection):
// it cannot see prior writes, so it structurally cannot detect an agent poisoning itself
// through repetitive self-authored writes (an ASI06-adjacent behavioral failure mode). That
// signal is cross-write, not lexical, so it needs its own seam that is allowed to hold state.
//
// Like Detector, MemoryStore (ADR-005), and AuditSink (ADR-007), the concrete implementation
// lives BEHIND this interface: guard.go holds only the WriteInspector interface and constructs
// a WriteContext at a single call site in ValidateWrite. No implementation-specific detail
// (SelfReinforcementDetector, its similarity helper, its history struct) leaks into guard.go,
// ipc.go, or the contract.

// WriteContext carries the minimal, backend-agnostic write metadata a WriteInspector needs.
// It deliberately exposes only what a behavioral inspector requires and nothing about how the
// identity was verified or how the content was produced:
//
//   - Key is the writer's normalized identity key (boundKeyFor: the attested Subject(), or the
//     unbound marker for an unattested/absent writer). It is the SAME key the store isolation
//     matches on, so a WriteInspector's per-subject history is scoped exactly as isolation is.
//   - SourceClass is the write's raw source-class provenance hint (the trimmed source_class
//     wire value, or "" when absent). It lets a behavioral inspector route on provenance (e.g.
//     scrutinize agent-authored writes, ignore human-authored ones) without the guard baking
//     any provenance policy into itself.
type WriteContext struct {
	Key         string
	SourceClass string
}

// WriteInspector is the stateful behavioral-detection seam. Inspect sees a write's content and
// its WriteContext and returns zero or more additive flag strings (mirroring the shape of
// Detector.DetectInjection). Unlike Detector, an implementation is explicitly permitted to hold
// state (e.g. a bounded per-identity write history) because cross-write detection is impossible
// without it; that state lives inside the implementation, never in the guard or the store.
//
// Contract:
//   - The returned flags are ADDITIVE on the existing validate_write flags array and
//     NON-BLOCKING: the guard appends them but they never change allow / stored_id. Blocking
//     policy for behavioral flags is a separate policy-engine concern (ADR-016 §3).
//   - Inspect MUST be safe for concurrent calls: the guard may call it without holding its own
//     mutex, so the implementation owns its synchronization.
//   - A nil WriteInspector means the seam is disabled; the guard never calls Inspect on nil, and
//     a guard built without WithWriteInspector is behaviorally identical to pre-task.
type WriteInspector interface {
	Inspect(content string, ctx WriteContext) []string
}
