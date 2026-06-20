# ADR-002 — `Detector` backend: Go-native, in-process

**Status:** Accepted
**Date:** 2026-06-19
**Supersedes:** ADR-001 "Open questions" → the `Detector` backend entry (the deferred decision).
**Task:** [001 — Resolve the `Detector` backend (memory-guard tracer)](../../tasks/backlog/001-detector-backend-tracer.md)

## Context

ADR-001 §3 deliberately left the production `Detector` backend unresolved behind the seam, with three
candidates from the scoping doc:

1. **Presidio as a sidecar/subprocess** — Microsoft Presidio (the production PII engine) out of
   process, called over a local socket/stdio.
2. **Presidio via an in-process ONNX runtime** — Presidio recognizer models loaded in-process via
   ONNX, no separate process.
3. **A Go-native recognizer engine** — pure-Go detection, no Python/ONNX dependency.

This is the **memory-guard tracer** decision: settle the backend, the deployment shape, and the
hot-path latency budget, behind the **unchanged** `Detector` interface (`RedactPII` /
`DetectInjection`).

The decision is weighed against memory-guard's **load-bearing invariants** (CLAUDE.md / ADR-001):
single static binary, **low per-call latency on the memory hot path** (the gate runs on *every* read
and write), the **smallest possible auditable dependency surface** for a block that sees PII and tool
output, and the `Detector` seam staying the one swap point.

## Decision

**Adopt a Go-native, in-process `Detector` backend for v1.** Defer (do not foreclose)
Presidio-as-sidecar and Presidio-via-ONNX.

- **Deployment shape:** **in-process.** No sidecar, no subprocess, no IPC round-trip on the hot path.
- **Dependencies:** **none.** The backend stays within the Go standard library (`regexp`, etc.),
  preserving ADR-001 §2's stdlib-only property. `dep-scan` / `code-scanner` therefore clear trivially
  (no new module tree to scan) — recorded as such per TC-004.
- **Realization:** a second `Detector` implementation alongside `RegexDetector`, satisfying the
  **unchanged** interface, reaching **parity** with `RegexDetector` on the v0 categories
  (EMAIL / US_SSN / CREDIT_CARD / API_KEY + the v0 injection patterns), and **swappable** in/out
  behind the seam with no `guard.go` / `ipc.go` / contract change. This is the thin end-to-end slice
  that proves the seam carries a real alternate backend.
- **Hot-path latency budget:** in-process detection must stay **well under 1 ms** per
  `validate_read` / `validate_write` on representative inputs (regex/heuristic matching is
  microsecond-scale). The measured figure is recorded by the task 001 implementation in the
  "Measured" section below.

## Rationale

| Criterion (invariant) | Presidio sidecar | Presidio / ONNX in-process | **Go-native in-process (chosen)** |
|---|---|---|---|
| Single static binary | ✗ extra process to deploy | ~ large native runtime + model blob | ✓ one binary |
| Hot-path latency (every memory op) | ✗ IPC round-trip per call | ~ model inference per call | ✓ microsecond regex/heuristic |
| Minimal auditable dep surface | ✗ Python tree | ✗ ONNX runtime + model | ✓ zero new deps |
| `dep-scan` / `code-scanner` gate | must clear a Python tree (offline-infeasible here) | must clear a native runtime | ✓ trivially clears (nothing added) |
| `Detector` seam preserved | ✓ | ✓ | ✓ |

Presidio's strength is **recall breadth** (a large recognizer set). That gap is closed *inside the Go
substrate* by **task 004** (PII recognizer coverage hardening), measured against a labelled PII
corpus — without importing the Python/ONNX dependency tree onto the memory hot path. The seam is
unchanged, so if a future requirement demands Presidio-grade NER recall that Go-native cannot reach,
a Presidio-backed `Detector` still slots in additively (this ADR defers that choice; it does not
foreclose it).

## Consequences

- The stdlib-only property (ADR-001 §2) **holds** through v1 — the "first external dependency"
  milestone is pushed out, not triggered.
- Broadening detection recall is now a **detector-internal** task (004), behind `RedactPII` — no
  guard/IPC/contract impact.
- A Presidio-backed `Detector` remains a clean future addition behind the seam; ADR-001 §3's seam
  guarantee is unchanged. The "Open questions → `Detector` backend" entry in ADR-001 is **resolved by
  this ADR**.
- CLAUDE.md's "Open decision — the `Detector` backend" section is updated to point here (done in
  task 001's commit).

## Measured

> Filled in by the task 001 implementation (REQ-003 / TC-003 — L6 observation).

- **Deployment shape (as built):** in-process, no subprocess.
- **Measured hot-path latency (`validate_write` / `validate_read`):** _to be recorded from
  `go run . write` / a live `serve` with the Go-native backend._
- **`dep-scan` / `code-scanner`:** no new dependency added → trivially clear (note in the task report).
