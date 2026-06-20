# Task 001: Resolve the `Detector` backend (memory-guard tracer + ADR)

**Project:** memory-guard
**Created:** 2026-06-19
**Status:** backlog (not started)

> **The open decision the v0 deliberately deferred.** CLAUDE.md and ADR-001 §3 leave the `Detector`
> backend unresolved on purpose, behind the seam. This task is the **memory-guard tracer-bullet** that
> settles it — the same way the first tracer settled the vault↔exec-sandbox credential handoff.

## Goal

Decide the production `Detector` backend and record it as an ADR, **behind the existing `Detector`
seam** (`detector.go`) so the choice changes one implementation and **nothing else** (no guard, IPC, or
contract change). The candidates from the scoping doc + CLAUDE.md:

- **Presidio as a sidecar/subprocess** — adopt Microsoft Presidio (the production PII engine) out of
  process, called over a local socket/stdio.
- **Presidio via an in-process ONNX runtime** — the Presidio recognizer models loaded in-process via
  ONNX, no separate process.
- **A Go-native NER model** — a pure-Go recognizer, no Python/ONNX dependency.

The tracer must produce: (1) a chosen backend with rationale, (2) the **detector deployment shape**
(sidecar vs. in-process), (3) the **hot-path latency budget** on `validate_read`/`validate_write` the
choice must fit (memory-guard gates *every* memory op), and (4) a thin end-to-end slice proving the
chosen backend redacts PII + flags injection through the unchanged `Detector` interface.

## Context

- Open decision: CLAUDE.md "Open decision — the `Detector` backend";
  [ADR-001](../../architecture/decisions/001-foundational-stack.md) §3 + "Open questions".
- Seam this plugs into: the `Detector` interface (`RedactPII` / `DetectInjection`) in `detector.go`.
  The new backend is a second `Detector` implementation; `MemoryGuard`, `ipc.go`, and the contract do
  not change.
- Scoping: the project's internal design notes
  §1 (DERIVE — adopt Presidio), §6 (open questions: Presidio version, deployment), §7.
- Reference: [`docs/spec/interfaces.md`](../../spec/interfaces.md) (`Detector` extension point),
  [`docs/CONTRACT.md`](../../CONTRACT.md) (unchanged here).
- **Dependencies (ask-first):** a Presidio SDK / sidecar protocol, an ONNX runtime, or an NER model is
  the block's **first third-party dependency**. It must clear `dep-scan` (`gods`) **and** `code-scanner`
  as **blocking** gates and be version-pinned, per CLAUDE.md → Recommended tooling. Prefer the smallest
  viable surface; a Go-native NER avoids the Python/ONNX tree entirely (weigh recall vs. dependency
  cost).
- **Constraint:** the contract and the `Detector` interface are **unchanged** — the new backend is a
  drop-in `Detector`. The write-gate stays fail-closed; PII stays redacted before storage and on read.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A new `Detector` implementation (the chosen backend) satisfies the **unchanged** `Detector` interface; `MemoryGuard`/`ipc.go`/contract are untouched. | must have |
| REQ-002 | The chosen backend redacts at least the v0 PII categories (EMAIL/US_SSN/CREDIT_CARD/API_KEY) and flags the v0 injection patterns, proven by tests that also pass against `RegexDetector` (parity baseline). | must have |
| REQ-003 | The **deployment shape** (sidecar vs. in-process) and a **measured hot-path latency** for `validate_read`/`validate_write` with the new backend are recorded in the ADR. | must have |
| REQ-004 | Any new dependency clears `dep-scan` (blocking) + `code-scanner` and is version-pinned; the pinned versions are recorded in the ADR + spec. | must have |
| REQ-005 | An **ADR** records the decision (backend, shape, latency budget, deps) and supersedes ADR-001 §3's "Open questions" entry for the detector backend. | must have |
| REQ-006 | The backend is **swappable** — a test substitutes the new backend for `RegexDetector` (and back) with no guard/IPC/contract change, proving the seam. | must have |

## Readiness gate

- [x] Test spec `001-detector-backend-tracer-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Candidate backend confirmed for the first cut (operator may steer Presidio-sidecar vs. ONNX vs. Go-native NER)
- [ ] Dependency (if any) selected, pinned, and `dep-scan`/`code-scanner`-cleared (ask-first)

## Acceptance criteria

- [ ] [REQ-001] New `Detector` impl satisfies the unchanged interface; guard/IPC/contract untouched (TC-001).
- [ ] [REQ-002] PII + injection parity with `RegexDetector` on the v0 categories/patterns (TC-002).
- [ ] [REQ-003] Deployment shape + measured latency recorded in the ADR (TC-003 / L6 observation).
- [ ] [REQ-004] `dep-scan`/`code-scanner` clear any new dep; versions pinned + recorded (TC-004).
- [ ] [REQ-005] ADR written, supersedes ADR-001 §3 detector "Open questions" (TC-005, doc check).
- [ ] [REQ-006] Backend swaps in/out behind the seam with no caller change (TC-006).
- [ ] `go build ./... && go test ./...` green; v0 tests unchanged and passing.

## Verification plan

- **Highest level achievable:** **L6** — a live `go run . write`/`serve` exercises the chosen backend
  end-to-end (PII redacted, injection flagged) and the measured hot-path latency is observed; plus
  **L5** unit round-trips and **L3** dep-scan/code-scanner on any new dependency.
- **Level 2 — unit:** `go build ./... && go test ./...` → `ok`, incl. parity (TC-002) and swap (TC-006).
- **Level 3 — supply-chain gate (if a dep is added):** `gods` (dep-scan) + `code-scanner` on the new
  module tree → pass, exit 0; versions pinned.
- **Level 6 — operator observation:** `go run . write "contact alice@example.com"` (and a live `serve`)
  with the new backend → PII `<LABEL>`-redacted, injection input → write-gate rejection; latency
  observed and recorded in the ADR. This is the evidence that earns ✅.
</content>
